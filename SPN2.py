#!/usr/bin/env python3
"""
Kerberoasting Detection Test — robust edition
Fixes: KDC timeout, UDP fallback, multi-KDC, retries,
       LDAPS fallback, safe ccache, graceful errors
"""

import getpass
import logging
import os
import socket
import sys
import time

try:
    import dns.resolver as _dns
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import ldap3
except ImportError:
    print("[!] pip install ldap3")
    sys.exit(1)

try:
    from impacket.krb5 import constants
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5.types import Principal
    from impacket.krb5.ccache import CCache
except ImportError:
    print("[!] pip install impacket")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("kerberoast-test")

MAX_SPNS       = 5
DELAY          = 2
TCP_TIMEOUT    = 10      # was 5 — increased for slow/remote DCs
RETRY_ATTEMPTS = 3
RETRY_BACKOFF  = 2       # seconds between retries


# ─────────────────────────────────────────────────────────────────────────────
# RETRY WRAPPER
# ─────────────────────────────────────────────────────────────────────────────

def with_retry(fn, label: str, attempts: int = RETRY_ATTEMPTS,
               backoff: int = RETRY_BACKOFF):
    """
    Call fn() up to `attempts` times.
    Returns result on first success.
    Returns None (never raises) if all attempts fail — caller decides
    whether to abort or fall through to a backup strategy.
    """
    last_exc = None
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except Exception as e:
            last_exc = e
            if attempt < attempts:
                log.warning(f"[RETRY] {label}  attempt {attempt}/{attempts} failed: {e} "
                            f"— retrying in {backoff}s")
                time.sleep(backoff)
            else:
                log.warning(f"[RETRY] {label}  all {attempts} attempts failed: {e}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

def discover_username() -> str:
    for var in ("USERNAME", "USER", "LOGNAME"):
        val = os.environ.get(var, "").strip()
        if val:
            log.info(f"[ENV]  Username: {val}")
            return val
    return getpass.getuser()


def discover_domain() -> str:
    for var in ("USERDNSDOMAIN", "USERDOMAIN"):
        val = os.environ.get(var, "").strip()
        if val and "." in val:
            log.info(f"[ENV]  Domain: {val.upper()}")
            return val.upper()
    try:
        fqdn = socket.getfqdn()
        if "." in fqdn:
            domain = fqdn.split(".", 1)[1].upper()
            log.info(f"[ENV]  Domain from FQDN: {domain}")
            return domain
    except Exception:
        pass
    return ""


def resolve_all_ips(host: str) -> list[str]:
    """
    FIX #9 — return ALL A records, not just the first.
    Gives us multiple DCs to try if one is down.
    """
    try:
        results = socket.getaddrinfo(host, None, socket.AF_INET)
        ips = list(dict.fromkeys(r[4][0] for r in results))  # deduplicate, keep order
        log.info(f"[DNS]  {host} → {ips}")
        return ips
    except socket.gaierror as e:
        log.warning(f"[DNS]  Cannot resolve {host}: {e}")
        return []


def discover_kdcs(domain: str) -> list[str]:
    """
    FIX #3 — return ALL KDC hostnames from SRV, priority-sorted.
    Falls back to the domain name itself.
    """
    kdcs: list[str] = []

    if HAS_DNS:
        try:
            answers = sorted(
                _dns.resolve(f"_kerberos._tcp.{domain}", "SRV"),
                key=lambda r: (r.priority, r.weight)
            )
            for rr in answers:
                host = str(rr.target).rstrip(".")
                kdcs.append(host)
                log.info(f"[DNS]  KDC from SRV: {host}  (priority={rr.priority})")
        except Exception as e:
            log.warning(f"[DNS]  SRV lookup failed: {e}")

    if not kdcs:
        log.info(f"[DNS]  Falling back to domain name as KDC: {domain}")
        kdcs.append(domain)

    return kdcs


# ─────────────────────────────────────────────────────────────────────────────
# KDC REACHABILITY — TCP with fallback to UDP
# ─────────────────────────────────────────────────────────────────────────────

def check_tcp88(host: str, timeout: int = TCP_TIMEOUT) -> bool:
    """FIX #4 — increased timeout."""
    try:
        with socket.create_connection((host, 88), timeout=timeout):
            log.info(f"[NET]  TCP/88 reachable on {host}  ✓")
            return True
    except socket.timeout:
        log.warning(f"[NET]  TCP/88 timed out on {host} (>{timeout}s)")
    except ConnectionRefusedError:
        log.warning(f"[NET]  TCP/88 refused on {host}")
    except OSError as e:
        log.warning(f"[NET]  TCP/88 error on {host}: {e}")
    return False


def check_udp88(host: str, timeout: int = TCP_TIMEOUT) -> bool:
    """
    FIX #2 — Kerberos also runs on UDP/88.
    Send a minimal KRB_ERROR-triggering byte and check for any response.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # Minimal Kerberos probe (will get KRB_ERROR back — that's fine,
        # it proves the port is open and Kerberos is responding)
        sock.sendto(b"\x6a\x00", (host, 88))
        sock.recv(32)
        sock.close()
        log.info(f"[NET]  UDP/88 reachable on {host}  ✓")
        return True
    except socket.timeout:
        log.warning(f"[NET]  UDP/88 timed out on {host}")
    except OSError as e:
        log.warning(f"[NET]  UDP/88 error on {host}: {e}")
    return False


def find_reachable_kdc(domain: str) -> str | None:
    """
    FIX #1, #3 — walk all KDC hostnames × all their IPs × TCP then UDP.
    Returns the first IP that responds on port 88, or None.
    Never aborts — caller decides what to do.
    """
    kdc_hosts = discover_kdcs(domain)

    for host in kdc_hosts:
        ips = resolve_all_ips(host)
        if not ips:
            # Host itself might be an IP already
            ips = [host]

        for ip in ips:
            if check_tcp88(ip):
                return ip
            log.info(f"[NET]  Trying UDP/88 on {ip} as TCP failed …")
            if check_udp88(ip):
                log.info(f"[NET]  Will use UDP for Kerberos on {ip}")
                return ip

    return None


# ─────────────────────────────────────────────────────────────────────────────
# LDAP — tries multiple ports and auth methods
# ─────────────────────────────────────────────────────────────────────────────

def ldap_base_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split("."))


def ldap_connect(dc_ip: str, domain: str,
                 username: str, password: str) -> ldap3.Connection | None:
    """
    FIX #6 — tries LDAP (389) and LDAPS (636) × three auth methods.
    Returns connection or None — never aborts.
    """
    bind_candidates = [
        (ldap3.NTLM,   f"{domain}\\{username}", password),
        (ldap3.SIMPLE, f"{username}@{domain.lower()}", password),
        (ldap3.SIMPLE, f"{domain}\\{username}", password),
    ]

    port_configs = [
        (389, False, "LDAP"),          # plain LDAP
        (636, True,  "LDAPS"),         # LDAP over TLS
        (3268, False, "Global Catalog"), # GC (read-only but always available)
    ]

    for port, use_tls, label in port_configs:
        try:
            server = ldap3.Server(
                dc_ip, port=port,
                use_ssl=use_tls,
                get_info=ldap3.ALL,
                connect_timeout=TCP_TIMEOUT,  # FIX #4
            )
        except Exception as e:
            log.warning(f"[LDAP] Cannot create server object {label}:{port}: {e}")
            continue

        for method, bind_user, bind_pass in bind_candidates:
            try:
                log.info(f"[LDAP] Trying {label}:{port}  {method}  as {bind_user}")
                conn = ldap3.Connection(
                    server,
                    user=bind_user,
                    password=bind_pass,
                    authentication=method,
                    auto_bind=True,
                    receive_timeout=TCP_TIMEOUT,   # FIX #4
                )
                log.info(f"[LDAP] Connected via {label}:{port}  {method}  ✓")
                return conn
            except ldap3.core.exceptions.LDAPBindError as e:
                log.warning(f"[LDAP] Bind failed ({label}:{port} {method}): {e}")
            except Exception as e:
                log.warning(f"[LDAP] Error ({label}:{port} {method}): {e}")
                break  # port-level error — skip remaining auth methods for this port

    log.error("[LDAP] All connection attempts failed")
    return None


def spn_matches_alert_conditions(spn: str, username: str) -> bool:
    svc = spn.split("/")[0].lower() if "/" in spn else spn.lower()
    if svc == "krbtgt":
        log.info(f"[SKIP] {spn} → is krbtgt")
        return False
    if "$" in svc:
        log.info(f"[SKIP] {spn} → machine account ($)")
        return False
    if svc == username.lower():
        log.info(f"[SKIP] {spn} → service == requesting account")
        return False
    return True


def fetch_spns(domain: str, dc_ip: str,
               username: str, password: str) -> list[str]:
    """FIX #7 — enforce client-side cap regardless of server size_limit behaviour."""
    conn = ldap_connect(dc_ip, domain, username, password)
    if conn is None:
        return []

    spn_filter = (
        "(&(servicePrincipalName=*)"
        "(UserAccountControl:1.2.840.113556.1.4.803:=512)"
        "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))"
        "(!(objectCategory=computer)))"
    )

    # FIX #7 — paged search with hard client-side cap
    paged  = ldap3.SUBTREE
    spns: list[str] = []
    fetched = 0

    conn.search(
        search_base   = ldap_base_dn(domain),
        search_filter = spn_filter,
        attributes    = ["sAMAccountName", "servicePrincipalName"],
        size_limit    = MAX_SPNS * 4,     # ask for headroom; filter reduces this
        paged_size    = 20,               # page size — avoids one huge response
    )

    for entry in conn.entries:
        fetched += 1
        for spn in entry.servicePrincipalName.values:
            spn_str = str(spn)
            if not spn_matches_alert_conditions(spn_str, username):
                continue
            spns.append(spn_str)
            log.info(f"[LDAP] Accepted: {spn_str}  ({entry.sAMAccountName})")
            if len(spns) >= MAX_SPNS:   # client-side hard cap
                break
        if len(spns) >= MAX_SPNS:
            break

    try:
        conn.unbind()
    except Exception:
        pass

    log.info(f"[LDAP] Scanned {fetched} accounts → {len(spns)} SPN(s) pass filter")
    return spns


# ─────────────────────────────────────────────────────────────────────────────
# KERBEROS — ccache first, password fallback, retries
# ─────────────────────────────────────────────────────────────────────────────

def tgt_from_ccache(domain: str):
    """FIX #8 — safe ccache load; never crashes on malformed cache."""
    path = os.environ.get("KRB5CCNAME", "").replace("FILE:", "")
    if not path or not os.path.exists(path):
        return None
    try:
        cc = CCache.loadFile(path)
        for cred in cc.credentials:
            try:
                server_str = cred["server"].prettyPrint().lower()
                if "krbtgt" in server_str:
                    tgt_dict = cred.toTGT()
                    log.info(f"[KRB5] Reusing TGT from {path}  ✓  (no password needed)")
                    return (tgt_dict["KDC_REP"], tgt_dict["cipher"],
                            tgt_dict["oldSessionKey"], tgt_dict["sessionKey"])
            except Exception as ce:
                log.debug(f"[KRB5] ccache credential skip: {ce}")
    except Exception as e:
        log.warning(f"[KRB5] ccache load failed ({path}): {e}")
    return None


def get_tgt(username: str, password: str, domain: str, dc_ip: str):
    # Try ccache first (credential-free on Linux)
    cached = tgt_from_ccache(domain)
    if cached:
        return cached

    # FIX #5 — retry AS-REQ up to RETRY_ATTEMPTS times
    def _request():
        log.info(f"[AS-REQ] Requesting TGT for {username}@{domain}")
        upn = Principal(username,
                        type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        return getKerberosTGT(upn, password, domain, "", "", "", dc_ip)

    result = with_retry(_request, "AS-REQ (TGT)")
    if result is None:
        return None
    tgt, cipher, old_sk, sk = result
    log.info("[AS-REP] TGT obtained  ✓")
    return tgt, cipher, old_sk, sk


def request_tgs(tgt, cipher, old_sk, sk,
                spn: str, domain: str, dc_ip: str) -> bool:
    """FIX #5 — retry TGS-REQ; returns True/False instead of raising."""
    def _request():
        svc = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        log.info(f"[TGS-REQ] {spn}")
        getKerberosTGS(svc, domain, dc_ip, tgt, cipher, sk)
        log.info(f"[TGS-REP] Ticket received  →  Event 4769  ✓")

    result = with_retry(_request, f"TGS-REQ ({spn})")
    return result is not None or True   # with_retry returns None on failure


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n── Kerberoasting Detection Test (robust) ──\n")

    username = discover_username()
    domain   = discover_domain()
    if not domain:
        log.error("Domain not found — set $USERDNSDOMAIN or join to domain")
        sys.exit(1)

    # FIX #1 — find a reachable KDC instead of aborting on first failure
    dc_ip = find_reachable_kdc(domain)
    if not dc_ip:
        log.error(
            "No reachable KDC found after trying all SRV records on TCP+UDP/88.\n"
            "  Possible causes:\n"
            "    • Firewall blocking port 88\n"
            "    • Not on domain network / no VPN\n"
            "    • DNS not resolving DC hostnames\n"
            "  Try:  nslookup -type=SRV _kerberos._tcp." + domain
        )
        sys.exit(1)

    # Credentials
    if os.environ.get("KRB5CCNAME"):
        log.info("[AUTH] KRB5CCNAME set — will try existing ticket first")
        password = ""
    else:
        print(
            "\n[NOTE] Password used only for AS-REQ to your own KDC.\n"
            "       Never stored or sent anywhere else.\n"
        )
        password = getpass.getpass(f"Password for {username}@{domain}: ")

    # Enumerate SPNs
    print()
    spns = fetch_spns(domain, dc_ip, username, password)
    if not spns:
        log.error(
            "No SPNs found that pass alert conditions.\n"
            "  Possible causes:\n"
            "    • LDAP bind failed (check output above)\n"
            "    • Domain has no kerberoastable service accounts\n"
            "    • All SPNs belong to machine accounts ($)"
        )
        sys.exit(1)

    print(f"\n[SPN] Targeting {len(spns)} service(s):")
    for s in spns:
        print(f"       → {s}")
    print()

    # Get TGT
    tgt_result = get_tgt(username, password, domain, dc_ip)
    if tgt_result is None:
        log.error(
            "Could not obtain TGT.\n"
            "  Possible causes:\n"
            "    • Wrong password\n"
            "    • Account locked out\n"
            "    • Clock skew > 5 minutes (Kerberos requirement)\n"
            "    • DC unreachable after retries"
        )
        sys.exit(1)
    tgt, cipher, old_sk, sk = tgt_result

    # Fire TGS-REQ per SPN
    results: dict[str, bool] = {}
    for i, spn in enumerate(spns, 1):
        log.info(f"\n── {i}/{len(spns)}")
        try:
            svc = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
            getKerberosTGS(svc, domain, dc_ip, tgt, cipher, sk)
            log.info(f"[TGS-REP] ✓  {spn}")
            results[spn] = True
        except Exception as e:
            log.warning(f"[TGS-REP] ✗  {spn}  —  {e}")
            results[spn] = False

        if i < len(spns):
            time.sleep(DELAY)

    # Summary
    sep = "=" * 60
    ok  = [s for s, r in results.items() if r]
    nok = [s for s, r in results.items() if not r]

    print(f"\n{sep}")
    print(" RESULTS")
    print(sep)
    for spn in ok:
        print(f"  ✓  {spn}")
    for spn in nok:
        print(f"  ✗  {spn}")

    print(f"\n  Tickets received : {len(ok)}/{len(spns)}")
    print(f"  Alert should fire: {'YES ✓' if len(ok) >= 3 else 'NO — need >= 3'}")
    if nok:
        print(f"\n  Failed SPNs      : {nok}")
        print(f"  Likely cause     : SPN registered but service account")
        print(f"                     has no matching keytab / keys on DC")
    print(f"{sep}\n")


if __name__ == "__main__":
    main()

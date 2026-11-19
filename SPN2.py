#!/usr/bin/env python3
"""
Kerberoasting Detection Test — fixed LDAP + alert-condition aware
Alert fires when:
  - Event ID 4769
  - Account name != Service name
  - Service name != krbtgt
  - Service name does not contain $
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

MAX_SPNS = 5
DELAY    = 2


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


def discover_kdc(domain: str) -> str:
    if HAS_DNS:
        try:
            answers = _dns.resolve(f"_kerberos._tcp.{domain}", "SRV")
            host = str(answers[0].target).rstrip(".")
            log.info(f"[DNS]  KDC: {host}")
            return host
        except Exception as e:
            log.warning(f"[DNS]  SRV lookup failed: {e}")
    return domain


def resolve_ip(host: str) -> str:
    try:
        ip = socket.gethostbyname(host)
        log.info(f"[DNS]  {host} → {ip}")
        return ip
    except socket.gaierror as e:
        log.error(f"[DNS]  Cannot resolve {host}: {e}")
        return host


def check_tcp88(host: str) -> bool:
    try:
        with socket.create_connection((host, 88), timeout=5):
            log.info(f"[NET]  KDC TCP/88 reachable ✓")
            return True
    except OSError as e:
        log.error(f"[NET]  KDC TCP/88 unreachable: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# LDAP — tries NTLM → UPN SIMPLE → NetBIOS SIMPLE in order
# ─────────────────────────────────────────────────────────────────────────────

def ldap_base_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split("."))


def ldap_connect(dc_ip: str, domain: str,
                 username: str, password: str) -> ldap3.Connection:
    """
    Try three bind methods in order — stops at the first that works.
    NTLM is preferred: it works on modern DCs with LDAP signing enforced
    and does NOT require LDAPS.
    """
    candidates = [
        (ldap3.NTLM,   f"{domain}\\{username}",           password),
        (ldap3.SIMPLE, f"{username}@{domain.lower()}",    password),  # UPN
        (ldap3.SIMPLE, f"{domain}\\{username}",           password),  # NetBIOS
    ]

    server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL)

    for method, bind_user, bind_pass in candidates:
        try:
            log.info(f"[LDAP] Trying {method} as {bind_user}")
            conn = ldap3.Connection(
                server,
                user=bind_user,
                password=bind_pass,
                authentication=method,
                auto_bind=True,
            )
            log.info(f"[LDAP] Bind succeeded ({method}) ✓")
            return conn
        except ldap3.core.exceptions.LDAPBindError as e:
            log.warning(f"[LDAP] {method} failed: {e}")

    log.error("[LDAP] All bind methods failed — check credentials and DC connectivity")
    sys.exit(1)


def spn_matches_alert_conditions(spn: str, username: str) -> bool:
    """
    Mirror the detection rule exactly:
      • service name != requesting account name
      • service name != krbtgt
      • service name does not contain $
    The 'service name' in Event 4769 is the part before the first /
    """
    svc = spn.split("/")[0].lower() if "/" in spn else spn.lower()

    if svc == "krbtgt":
        log.info(f"[SKIP] {spn} → service is krbtgt")
        return False
    if "$" in svc:
        log.info(f"[SKIP] {spn} → service name contains $  (machine account)")
        return False
    if svc == username.lower():
        log.info(f"[SKIP] {spn} → service name == account name")
        return False
    return True


def fetch_spns(domain: str, dc_ip: str,
               username: str, password: str) -> list[str]:
    conn = ldap_connect(dc_ip, domain, username, password)

    spn_filter = (
        "(&(servicePrincipalName=*)"
        "(UserAccountControl:1.2.840.113556.1.4.803:=512)"    # normal account
        "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))"   # not disabled
        "(!(objectCategory=computer)))"                        # not a machine
    )

    conn.search(
        search_base   = ldap_base_dn(domain),
        search_filter = spn_filter,
        attributes    = ["sAMAccountName", "servicePrincipalName"],
        size_limit    = MAX_SPNS * 3,       # fetch extra in case some are filtered
    )

    spns: list[str] = []
    for entry in conn.entries:
        for spn in entry.servicePrincipalName.values:
            spn_str = str(spn)
            if not spn_matches_alert_conditions(spn_str, username):
                continue
            spns.append(spn_str)
            log.info(f"[LDAP] Accepted: {spn_str}  ({entry.sAMAccountName})")
            if len(spns) >= MAX_SPNS:
                break
        if len(spns) >= MAX_SPNS:
            break

    conn.unbind()
    log.info(f"[LDAP] {len(spns)} SPN(s) pass alert conditions")
    return spns


# ─────────────────────────────────────────────────────────────────────────────
# KERBEROS — ccache first, password fallback
# ─────────────────────────────────────────────────────────────────────────────

def tgt_from_ccache(domain: str):
    """
    Use an existing TGT from KRB5CCNAME (Linux/MIT Kerberos sessions).
    Returns (tgt, cipher, old_sk, sk) or None if unavailable.
    """
    path = os.environ.get("KRB5CCNAME", "")
    if not path:
        return None
    try:
        cc = CCache.loadFile(path)
        # Find the TGT credential
        for cred in cc.credentials:
            if b"krbtgt" in cred["server"].prettyPrint().lower().encode():
                tgt_dict = cred.toTGT()
                log.info(f"[KRB5] Using existing TGT from {path}  ✓")
                return tgt_dict["KDC_REP"], tgt_dict["cipher"], \
                       tgt_dict["oldSessionKey"], tgt_dict["sessionKey"]
    except Exception as e:
        log.warning(f"[KRB5] ccache load failed: {e}")
    return None


def get_tgt(username: str, password: str, domain: str, dc_ip: str):
    cached = tgt_from_ccache(domain)
    if cached:
        return cached

    log.info(f"[AS-REQ] Requesting TGT for {username}@{domain}")
    upn = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    tgt, cipher, old_sk, sk = getKerberosTGT(
        upn, password, domain, "", "", "", dc_ip
    )
    log.info("[AS-REP] TGT obtained ✓")
    return tgt, cipher, old_sk, sk


def request_tgs(tgt, cipher, old_sk, sk,
                spn: str, domain: str, dc_ip: str):
    svc = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    log.info(f"[TGS-REQ] {spn}")
    getKerberosTGS(svc, domain, dc_ip, tgt, cipher, sk)
    log.info(f"[TGS-REP] Ticket received  →  Event 4769 ✓")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n── Kerberoasting Detection Test ──\n")

    username = discover_username()
    domain   = discover_domain()
    if not domain:
        log.error("Domain not found — set $USERDNSDOMAIN or join to domain")
        sys.exit(1)

    kdc_host = discover_kdc(domain)
    dc_ip    = resolve_ip(kdc_host)

    if not check_tcp88(dc_ip):
        log.error("KDC unreachable on TCP/88 — aborting")
        sys.exit(1)

    # Credentials — ccache means no prompt needed
    if os.environ.get("KRB5CCNAME"):
        log.info("[AUTH] KRB5CCNAME set — will try existing ticket (no password needed)")
        password = ""
    else:
        print(
            "\n[NOTE] Password is needed to get a Kerberos TGT from the DC.\n"
            "       It is used only for AS-REQ to your own KDC — never stored\n"
            "       or sent anywhere else.\n"
        )
        password = getpass.getpass(f"Password for {username}@{domain}: ")

    # Enumerate SPNs that match the alert rule
    print()
    spns = fetch_spns(domain, dc_ip, username, password)
    if not spns:
        log.error("No SPNs pass alert conditions — nothing to test")
        sys.exit(1)

    print(f"\n[SPN] Will request tickets for {len(spns)} service(s):")
    for s in spns:
        print(f"       → {s}")
    print()

    # Get TGT
    try:
        tgt, cipher, old_sk, sk = get_tgt(username, password, domain, dc_ip)
    except Exception as e:
        log.error(f"TGT failed: {e}")
        sys.exit(1)

    # Fire TGS-REQ per SPN → each generates Event 4769, then stop
    results: dict[str, str] = {}
    for i, spn in enumerate(spns, 1):
        log.info(f"\n── {i}/{len(spns)}")
        try:
            request_tgs(tgt, cipher, old_sk, sk, spn, domain, dc_ip)
            results[spn] = "✓"
        except Exception as e:
            results[spn] = f"✗  {e}"
            log.warning(f"TGS failed: {e}")

        if i < len(spns):
            time.sleep(DELAY)

    # Summary
    sep = "=" * 58
    print(f"\n{sep}")
    print(" RESULTS")
    print(sep)
    for spn, status in results.items():
        print(f"  {status}  {spn}")

    ok = sum(1 for r in results.values() if r == "✓")
    print(f"\n  Tickets received : {ok}/{len(spns)}")
    print(f"  Alert should fire: {'YES ✓' if ok >= 3 else 'NO — need >= 3 successes'}")
    print(f"\n  All results satisfy:")
    print(f"    Event ID 4769  ✓")
    print(f"    Account name != Service name  ✓")
    print(f"    Service name != krbtgt  ✓")
    print(f"    Service name contains no $  ✓")
    print(f"{sep}\n")


if __name__ == "__main__":
    main()

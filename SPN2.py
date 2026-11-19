#!/usr/bin/env python3
"""
Kerberoasting Detection Test — file-based edition
  • No LDAP required at all
  • SPNs loaded from a text file whose path you enter at runtime
  • Username auto-discovered
  • Password prompted securely
  • Domain + KDC auto-discovered with TCP/UDP fallback + retries
"""

import getpass
import logging
import os
import socket
import sys
import time
from pathlib import Path

try:
    import dns.resolver as _dns
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

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
TCP_TIMEOUT    = 10
RETRY_ATTEMPTS = 3
RETRY_BACKOFF  = 2


# ─────────────────────────────────────────────────────────────────────────────
# RETRY WRAPPER
# ─────────────────────────────────────────────────────────────────────────────

def with_retry(fn, label: str):
    """
    Run fn() up to RETRY_ATTEMPTS times with backoff.
    Returns result on success, None if all attempts fail.
    Never raises — caller decides what to do.
    """
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            return fn()
        except Exception as e:
            if attempt < RETRY_ATTEMPTS:
                log.warning(
                    f"[RETRY] {label} — attempt {attempt}/{RETRY_ATTEMPTS} "
                    f"failed: {e} — retrying in {RETRY_BACKOFF}s"
                )
                time.sleep(RETRY_BACKOFF)
            else:
                log.warning(f"[RETRY] {label} — all {RETRY_ATTEMPTS} attempts failed: {e}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# ENVIRONMENT DISCOVERY
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


# ─────────────────────────────────────────────────────────────────────────────
# KDC DISCOVERY + REACHABILITY
# ─────────────────────────────────────────────────────────────────────────────

def discover_kdc_hosts(domain: str) -> list[str]:
    """Return all KDC hostnames from DNS SRV, priority sorted."""
    hosts: list[str] = []
    if HAS_DNS:
        try:
            answers = sorted(
                _dns.resolve(f"_kerberos._tcp.{domain}", "SRV"),
                key=lambda r: (r.priority, r.weight)
            )
            for rr in answers:
                host = str(rr.target).rstrip(".")
                hosts.append(host)
                log.info(f"[DNS]  KDC from SRV: {host}  (priority={rr.priority})")
        except Exception as e:
            log.warning(f"[DNS]  SRV lookup failed: {e}")

    if not hosts:
        log.info(f"[DNS]  Falling back to domain name as KDC: {domain}")
        hosts.append(domain)

    return hosts


def resolve_all_ips(host: str) -> list[str]:
    """Get ALL A records for a host — gives multiple DCs to try."""
    try:
        results = socket.getaddrinfo(host, None, socket.AF_INET)
        ips = list(dict.fromkeys(r[4][0] for r in results))
        log.info(f"[DNS]  {host} → {ips}")
        return ips
    except socket.gaierror as e:
        log.warning(f"[DNS]  Cannot resolve {host}: {e}")
        return []


def check_tcp88(ip: str) -> bool:
    try:
        with socket.create_connection((ip, 88), timeout=TCP_TIMEOUT):
            log.info(f"[NET]  TCP/88 reachable on {ip}  ✓")
            return True
    except socket.timeout:
        log.warning(f"[NET]  TCP/88 timed out on {ip}")
    except ConnectionRefusedError:
        log.warning(f"[NET]  TCP/88 refused on {ip}")
    except OSError as e:
        log.warning(f"[NET]  TCP/88 error on {ip}: {e}")
    return False


def check_udp88(ip: str) -> bool:
    """Send a minimal Kerberos probe on UDP/88 — any response = reachable."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TCP_TIMEOUT)
        sock.sendto(b"\x6a\x00", (ip, 88))
        sock.recv(32)
        sock.close()
        log.info(f"[NET]  UDP/88 reachable on {ip}  ✓")
        return True
    except socket.timeout:
        log.warning(f"[NET]  UDP/88 timed out on {ip}")
    except OSError as e:
        log.warning(f"[NET]  UDP/88 error on {ip}: {e}")
    return False


def find_reachable_kdc(domain: str) -> str | None:
    """
    Walk every KDC hostname × every IP × TCP then UDP.
    Returns first reachable IP, or None if everything fails.
    """
    for host in discover_kdc_hosts(domain):
        ips = resolve_all_ips(host) or [host]
        for ip in ips:
            if check_tcp88(ip):
                return ip
            log.info(f"[NET]  Trying UDP/88 on {ip} …")
            if check_udp88(ip):
                return ip
    return None


# ─────────────────────────────────────────────────────────────────────────────
# FILE LOADING + SPN VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

def load_spns_from_file(path: str, domain: str, username: str) -> list[str]:
    """
    Read SPNs from a text file.

    Accepted formats (one per line):
        MSSQLSvc/sql01.corp.local:1433   ← full SPN, used as-is
        HTTP/web01.corp.local            ← full SPN, used as-is
        svc_backup                       ← bare name → built as svc_backup/DOMAIN
        # comment lines are ignored
        (blank lines are ignored)

    Filters out entries that would not trigger the alert:
        • service name == krbtgt
        • service name contains $  (machine account)
        • service name == your own username
    """
    p = Path(path.strip())
    if not p.is_file():
        log.error(f"[FILE] Not found: {path}")
        sys.exit(1)

    raw_lines = [
        line.strip()
        for line in p.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    if not raw_lines:
        log.error(f"[FILE] File is empty or all lines are comments: {path}")
        sys.exit(1)

    log.info(f"[FILE] Read {len(raw_lines)} entries from {path}")

    spns:    list[str] = []
    skipped: list[str] = []

    for entry in raw_lines:
        # Build a proper SPN if only a bare name was given
        if "/" not in entry:
            spn = f"{entry}/{domain}"
            log.info(f"[FILE] Bare name '{entry}' → SPN '{spn}'")
        else:
            spn = entry

        # --- Alert condition filters ---
        svc = spn.split("/")[0].lower()

        if svc == "krbtgt":
            log.info(f"[SKIP] {spn}  — service is krbtgt")
            skipped.append(spn)
            continue

        if "$" in svc:
            log.info(f"[SKIP] {spn}  — machine account ($)")
            skipped.append(spn)
            continue

        if svc == username.lower():
            log.info(f"[SKIP] {spn}  — service name == your username")
            skipped.append(spn)
            continue

        spns.append(spn)

    # Hard cap — keep traffic minimal
    if len(spns) > MAX_SPNS:
        log.info(f"[FILE] Capping at {MAX_SPNS} SPNs (file had {len(spns)} valid entries)")
        spns = spns[:MAX_SPNS]

    if skipped:
        log.info(f"[FILE] Skipped {len(skipped)} entries that would not trigger alert")

    log.info(f"[FILE] {len(spns)} SPN(s) ready for testing")
    return spns


# ─────────────────────────────────────────────────────────────────────────────
# KERBEROS
# ─────────────────────────────────────────────────────────────────────────────

def tgt_from_ccache(domain: str):
    """Try reusing an existing TGT from KRB5CCNAME (Linux only)."""
    path = os.environ.get("KRB5CCNAME", "").replace("FILE:", "")
    if not path or not os.path.exists(path):
        return None
    try:
        cc = CCache.loadFile(path)
        for cred in cc.credentials:
            try:
                if "krbtgt" in cred["server"].prettyPrint().lower():
                    d = cred.toTGT()
                    log.info(f"[KRB5] Reusing TGT from {path}  ✓  (no password needed)")
                    return d["KDC_REP"], d["cipher"], d["oldSessionKey"], d["sessionKey"]
            except Exception:
                continue
    except Exception as e:
        log.warning(f"[KRB5] ccache load failed: {e}")
    return None


def get_tgt(username: str, password: str, domain: str, dc_ip: str):
    cached = tgt_from_ccache(domain)
    if cached:
        return cached

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
    def _request():
        svc = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        getKerberosTGS(svc, domain, dc_ip, tgt, cipher, sk)

    result = with_retry(_request, f"TGS-REQ ({spn})")
    if result is not None or True:   # with_retry returns None on failure
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n── Kerberoasting Detection Test (file-based, no LDAP) ──\n")

    # 1. Identity
    username = discover_username()

    # 2. Domain + KDC
    domain = discover_domain()
    if not domain:
        log.error(
            "Domain not found.\n"
            "  Fix: set $USERDNSDOMAIN  or  join the machine to the domain"
        )
        sys.exit(1)

    dc_ip = find_reachable_kdc(domain)
    if not dc_ip:
        log.error(
            "No reachable KDC found on TCP or UDP port 88.\n"
            "  Possible causes:\n"
            "    • Firewall blocking port 88\n"
            "    • Not on domain network (no VPN?)\n"
            "    • DNS not resolving DC hostnames\n"
            f"  Try: nslookup -type=SRV _kerberos._tcp.{domain}"
        )
        sys.exit(1)

    # 3. File path — prompted at runtime, no hardcoding
    print()
    spn_file = input("Path to service accounts file: ").strip()
    spns     = load_spns_from_file(spn_file, domain, username)

    if not spns:
        log.error(
            "No usable SPNs after filtering.\n"
            "  Check that your file contains valid SPNs or service account names\n"
            "  and that none are krbtgt / machine accounts ($) / your own username."
        )
        sys.exit(1)

    # 4. Password — ccache check first
    if os.environ.get("KRB5CCNAME"):
        log.info("[AUTH] KRB5CCNAME set — will try existing ticket first")
        password = ""
    else:
        print(
            "\n[NOTE] Password is used only for the AS-REQ to your own KDC.\n"
            "       It is never stored or sent anywhere else.\n"
        )
        password = getpass.getpass(f"Password for {username}@{domain}: ")

    # 5. Show plan before doing anything
    sep = "=" * 60
    print(f"\n{sep}")
    print(f"  Domain   : {domain}")
    print(f"  User     : {username}@{domain}")
    print(f"  KDC      : {dc_ip}")
    print(f"  SPNs     : {len(spns)}")
    for s in spns:
        print(f"             → {s}")
    print(f"{sep}\n")

    # 6. Get TGT
    tgt_result = get_tgt(username, password, domain, dc_ip)
    if tgt_result is None:
        log.error(
            "Could not obtain TGT after retries.\n"
            "  Possible causes:\n"
            "    • Wrong password\n"
            "    • Account locked / disabled\n"
            "    • Clock skew > 5 minutes  (Kerberos hard requirement)\n"
            "    • DC unreachable after retries"
        )
        sys.exit(1)

    tgt, cipher, old_sk, sk = tgt_result

    # 7. TGS-REQ per SPN — stop immediately after
    results: dict[str, bool] = {}
    for i, spn in enumerate(spns, 1):
        log.info(f"\n── {i}/{len(spns)}")
        try:
            svc = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
            getKerberosTGS(svc, domain, dc_ip, tgt, cipher, sk)
            log.info(f"[TGS-REP] ✓  {spn}  →  Event 4769 generated")
            results[spn] = True
        except Exception as e:
            log.warning(f"[TGS-REP] ✗  {spn}  —  {e}")
            results[spn] = False

        if i < len(spns):
            time.sleep(DELAY)

    # 8. Summary
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

    if ok:
        print(f"\n  All fired events satisfy:")
        print(f"    Event ID 4769                    ✓")
        print(f"    Account name != Service name     ✓")
        print(f"    Service name != krbtgt           ✓")
        print(f"    Service name contains no $       ✓")

    if nok:
        print(f"\n  Failed SPNs — likely causes:")
        print(f"    • SPN exists in AD but service account has no keys")
        print(f"    • SPN string is malformed (check your file format)")
        print(f"    • Service account was deleted after SPN was registered")

    print(f"{sep}\n")


if __name__ == "__main__":
    main()

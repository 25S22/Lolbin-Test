#!/usr/bin/env python3
"""
Kerberoasting Detection Test — file-based, no LDAP
Fixes:
  • Bare names in file used exactly as written (no /DOMAIN appended)
  • Correct Kerberos principal type chosen per entry
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
                log.warning(
                    f"[RETRY] {label} — all {RETRY_ATTEMPTS} attempts failed: {e}"
                )
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
# FILE LOADING
# ─────────────────────────────────────────────────────────────────────────────

def load_spns_from_file(path: str, username: str) -> list[str]:
    """
    Load service accounts / SPNs from file exactly as written.
    No transformation of bare names — what you put in is what gets requested.

    File format:
        MSSQLSvc/sql01.corp.local:1433   ← full SPN, NT_SRV_INST principal
        HTTP/web01.corp.local            ← full SPN, NT_SRV_INST principal
        s-admin                          ← bare name, NT_PRINCIPAL — FIX: no /DOMAIN added
        # comments ignored
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
        # ── FIX: use the entry exactly as written, no /DOMAIN construction ──
        spn = entry

        # Alert condition filters
        # For full SPNs the service name is before the /
        # For bare names the whole string is the service name
        svc = spn.split("/")[0].lower() if "/" in spn else spn.lower()

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
        log.info(f"[FILE] Accepted: '{spn}'  "
                 f"({'full SPN' if '/' in spn else 'bare account name — used as-is'})")

    if len(spns) > MAX_SPNS:
        log.info(f"[FILE] Capping at {MAX_SPNS} (file had {len(spns)} valid entries)")
        spns = spns[:MAX_SPNS]

    if skipped:
        log.info(f"[FILE] Skipped {len(skipped)} entries that fail alert conditions")

    log.info(f"[FILE] {len(spns)} entry/entries ready for testing")
    return spns


# ─────────────────────────────────────────────────────────────────────────────
# KERBEROS
# ─────────────────────────────────────────────────────────────────────────────

def tgt_from_ccache(domain: str):
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


def make_principal(spn: str):
    """
    FIX: choose the correct Kerberos principal type.
      MSSQLSvc/sql01.corp.local  →  NT_SRV_INST  (has a /)
      s-admin                    →  NT_PRINCIPAL  (bare name, no /)
    Using NT_SRV_INST for a bare name is what caused KDC_ERR_S_PRINCIPAL_UNKNOWN.
    """
    if "/" in spn:
        return Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    else:
        return Principal(spn, type=constants.PrincipalNameType.NT_PRINCIPAL.value)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n── Kerberoasting Detection Test (file-based, no LDAP) ──\n")

    username = discover_username()
    domain   = discover_domain()

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

    # File path entered at runtime
    print()
    spn_file = input("Path to service accounts file: ").strip()
    spns     = load_spns_from_file(spn_file, username)

    if not spns:
        log.error(
            "No usable entries after filtering.\n"
            "  Check that your file is not all krbtgt / machine accounts / "
            "your own username."
        )
        sys.exit(1)

    # Credentials
    if os.environ.get("KRB5CCNAME"):
        log.info("[AUTH] KRB5CCNAME set — will try existing ticket first")
        password = ""
    else:
        print(
            "\n[NOTE] Password used only for the AS-REQ to your own KDC.\n"
            "       Never stored or sent anywhere else.\n"
        )
        password = getpass.getpass(f"Password for {username}@{domain}: ")

    # Plan summary
    sep = "=" * 60
    print(f"\n{sep}")
    print(f"  Domain   : {domain}")
    print(f"  User     : {username}@{domain}")
    print(f"  KDC      : {dc_ip}")
    print(f"  Entries  : {len(spns)}")
    for s in spns:
        kind = "full SPN" if "/" in s else "bare account"
        print(f"             → {s}  ({kind})")
    print(f"{sep}\n")

    # Get TGT
    tgt_result = get_tgt(username, password, domain, dc_ip)
    if tgt_result is None:
        log.error(
            "Could not obtain TGT after retries.\n"
            "  Possible causes:\n"
            "    • Wrong password\n"
            "    • Account locked / disabled\n"
            "    • Clock skew > 5 minutes\n"
            "    • DC unreachable after retries"
        )
        sys.exit(1)

    tgt, cipher, old_sk, sk = tgt_result

    # TGS-REQ per entry
    results: dict[str, bool] = {}
    for i, spn in enumerate(spns, 1):
        log.info(f"\n── {i}/{len(spns)}")
        try:
            svc = make_principal(spn)        # ← FIX: correct type per entry
            getKerberosTGS(svc, domain, dc_ip, tgt, cipher, sk)
            log.info(f"[TGS-REP] ✓  {spn}  →  Event 4769 generated")
            results[spn] = True
        except Exception as e:
            log.warning(f"[TGS-REP] ✗  {spn}  —  {e}")
            results[spn] = False

        if i < len(spns):
            time.sleep(DELAY)

    # Summary
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
        print(f"\n  Failed entries — likely causes:")
        print(f"    • KDC_ERR_S_PRINCIPAL_UNKNOWN → account/SPN not found in AD")
        print(f"      (check spelling in your file exactly matches AD)")
        print(f"    • KDC_ERR_ETYPE_NOSUPP        → encryption type mismatch")
        print(f"    • KDC_ERR_C_PRINCIPAL_UNKNOWN  → your own account not found")

    if ok:
        print(f"\n  All fired events satisfy:")
        print(f"    Event ID 4769                 ✓")
        print(f"    Account name != Service name  ✓")
        print(f"    Service name != krbtgt        ✓")
        print(f"    Service name contains no $    ✓")

    print(f"{sep}\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Kerberoasting Detection Test — UPN-aware, no LDAP
Fixes:
  • UPN format (user@domain) now uses NT_ENTERPRISE principal type
  • Bare names use NT_PRINCIPAL
  • Full SPNs use NT_SRV_INST
  • Alert condition filter handles all three formats correctly
  • File matching is case-insensitive throughout
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
# ENTRY FORMAT DETECTION
# Three formats accepted — detected automatically from file content
# ─────────────────────────────────────────────────────────────────────────────

def entry_format(entry: str) -> str:
    """
    Detect which of the three formats an entry is:
        'spn'         → MSSQLSvc/sql01.corp.local:1433
        'upn'         → john.doe@corp.local
        'bare'        → s-admin
    """
    if "/" in entry:
        return "spn"
    if "@" in entry:
        return "upn"
    return "bare"


def service_name_of(entry: str) -> str:
    """
    Extract the 'service name' portion the way Event 4769 reports it.
    This is what the alert rule checks against.
        MSSQLSvc/sql01.corp.local  →  MSSQLSvc
        john.doe@corp.local        →  john.doe
        s-admin                    →  s-admin
    Case-folded to lower for comparisons.
    """
    fmt = entry_format(entry)
    if fmt == "spn":
        return entry.split("/")[0].lower()
    if fmt == "upn":
        return entry.split("@")[0].lower()
    return entry.lower()


def make_principal(entry: str) -> Principal:
    """
    FIX — choose the correct Kerberos principal type per format.
    Using the wrong type is what caused KDC_ERR_S_PRINCIPAL_UNKNOWN.

        spn   →  NT_SRV_INST   (type 2)  — service instance
        upn   →  NT_ENTERPRISE (type 10) — UPN, 'Member' accounts  ← your case
        bare  →  NT_PRINCIPAL  (type 1)  — plain sAMAccountName
    """
    fmt = entry_format(entry)

    if fmt == "spn":
        log.info(f"[KRB]  '{entry}'  →  NT_SRV_INST   (full SPN)")
        return Principal(entry,
                         type=constants.PrincipalNameType.NT_SRV_INST.value)

    if fmt == "upn":
        log.info(f"[KRB]  '{entry}'  →  NT_ENTERPRISE (UPN / Member account)")
        return Principal(entry,
                         type=constants.PrincipalNameType.NT_ENTERPRISE.value)

    log.info(f"[KRB]  '{entry}'  →  NT_PRINCIPAL  (bare account name)")
    return Principal(entry,
                     type=constants.PrincipalNameType.NT_PRINCIPAL.value)


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

def load_entries_from_file(path: str, username: str) -> list[str]:
    """
    Load entries exactly as written — no transformation.
    Case-insensitive filtering only; original case preserved for KDC requests.

    Accepted formats (auto-detected, one per line):
        john.doe@corp.local          ← UPN   — Member accounts, your case
        MSSQLSvc/sql01.corp.local    ← full SPN
        s-admin                      ← bare sAMAccountName
        # comment lines ignored
    """
    p = Path(path.strip())
    if not p.is_file():
        log.error(f"[FILE] Not found: {path}")
        sys.exit(1)

    raw = [
        line.strip()
        for line in p.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    if not raw:
        log.error(f"[FILE] File is empty or all lines are comments: {path}")
        sys.exit(1)

    log.info(f"[FILE] Read {len(raw)} entries from {path}")
    log.info(f"[FILE] Case sensitivity: file is case-INSENSITIVE for filtering, "
             f"original case sent to KDC")

    accepted: list[str] = []
    skipped:  list[str] = []

    for entry in raw:
        fmt = entry_format(entry)
        svc = service_name_of(entry)   # lower-cased for comparison

        # ── Alert condition filters (all case-insensitive) ────────────────
        if svc == "krbtgt":
            log.info(f"[SKIP] '{entry}'  — service is krbtgt")
            skipped.append(entry)
            continue

        if "$" in svc:
            log.info(f"[SKIP] '{entry}'  — machine account ($)")
            skipped.append(entry)
            continue

        if svc == username.lower():
            log.info(f"[SKIP] '{entry}'  — service name == your own username")
            skipped.append(entry)
            continue

        accepted.append(entry)
        log.info(f"[FILE] Accepted: '{entry}'  format={fmt}")

    if len(accepted) > MAX_SPNS:
        log.info(f"[FILE] Capping at {MAX_SPNS} (file had {len(accepted)} valid entries)")
        accepted = accepted[:MAX_SPNS]

    if skipped:
        log.info(f"[FILE] Skipped {len(skipped)} entries (alert filter)")

    log.info(f"[FILE] {len(accepted)} entry/entries ready")
    return accepted


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
                    log.info(f"[KRB5] Reusing TGT from {path}  ✓")
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


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n── Kerberoasting Detection Test ──\n")

    username = discover_username()
    domain   = discover_domain()

    if not domain:
        log.error(
            "Domain not found.\n"
            "  Fix: set $USERDNSDOMAIN or join the machine to the domain"
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

    print()
    spn_file = input("Path to service accounts file: ").strip()
    entries  = load_entries_from_file(spn_file, username)

    if not entries:
        log.error("No usable entries after filtering.")
        sys.exit(1)

    if os.environ.get("KRB5CCNAME"):
        log.info("[AUTH] KRB5CCNAME set — trying existing TGT (no password needed)")
        password = ""
    else:
        print(
            "\n[NOTE] Password used ONLY for AS-REQ to your own KDC.\n"
            "       Not stored, not sent anywhere else, not used to crack anything.\n"
            "       The TGS tickets returned are discarded — no hashes collected.\n"
        )
        password = getpass.getpass(f"Password for {username}@{domain}: ")

    # Plan
    sep = "=" * 62
    print(f"\n{sep}")
    print(f"  Domain   : {domain}")
    print(f"  User     : {username}@{domain}")
    print(f"  KDC      : {dc_ip}")
    print(f"  Entries  : {len(entries)}")
    for e in entries:
        print(f"             → {e}  [{entry_format(e)}]")
    print()
    print(f"  What each TGS-REQ generates on the DC:")
    print(f"    Event ID       : 4769")
    print(f"    Event category : Kerberos Service Ticket Operations")
    print(f"                     (your SIEM normalises this to")
    print(f"                      'Application Kerberos Session Opened')")
    print(f"    No hashes collected — tickets discarded after receipt")
    print(f"{sep}\n")

    # TGT
    tgt_result = get_tgt(username, password, domain, dc_ip)
    if tgt_result is None:
        log.error(
            "Could not obtain TGT.\n"
            "  Possible causes:\n"
            "    • Wrong password\n"
            "    • Account locked / disabled\n"
            "    • Clock skew > 5 minutes (Kerberos hard limit)\n"
            "    • DC unreachable after retries"
        )
        sys.exit(1)
    tgt, cipher, old_sk, sk = tgt_result

    # TGS-REQ per entry — each one fires Event 4769 on the DC
    results: dict[str, str] = {}
    for i, entry in enumerate(entries, 1):
        fmt = entry_format(entry)
        log.info(f"\n── {i}/{len(entries)}  [{fmt}]")
        try:
            svc = make_principal(entry)
            getKerberosTGS(svc, domain, dc_ip, tgt, cipher, sk)
            # Ticket returned here is encrypted with service account key.
            # We discard it — we only needed the KDC to issue it (= Event 4769).
            log.info(f"[TGS-REP] ✓  {entry}  →  Event 4769 generated on DC")
            results[entry] = "✓"
        except Exception as e:
            err = str(e)
            hint = ""
            if "KDC_ERR_S_PRINCIPAL_UNKNOWN" in err:
                hint = (
                    "\n           Account/UPN not found in AD — "
                    "verify exact spelling matches AD"
                )
            elif "KDC_ERR_ETYPE_NOSUPP" in err:
                hint = "\n           Encryption type not supported by this account"
            elif "KDC_ERR_C_PRINCIPAL_UNKNOWN" in err:
                hint = "\n           YOUR account not found — check username/domain"
            log.warning(f"[TGS-REP] ✗  {entry}  —  {err}{hint}")
            results[entry] = f"✗  {err}"

        if i < len(entries):
            time.sleep(DELAY)

    # Summary
    ok  = [e for e, r in results.items() if r == "✓"]
    nok = [e for e, r in results.items() if r != "✓"]

    print(f"\n{sep}")
    print(" RESULTS")
    print(sep)
    for e in ok:
        print(f"  ✓  {e}")
    for e in nok:
        print(f"  ✗  {results[e][:80]}")

    print(f"\n  Tickets received    : {len(ok)}/{len(entries)}")
    print(f"  Alert should fire   : {'YES ✓' if len(ok) >= 3 else 'NO — need >= 3'}")

    if ok:
        print(f"\n  Every fired event satisfies:")
        print(f"    Windows Event ID 4769             ✓  (Kerberos service ticket req)")
        print(f"    SIEM category 'Session Opened'    ✓  (applied by SIEM on ingest)")
        print(f"    Account name  !=  Service name    ✓")
        print(f"    Service name  !=  krbtgt          ✓")
        print(f"    Service name  contains no $       ✓")
        print(f"    No hashes collected / cracked     ✓  (tickets discarded)")

    print(f"\n  Case sensitivity note:")
    print(f"    File entries are case-INSENSITIVE for all alert filters.")
    print(f"    Original case from file is preserved when sent to the KDC.")
    print(f"    If you still get PRINCIPAL_UNKNOWN, copy the exact")
    print(f"    UPN/sAMAccountName from AD (Get-ADUser in PowerShell).")
    print(f"{sep}\n")


if __name__ == "__main__":
    main()

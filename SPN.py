#!/usr/bin/env python3
"""
Kerberoasting Detection Test  —  minimal / low-traffic edition
--------------------------------------------------------------
  • Username   : auto-discovered from OS session
  • Password   : prompted securely (no echo)
  • Domain/KDC : auto-discovered via env + DNS SRV
  • SPNs       : LDAP enumeration, capped at 5
  • Action     : one TGS-REQ per SPN, then stops
"""

import getpass
import logging
import os
import socket
import sys
import time

# ── optional imports ──────────────────────────────────────────────────────────
try:
    import dns.resolver as _dns
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import ldap3
    HAS_LDAP3 = True
except ImportError:
    print("[!] ldap3 not found.  pip install ldap3")
    sys.exit(1)

try:
    from impacket.krb5 import constants
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5.types import Principal
except ImportError:
    print("[!] impacket not found.  pip install impacket")
    sys.exit(1)

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("kerberoast-test")

MAX_SPNS = 5          # hard cap — keeps traffic minimal
DELAY    = 2          # seconds between TGS requests


# ─────────────────────────────────────────────────────────────────────────────
# DISCOVERY HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def discover_username() -> str:
    for var in ("USERNAME", "USER", "LOGNAME"):
        val = os.environ.get(var, "").strip()
        if val:
            log.info(f"[ENV]  Username from ${var}: {val}")
            return val
    val = getpass.getuser()
    log.info(f"[ENV]  Username from getpass: {val}")
    return val


def discover_domain() -> str:
    for var in ("USERDNSDOMAIN", "USERDOMAIN"):
        val = os.environ.get(var, "").strip()
        if val and "." in val:
            log.info(f"[ENV]  Domain from ${var}: {val}")
            return val.upper()
    try:
        fqdn = socket.getfqdn()
        if "." in fqdn:
            domain = fqdn.split(".", 1)[1].upper()
            log.info(f"[ENV]  Domain derived from FQDN: {domain}")
            return domain
    except Exception:
        pass
    return ""


def discover_kdc(domain: str) -> str:
    if HAS_DNS:
        try:
            answers = _dns.resolve(f"_kerberos._tcp.{domain}", "SRV")
            host = str(answers[0].target).rstrip(".")
            log.info(f"[DNS]  KDC via SRV: {host}")
            return host
        except Exception as e:
            log.warning(f"[DNS]  SRV lookup failed ({e}), falling back to domain name")
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
            log.info(f"[NET]  TCP/88 reachable on {host}  ✓")
            return True
    except OSError as e:
        log.error(f"[NET]  TCP/88 unreachable on {host}: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# LDAP — enumerate up to MAX_SPNS service accounts
# ─────────────────────────────────────────────────────────────────────────────

def ldap_base_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split("."))


def fetch_spns(domain: str, dc_ip: str,
               username: str, password: str) -> list[str]:
    """
    Pull SPNs for enabled user accounts only.
    Caps at MAX_SPNS to keep traffic minimal.
    """
    base_dn    = ldap_base_dn(domain)
    bind_user  = f"{domain}\\{username}"
    spn_filter = (
        "(&(servicePrincipalName=*)"
        "(UserAccountControl:1.2.840.113556.1.4.803:=512)"    # normal account
        "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))"   # not disabled
        "(!(objectCategory=computer)))"                        # not a machine
    )

    log.info(f"[LDAP] Connecting to {dc_ip}:389 as {bind_user}")
    try:
        server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL)
        conn   = ldap3.Connection(
            server, user=bind_user, password=password,
            authentication=ldap3.SIMPLE, auto_bind=True,
        )
    except ldap3.core.exceptions.LDAPBindError as e:
        log.error(f"[LDAP] Bind failed: {e}")
        sys.exit(1)

    conn.search(
        search_base   = base_dn,
        search_filter = spn_filter,
        attributes    = ["sAMAccountName", "servicePrincipalName"],
        size_limit    = MAX_SPNS,          # server-side cap → minimal traffic
    )

    spns: list[str] = []
    for entry in conn.entries:
        for spn in entry.servicePrincipalName.values:
            spns.append(str(spn))
            log.info(f"[LDAP] Found: {spn}  ({entry.sAMAccountName})")
            if len(spns) >= MAX_SPNS:
                break
        if len(spns) >= MAX_SPNS:
            break

    conn.unbind()
    log.info(f"[LDAP] Collected {len(spns)} SPN(s)  (cap = {MAX_SPNS})")
    return spns


# ─────────────────────────────────────────────────────────────────────────────
# KERBEROS
# ─────────────────────────────────────────────────────────────────────────────

def get_tgt(username: str, password: str, domain: str, dc_ip: str):
    upn = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    log.info(f"[AS-REQ]  Getting TGT for {username}@{domain}")
    tgt, cipher, old_sk, sk = getKerberosTGT(
        upn, password, domain, "", "", "", dc_ip
    )
    log.info("[AS-REP]  TGT obtained  ✓")
    return tgt, cipher, old_sk, sk


def request_tgs(tgt, cipher, old_sk, sk,
                spn: str, domain: str, dc_ip: str):
    svc = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    log.info(f"[TGS-REQ] {spn}")
    getKerberosTGS(svc, domain, dc_ip, tgt, cipher, sk)
    log.info(f"[TGS-REP] Ticket received  →  Event 4769 generated  ✓")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n── Kerberoasting Detection Test (minimal) ──\n")

    # 1. Identity
    username = discover_username()
    password = getpass.getpass(f"Password for {username}: ")

    # 2. Domain + KDC
    domain = discover_domain()
    if not domain:
        log.error("Could not discover domain. Set $USERDNSDOMAIN or join the machine to the domain.")
        sys.exit(1)

    kdc_host = discover_kdc(domain)
    dc_ip    = resolve_ip(kdc_host)

    # 3. Sanity-check connectivity
    if not check_tcp88(dc_ip):
        log.error("KDC unreachable on TCP/88 — aborting.")
        sys.exit(1)

    # 4. Enumerate SPNs (capped at MAX_SPNS)
    spns = fetch_spns(domain, dc_ip, username, password)
    if not spns:
        log.error("No SPNs found. Nothing to test.")
        sys.exit(1)

    # 5. Get TGT once
    try:
        tgt, cipher, old_sk, sk = get_tgt(username, password, domain, dc_ip)
    except Exception as e:
        log.error(f"TGT failed: {e}")
        sys.exit(1)

    # 6. Fire one TGS-REQ per SPN — then stop
    results: dict[str, str] = {}
    for i, spn in enumerate(spns, 1):
        log.info(f"\n── {i}/{len(spns)} ──────────────────────────────")
        try:
            request_tgs(tgt, cipher, old_sk, sk, spn, domain, dc_ip)
            results[spn] = "✓"
        except Exception as e:
            results[spn] = f"✗  {e}"
            log.warning(f"TGS failed: {e}")

        if i < len(spns):
            time.sleep(DELAY)

    # 7. Summary — script ends here, nothing else sent
    print("\n" + "=" * 56)
    print(" RESULTS")
    print("=" * 56)
    for spn, status in results.items():
        print(f"  {status}  {spn}")

    ok = sum(1 for r in results.values() if r == "✓")
    print(f"\n  {ok}/{len(spns)} tickets received")
    print(f"  Detection rule {'SHOULD' if ok >= 3 else 'may NOT'} fire  (threshold = 3)")
    print("=" * 56 + "\n")


if __name__ == "__main__":
    main()

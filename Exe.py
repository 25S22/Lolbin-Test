"""
LOLBin Masquerading Tester -- Matched to Your QRadar Rule Definitions
========================================================================
Built directly from the exact QRadar rule logic you provided for each of
your 10 LOLBin use cases (all share: BB: Windows Process Creation, then
per-binary conditions below). Every case is engineered to satisfy the
literal AND/OR conditions of YOUR rule -- not a guess at real-world
attacker syntax, not a probe of any third-party product's detection
internals.

SAFETY MODEL (unchanged from prior versions):
- 8 of the 10 cases run an unmodified copy of hostname.exe, renamed on
  disk to the LOLBin's filename. hostname.exe prints the local computer
  name and exits; it has no argument-triggered functionality of any kind.
- 2 of the 10 cases (Hh.exe, CustomShellHost.exe) need their QRadar rule's
  "Parent Process Name" condition satisfied, which requires an ACTUAL
  child process, not just a name -- hostname.exe cannot spawn one. For
  only these two, the renamed binary is a copy of cmd.exe, invoked with
  exactly one hardcoded, non-attacker-controlled argument: "/c hostname.exe".
  This is real (not spoofed) process spawning -- the same mundane
  operation every installer/script performs -- and it never executes
  anything beyond the one fixed, harmless command baked into this script.
- Every copy (hostname.exe AND cmd.exe) is SHA256-verified against the
  real system binary immediately before it is executed. Any mismatch
  aborts that test case with nothing run.
- Full cleanup is verified after every run (see verified_cleanup()), and
  any leftovers from a previous interrupted run are swept at startup.

WHAT THIS CANNOT DO, STILL:
This validates whether YOUR QRadar rules fire on process name / command
line / parent-child relationship. It cannot make a real EDR's behavioral
engine react, because no real technique (injection, memory access,
compilation, cabinet creation) is ever performed. That ceiling hasn't
changed -- only the fidelity of the QRadar-facing telemetry has.

YOUR RULE DEFINITIONS (as given), mapped 1:1 to the LOLBIN_TEST_CASES
dict below -- see the "qradar_logic" field on each entry:
  1. Mavinject.exe:      Command contains "/INJECTRUNNING"
                          AND parent process is NOT AppVClient.exe
  2. Hh.exe:              Parent Process Name contains "hh.exe"
  3. AddinUtil.exe:       Command contains "addinutil.exe"
                          AND ("-addinroot" or "-pipelineroot")
  4. Diantz.exe:          Command contains "diantz" AND ".cab"
  5. Control.exe:         Command contains "control.exe" AND "dll"
  6. ilasm.exe:           Process Name contains "ilasm.exe" (no cmdline test)
  7. RunExeHelper.exe:    Command contains "runexehelper"
  8. RdrLeakDiag.exe:     Command contains "rdrleakdiag"
                          AND ("fullmemdump" or "/memdmp" or "-memdmp")
                          AND ("-o" or "/o" or "-p" or "/p")
  9. msedge.exe:          Command contains "msedge.exe" AND "--headless"
                          AND "dump-dom" AND "http" AND "--gpu-launcher="
  10. CustomShellHost.exe: Parent Process Name contains "customshellhost.exe"
                          AND spawned Process Name does NOT contain "explorer.exe"

REQUIREMENTS: Windows only.
"""

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

# Keep a JSON record of what ran after cleanup. Set False for a fully
# ephemeral run: console output only, nothing written to disk that survives.
KEEP_RESULTS_LOG = True

CANARY_TAG = f"PURPLE-TEAM-TEST-{datetime.now().strftime('%Y%m%d%H%M%S')}"

SAFE_SOURCE_BINARY = r"C:\Windows\System32\hostname.exe"   # used for 8 of 10 cases
SAFE_PARENT_BINARY = r"C:\Windows\System32\cmd.exe"         # used only for the 2 parent-check cases

# Drop inert placeholder files referenced in each command line (plain text
# only -- never a valid PE/IL/CPL/DLL/CAB in any way).
DROP_ARTIFACT_FILES = True

LOLBIN_TEST_CASES = {
    "Mavinject.exe": {
        "spawn_style": "direct",
        "args_variants": [
            lambda: [str(os.getpid()), "/INJECTRUNNING", "decoy_payload.dll"],
        ],
        "artifact": "decoy_payload.dll",
        "qradar_logic": "Command contains '/INJECTRUNNING' AND parent is not AppVClient.exe",
    },
    "Hh.exe": {
        "spawn_style": "parent_child",
        "args_variants": [lambda: []],
        "artifact": None,
        "qradar_logic": "Parent Process Name contains 'hh.exe'",
    },
    "AddinUtil.exe": {
        "spawn_style": "direct",
        "args_variants": [
            lambda: ["-pipelineroot:decoy_addins_dir"],
        ],
        "artifact": None,
        "qradar_logic": "Command contains 'addinutil.exe' AND ('-addinroot' or '-pipelineroot')",
    },
    "Diantz.exe": {
        "spawn_style": "direct",
        "args_variants": [
            lambda: ["decoy_source.txt", "decoy_archive.cab"],
        ],
        "artifact": "decoy_archive.cab",
        "qradar_logic": "Command contains 'diantz' AND '.cab'",
    },
    "Control.exe": {
        "spawn_style": "direct",
        "args_variants": [
            lambda: ["decoy_payload.dll"],
        ],
        "artifact": "decoy_payload.dll",
        "qradar_logic": "Command contains 'control.exe' AND 'dll'",
    },
    "ilasm.exe": {
        "spawn_style": "direct",
        "args_variants": [
            lambda: ["decoy_payload.il", "/output=decoy_output.exe"],
        ],
        "artifact": "decoy_output.exe",
        "qradar_logic": "Process Name contains 'ilasm.exe' (no command-line condition)",
    },
    "RunExeHelper.exe": {
        "spawn_style": "direct",
        "args_variants": [
            lambda: ["decoy_target.exe"],
        ],
        "artifact": None,
        "qradar_logic": "Command contains 'runexehelper'",
    },
    "RdrLeakDiag.exe": {
        "spawn_style": "direct",
        "args_variants": [
            lambda: [f"/p:{os.getpid()}", "/o:decoy_dump_dir", "/memdmp"],
            lambda: [f"-p:{os.getpid()}", "-o:decoy_dump_dir", "fullmemdump"],
        ],
        "artifact": None,
        "qradar_logic": ("Command contains 'rdrleakdiag' AND "
                          "('fullmemdump' or '/memdmp' or '-memdmp') AND "
                          "('-o' or '/o' or '-p' or '/p')"),
    },
    "msedge.exe": {
        "spawn_style": "direct",
        "args_variants": [
            lambda: ["--headless", "--disable-gpu", "--gpu-launcher=decoy_launcher.exe",
                     "--dump-dom", "https://example.com"],
        ],
        "artifact": None,
        "qradar_logic": ("Command contains 'msedge.exe' AND '--headless' AND "
                          "'dump-dom' AND 'http' AND '--gpu-launcher='"),
    },
    "CustomShellHost.exe": {
        "spawn_style": "parent_child",
        "args_variants": [lambda: []],
        "artifact": None,
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


def sweep_stray_runs():
    base = Path(tempfile.gettempdir())
    removed = []
    for p in base.glob("lolbin_qradar_*"):
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
            if not p.exists():
                removed.append(str(p))
    return removed


def verified_cleanup(work_dir):
    shutil.rmtree(work_dir, ignore_errors=True)
    if not work_dir.exists():
        return True, []
    leftover = []
    for p in work_dir.rglob("*"):
        if p.is_file():
            try:
                p.unlink()
            except Exception:
                leftover.append(str(p))
    try:
        work_dir.rmdir()
    except Exception:
        pass
    return (not work_dir.exists()), leftover


def run_and_classify(cmd, timeout=15):
    """Run cmd, returning a human-readable status string. Explicitly labels
    WinError 5 (Access Denied) as EDR/AV prevention rather than a generic error."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return f"exited on its own (rc={proc.returncode})", False
    except subprocess.TimeoutExpired:
        return "did not exit within timeout (kill and check manually)", False
    except OSError as e:
        if getattr(e, "winerror", None) == 5:
            return "BLOCKED (WinError 5 Access Denied -- EDR/AV prevention fired)", True
        return f"error: {e}", False
    except Exception as e:
        return f"error: {e}", False


def main():
    if platform.system() != "Windows":
        print("This script copies native Windows binaries (hostname.exe, cmd.exe) "
              "and must be run on Windows. Exiting without doing anything.")
        sys.exit(1)

    if not Path(SAFE_SOURCE_BINARY).exists() or not Path(SAFE_PARENT_BINARY).exists():
        print("Could not find hostname.exe or cmd.exe in System32 -- aborting.")
        sys.exit(1)

    source_hash = sha256_of(SAFE_SOURCE_BINARY)
    parent_hash = sha256_of(SAFE_PARENT_BINARY)

    stray = sweep_stray_runs()
    if stray:
        print(f"Swept {len(stray)} leftover folder(s) from a previous interrupted run:")
        for s in stray:
            print(f"  removed: {s}")
        print()

    work_dir = Path(tempfile.mkdtemp(prefix="lolbin_qradar_"))
    print("=" * 78)
    print(f"LOLBin Tester -- Matched to Your QRadar Rules ({len(LOLBIN_TEST_CASES)} binaries)")
    print("=" * 78)
    print(f"Canary tag: {CANARY_TAG}")
    print(f"hostname.exe SHA256 (8 direct cases): {source_hash}")
    print(f"cmd.exe SHA256 (2 parent-check cases): {parent_hash}")
    print(f"Working directory: {work_dir}\n")

    log = []
    try:
        for name, cfg in LOLBIN_TEST_CASES.items():
            decoy_path = work_dir / name
            print(f"[*] {name}")
            print(f"    QRadar logic: {cfg['qradar_logic']}")

            if cfg["spawn_style"] == "parent_child":
                shutil.copy2(SAFE_PARENT_BINARY, decoy_path)
                decoy_hash = sha256_of(decoy_path)
                if decoy_hash != parent_hash:
                    print(f"    [!] hash mismatch after copy -- ABORTING, nothing executed.\n")
                    log.append({"decoy_name": name, "variant": 0,
                                "timestamp": datetime.now().isoformat(),
                                "command": None, "status": "ABORTED - hash mismatch",
                                "sha256": decoy_hash})
                    continue

                cmd = [str(decoy_path), "/c", SAFE_SOURCE_BINARY]
                print(f"    command: {' '.join(cmd)}")
                print(f"    (this spawns the real, unmodified hostname.exe as an "
                      f"ACTUAL child, so its recorded parent is genuinely '{name}')")
                ts = datetime.now().isoformat()
                status, blocked = run_and_classify(cmd)
                print(f"      -> {status}\n")
                log.append({"decoy_name": name, "variant": 1, "timestamp": ts,
                            "command": " ".join(cmd), "status": status,
                            "sha256": decoy_hash})
                time.sleep(1)
                continue

            # spawn_style == "direct"
            shutil.copy2(SAFE_SOURCE_BINARY, decoy_path)
            decoy_hash = sha256_of(decoy_path)
            if decoy_hash != source_hash:
                print(f"    [!] hash mismatch after copy -- ABORTING, nothing executed.\n")
                log.append({"decoy_name": name, "variant": 0,
                            "timestamp": datetime.now().isoformat(),
                            "command": None, "status": "ABORTED - hash mismatch",
                            "sha256": decoy_hash})
                continue

            if DROP_ARTIFACT_FILES and cfg["artifact"]:
                (work_dir / cfg["artifact"]).write_text(
                    f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\nCanary: {CANARY_TAG}\n"
                )

            blocked_any = False
            for i, args_fn in enumerate(cfg["args_variants"], start=1):
                args = args_fn()
                cmd = [str(decoy_path)] + args
                print(f"    variant {i}: {' '.join(cmd)}")
                ts = datetime.now().isoformat()
                status, blocked = run_and_classify(cmd)
                print(f"      -> {status}")
                log.append({"decoy_name": name, "variant": i, "timestamp": ts,
                            "command": " ".join(cmd), "status": status,
                            "sha256": decoy_hash})
                time.sleep(1)
                if blocked:
                    blocked_any = True
                    break
            print()
    finally:
        cleaned, leftover = verified_cleanup(work_dir)

    print("=" * 78)
    if cleaned:
        print(f"CLEANUP VERIFIED: {work_dir} no longer exists on disk.")
    else:
        print(f"CLEANUP INCOMPLETE -- stuck files:")
        for f in leftover:
            print(f"  STUCK: {f}")
        print(f"Remaining folder: {work_dir}")
    print("=" * 78 + "\n")

    if KEEP_RESULTS_LOG:
        results_file = Path.cwd() / f"lolbin_qradar_results_{CANARY_TAG}.json"
        with open(results_file, "w") as f:
            json.dump({
                "canary_tag": CANARY_TAG,
                "hostname_sha256": source_hash,
                "cmd_sha256": parent_hash,
                "work_dir_cleaned": cleaned,
                "work_dir_leftover_files": leftover,
                "results": log,
            }, f, indent=2)
        print(f"Results saved to: {results_file} (only file this script leaves behind)")
    else:
        print("KEEP_RESULTS_LOG is False -- nothing written to disk.")

    blocked_count = sum(1 for e in log if "BLOCKED" in e["status"])
    print(f"\nSearch QRadar for canary tag: {CANARY_TAG}")
    print(f"{blocked_count} of {len(LOLBIN_TEST_CASES)} were blocked by EDR prevention (WinError 5).")
    print("Everything else exiting cleanly means QRadar is the layer being validated here --")
    print("that's the point of this script. It says nothing about EDR's behavioral coverage,")
    print("since no real technique (injection, memory access, compile, cabinet) ever ran.")


if __name__ == "__main__":
    main()

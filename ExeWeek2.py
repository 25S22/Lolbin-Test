"""
LOLBin Masquerading Tester -- 16 Binaries, for Security Event Log (4688) Pipelines
=====================================================================================
Scope (exactly these 16):
  AddinUtil.exe, Diantz.exe, Control.exe, ilasm.exe, RunExeHelper.exe,
  CustomShellHost.exe, Rundll32.exe, OneDriveStandaloneUpdater.exe,
  Msconfig.exe, Csc.exe, mshta.exe, Dump64.exe, Fsutil.exe, Explorer.exe,
  Diskshadow.exe, Sc.exe

Generates REAL Windows Security Event Log 4688 (Process Creation) records --
genuinely audited by the OS itself, nothing fabricated.

SAFETY MODEL (unchanged throughout this whole exercise):
- 15 of 16 run an unmodified copy of hostname.exe, renamed on disk to the
  LOLBin's filename. hostname.exe prints the local computer name and exits.
  No argument-triggered functionality of any kind exists in it.
- 1 of 16 (CustomShellHost.exe) needs a genuine PARENT-CHILD relationship
  because its QRadar rule checks Parent Process Name. For only this case,
  the renamed binary is a copy of cmd.exe, invoked with exactly one
  hardcoded argument: "/c hostname.exe" -- ordinary process spawning, the
  same operation every installer performs, never anything attacker-controlled.
- Every copy is SHA256-verified against the real system binary immediately
  before execution. Any mismatch aborts that case with nothing run.
- Cleanup is verified (not just attempted) after every run, and any
  leftovers from a prior interrupted run are swept at startup.

CONFIDENCE LEVELS:
- The first 6 use command-line syntax matched directly against QRadar rule
  text you provided. They didn't produce a QRadar offense in your last test
  despite the process genuinely being created (you saw the path in the
  logs) -- that's very likely a rule-configuration issue on QRadar's side
  (disabled rule / response action / field-mapping mismatch), not something
  a different command line fixes. Worth checking the Rules editor directly
  for these 6 before re-running.
- The other 10 use my best recollection of publicly documented LOLBAS
  syntax -- I don't have your QRadar rule text for these yet, so treat
  "low/medium" confidence ones as a starting point, not a guarantee. Send
  me their exact rule conditions and I'll tighten these to match precisely.

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

KEEP_RESULTS_LOG = True
CANARY_TAG = f"PURPLE-TEAM-TEST-{datetime.now().strftime('%Y%m%d%H%M%S')}"

SAFE_SOURCE_BINARY = r"C:\Windows\System32\hostname.exe"   # 14 of 16 cases
SAFE_PARENT_BINARY = r"C:\Windows\System32\cmd.exe"         # 2 parent-check cases
DROP_ARTIFACT_FILES = True

LOLBIN_TEST_CASES = {
    # ---- 6 from the original set that did NOT fire last time ----
    "AddinUtil.exe": {
        "spawn_style": "direct", "confidence": "high match, but did not fire -- check rule config",
        "args_variants": [lambda: ["-pipelineroot:decoy_addins_dir"]], "artifact": None,
        "qradar_logic": "Command contains 'addinutil.exe' AND ('-addinroot' or '-pipelineroot')",
    },
    "Diantz.exe": {
        "spawn_style": "direct", "confidence": "high match, but did not fire -- check rule config",
        "args_variants": [lambda: ["decoy_source.txt", "decoy_archive.cab"]],
        "artifact": "decoy_archive.cab",
        "qradar_logic": "Command contains 'diantz' AND '.cab'",
    },
    "Control.exe": {
        "spawn_style": "direct", "confidence": "high match, but did not fire -- check rule config",
        "args_variants": [lambda: ["decoy_payload.dll"]], "artifact": "decoy_payload.dll",
        "qradar_logic": "Command contains 'control.exe' AND 'dll'",
    },
    "ilasm.exe": {
        "spawn_style": "direct", "confidence": "high match, but did not fire -- check rule config",
        "args_variants": [lambda: ["decoy_payload.il", "/output=decoy_output.exe"]],
        "artifact": "decoy_output.exe",
        "qradar_logic": "Process Name contains 'ilasm.exe' (no command-line condition)",
    },
    "RunExeHelper.exe": {
        "spawn_style": "direct", "confidence": "high match, but did not fire -- check rule config",
        "args_variants": [lambda: ["decoy_target.exe"]], "artifact": None,
        "qradar_logic": "Command contains 'runexehelper'",
    },
    "CustomShellHost.exe": {
        "spawn_style": "parent_child", "confidence": "high match, but did not fire -- check rule config",
        "args_variants": [lambda: []], "artifact": None,
        "qradar_logic": ("Parent Process Name contains 'customshellhost.exe' AND "
                          "spawned Process Name does not contain 'explorer.exe'"),
    },

    # ---- New 10 -- best-recollection LOLBAS syntax, UNVERIFIED against
    #      your actual QRadar rules. Send me those rules to tighten these. ----
    "Rundll32.exe": {
        "spawn_style": "direct", "confidence": "medium (unverified vs your rule)",
        "args_variants": [lambda: ["decoy_payload.dll,DllRegisterServer"]],
        "artifact": "decoy_payload.dll",
        "qradar_logic": "UNKNOWN -- share your rule text",
    },
    "OneDriveStandaloneUpdater.exe": {
        "spawn_style": "direct", "confidence": "low (unverified vs your rule)",
        "args_variants": [lambda: []], "artifact": None,
        "qradar_logic": "UNKNOWN -- share your rule text",
    },
    "Msconfig.exe": {
        "spawn_style": "direct", "confidence": "low (unverified vs your rule)",
        "args_variants": [lambda: []], "artifact": None,
        "qradar_logic": "UNKNOWN -- share your rule text",
    },
    "Csc.exe": {
        "spawn_style": "direct", "confidence": "medium (unverified vs your rule)",
        "args_variants": [lambda: ["/out:decoy_output.exe", "decoy_payload.cs"]],
        "artifact": "decoy_output.exe",
        "qradar_logic": "UNKNOWN -- share your rule text",
    },
    "mshta.exe": {
        "spawn_style": "direct", "confidence": "medium (unverified vs your rule)",
        "args_variants": [lambda: ["decoy_payload.hta"]],
        "artifact": "decoy_payload.hta",
        "qradar_logic": "UNKNOWN -- share your rule text",
    },
    "Dump64.exe": {
        "spawn_style": "direct", "confidence": "low (unverified vs your rule)",
        "args_variants": [lambda: ["-p", str(os.getpid()), "-o", "decoy_dump.dmp"]],
        "artifact": None,
        "qradar_logic": "UNKNOWN -- share your rule text",
    },
    "Fsutil.exe": {
        "spawn_style": "direct", "confidence": "medium (unverified vs your rule)",
        "args_variants": [lambda: ["usn", "deletejournal", "/D", "C:"]],
        "artifact": None,
        "qradar_logic": "UNKNOWN -- share your rule text",
    },
    "Explorer.exe": {
        "spawn_style": "direct", "confidence": "low (unverified vs your rule)",
        "args_variants": [lambda: ["decoy_target.exe"]], "artifact": None,
        "qradar_logic": "UNKNOWN -- share your rule text",
    },
    "Diskshadow.exe": {
        "spawn_style": "direct", "confidence": "medium (unverified vs your rule)",
        "args_variants": [lambda: ["/s", "decoy_script.txt"]],
        "artifact": "decoy_script.txt",
        "qradar_logic": "UNKNOWN -- share your rule text",
    },
    "Sc.exe": {
        "spawn_style": "direct", "confidence": "medium (unverified vs your rule)",
        "args_variants": [lambda: ["create", "decoysvc", "binpath=", r"C:\Test\decoy_payload.exe"]],
        "artifact": None,
        "qradar_logic": "UNKNOWN -- share your rule text",
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
    for p in base.glob("lolbin16_*"):
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
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return f"exited on its own (rc={proc.returncode})", False, proc.pid if hasattr(proc, "pid") else None
    except subprocess.TimeoutExpired:
        return "did not exit within timeout", False, None
    except OSError as e:
        if getattr(e, "winerror", None) == 5:
            return "BLOCKED (WinError 5 Access Denied -- EDR/AV prevention fired)", True, None
        return f"error: {e}", False, None
    except Exception as e:
        return f"error: {e}", False, None


def main():
    if platform.system() != "Windows":
        print("Windows only -- this script copies native Windows binaries "
              "(hostname.exe, cmd.exe). Exiting without doing anything.")
        sys.exit(1)

    if not Path(SAFE_SOURCE_BINARY).exists() or not Path(SAFE_PARENT_BINARY).exists():
        print("Could not find hostname.exe or cmd.exe in System32 -- aborting.")
        sys.exit(1)

    source_hash = sha256_of(SAFE_SOURCE_BINARY)
    parent_hash = sha256_of(SAFE_PARENT_BINARY)

    stray = sweep_stray_runs()
    if stray:
        print(f"Swept {len(stray)} leftover folder(s) from a previous interrupted run.\n")

    work_dir = Path(tempfile.mkdtemp(prefix="lolbin16_"))
    print("=" * 78)
    print(f"LOLBin Tester -- 16 scoped binaries, Security-Event-Log (4688) pipeline")
    print("=" * 78)
    print(f"Canary tag: {CANARY_TAG}")
    print(f"hostname.exe SHA256: {source_hash}")
    print(f"cmd.exe SHA256:      {parent_hash}")
    print(f"Working directory:   {work_dir}\n")

    log = []
    try:
        for name, cfg in LOLBIN_TEST_CASES.items():
            decoy_path = work_dir / name
            print(f"[*] {name}  [{cfg['confidence']}]")
            print(f"    QRadar logic: {cfg['qradar_logic']}")

            if cfg["spawn_style"] == "parent_child":
                shutil.copy2(SAFE_PARENT_BINARY, decoy_path)
                decoy_hash = sha256_of(decoy_path)
                if decoy_hash != parent_hash:
                    print("    [!] hash mismatch -- ABORTED\n")
                    log.append({"decoy_name": name, "variant": 0,
                                "timestamp": datetime.now().isoformat(),
                                "command": None, "status": "ABORTED - hash mismatch"})
                    continue
                cmd = [str(decoy_path), "/c", SAFE_SOURCE_BINARY]
                print(f"    command: {' '.join(cmd)}  (real child spawn, parent = {name})")
                ts = datetime.now().isoformat()
                status, blocked, pid = run_and_classify(cmd)
                print(f"      -> {status}  pid={pid}\n")
                log.append({"decoy_name": name, "variant": 1, "timestamp": ts,
                            "command": " ".join(cmd), "status": status, "pid": pid})
                time.sleep(1)
                continue

            shutil.copy2(SAFE_SOURCE_BINARY, decoy_path)
            decoy_hash = sha256_of(decoy_path)
            if decoy_hash != source_hash:
                print("    [!] hash mismatch -- ABORTED\n")
                log.append({"decoy_name": name, "variant": 0,
                            "timestamp": datetime.now().isoformat(),
                            "command": None, "status": "ABORTED - hash mismatch"})
                continue

            if DROP_ARTIFACT_FILES and cfg["artifact"]:
                (work_dir / cfg["artifact"]).write_text(
                    f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\nCanary: {CANARY_TAG}\n"
                )

            for i, args_fn in enumerate(cfg["args_variants"], start=1):
                cmd = [str(decoy_path)] + args_fn()
                print(f"    variant {i}: {' '.join(cmd)}")
                ts = datetime.now().isoformat()
                status, blocked, pid = run_and_classify(cmd)
                print(f"      -> {status}  pid={pid}")
                log.append({"decoy_name": name, "variant": i, "timestamp": ts,
                            "command": " ".join(cmd), "status": status, "pid": pid})
                time.sleep(1)
                if blocked:
                    break
            print()
    finally:
        cleaned, leftover = verified_cleanup(work_dir)

    print("=" * 78)
    print(f"CLEANUP VERIFIED: {work_dir} gone = {cleaned}")
    if not cleaned:
        for f in leftover:
            print(f"  STUCK: {f}")
    print("=" * 78 + "\n")

    if KEEP_RESULTS_LOG:
        results_file = Path.cwd() / f"lolbin16_results_{CANARY_TAG}.json"
        with open(results_file, "w") as f:
            json.dump({"canary_tag": CANARY_TAG, "results": log,
                       "work_dir_cleaned": cleaned}, f, indent=2)
        print(f"Results saved to: {results_file}")

    blocked_count = sum(1 for e in log if "BLOCKED" in e.get("status", ""))
    print(f"\nSearch QRadar for canary tag: {CANARY_TAG}")
    print(f"{blocked_count} of {len(LOLBIN_TEST_CASES)} blocked by EDR prevention.")
    print("For the 6 flagged 'did not fire -- check rule config' above: the process")
    print("was genuinely created (same as the ones that worked); check those rules'")
    print("enabled/response state in QRadar directly rather than re-running this.")


if __name__ == "__main__":
    main()

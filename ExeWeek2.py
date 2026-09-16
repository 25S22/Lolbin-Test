r"""
LOLBin Masquerading Tester -- 13 Remaining (excludes mshta, Csc, Diskshadow
which already fired -- do not re-touch those).

Scope (exactly these 13):
  AddinUtil.exe, Diantz.exe, Control.exe, ilasm.exe, RunExeHelper.exe,
  CustomShellHost.exe, Rundll32.exe, OneDriveStandaloneUpdater.exe,
  Msconfig.exe, Dump64.exe, Fsutil.exe, Explorer.exe, Sc.exe

KEY FIX vs. the prior version: every referenced artifact now uses the
FULL ABSOLUTE PATH inside the temp work directory, not a bare relative
filename. Many real Sigma-style rules for path-sensitive LOLBins key off
"argument path is NOT in System32/standard locations" -- a relative
filename in the command line doesn't visibly carry that signal; an
absolute Temp path does, and matches the actual suspicious-location
condition those rules are checking for.

CONFIDENCE NOTE: I don't have live access to SigmaHQ's repository in this
session, so these are reconstructed from general knowledge of published
LOLBAS/Sigma patterns, not verified against current rule text. The first
6 below (AddinUtil, Diantz, Control, ilasm, RunExeHelper, CustomShellHost)
still match YOUR literal QRadar rule text from earlier and are UNCHANGED
in logic -- only the artifact paths were made absolute for consistency.
If those 6 still don't fire, that points at QRadar rule config, not this
script. For the other 7, I've applied the absolute-path fix plus, for
Rundll32, an additional well-known public technique (zipfldr.dll,RouteTheCall).

SAFETY MODEL (unchanged throughout this whole exercise):
- 12 of 13 run an unmodified copy of hostname.exe, renamed on disk.
  No argument-triggered functionality of any kind exists in it.
- 1 of 13 (CustomShellHost.exe) uses a renamed copy of cmd.exe, invoked
  with exactly one hardcoded argument ("/c hostname.exe") to produce a
  genuine (not spoofed) parent-child relationship.
- Every copy is SHA256-verified against the real system binary immediately
  before execution. Any mismatch aborts that case with nothing run.
- Cleanup is verified after every run; leftovers from a prior interrupted
  run are swept at startup.

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

SAFE_SOURCE_BINARY = r"C:\Windows\System32\hostname.exe"
SAFE_PARENT_BINARY = r"C:\Windows\System32\cmd.exe"
DROP_ARTIFACT_FILES = True

# args_variants lambdas now take work_dir (Path) so they can build absolute
# paths to the artifacts actually sitting in the temp directory.
LOLBIN_TEST_CASES = {
    "AddinUtil.exe": {
        "spawn_style": "direct", "confidence": "high match to your rule text; check QRadar config if still silent",
        "args_variants": [lambda wd: ["-pipelineroot:" + str(wd / "decoy_addins_dir")]],
        "artifact": None,
        "qradar_logic": "Command contains 'addinutil.exe' AND ('-addinroot' or '-pipelineroot')",
    },
    "Diantz.exe": {
        "spawn_style": "direct", "confidence": "high match to your rule text; check QRadar config if still silent",
        "args_variants": [lambda wd: [str(wd / "decoy_source.txt"), str(wd / "decoy_archive.cab")]],
        "artifact": "decoy_archive.cab",
        "qradar_logic": "Command contains 'diantz' AND '.cab'",
    },
    "Control.exe": {
        "spawn_style": "direct", "confidence": "high match to your rule text; check QRadar config if still silent",
        "args_variants": [lambda wd: [str(wd / "decoy_payload.dll")]],
        "artifact": "decoy_payload.dll",
        "qradar_logic": "Command contains 'control.exe' AND 'dll'",
    },
    "ilasm.exe": {
        "spawn_style": "direct", "confidence": "high match to your rule text; check QRadar config if still silent",
        "args_variants": [lambda wd: [str(wd / "decoy_payload.il"), "/output=" + str(wd / "decoy_output.exe")]],
        "artifact": "decoy_payload.il",
        "qradar_logic": "Process Name contains 'ilasm.exe' (no command-line condition)",
    },
    "RunExeHelper.exe": {
        "spawn_style": "direct", "confidence": "high match to your rule text; check QRadar config if still silent",
        "args_variants": [lambda wd: [str(wd / "decoy_target.exe")]],
        "artifact": None,
        "qradar_logic": "Command contains 'runexehelper'",
    },
    "CustomShellHost.exe": {
        "spawn_style": "parent_child", "confidence": "high match to your rule text; check QRadar config if still silent",
        "args_variants": [lambda wd: []], "artifact": None,
        "qradar_logic": ("Parent Process Name contains 'customshellhost.exe' AND "
                          "spawned Process Name does not contain 'explorer.exe'"),
    },
    "Rundll32.exe": {
        "spawn_style": "direct", "confidence": "medium (Sigma-pattern guess, path now absolute)",
        "args_variants": [
            lambda wd: [str(wd / "decoy_payload.dll") + ",DllRegisterServer"],
            lambda wd: ["zipfldr.dll,RouteTheCall", str(wd / "decoy_command.txt")],
        ],
        "artifact": "decoy_payload.dll",
        "qradar_logic": "UNKNOWN -- guess: suspicious DLL path outside System32",
    },
    "OneDriveStandaloneUpdater.exe": {
        "spawn_style": "direct", "confidence": "low -- real technique is DLL side-loading, not command-line based",
        "args_variants": [lambda wd: []],
        "artifact": "version.dll",   # commonly hijacked DLL name, dropped alongside as a FILE-placement signal
        "qradar_logic": "UNKNOWN -- if rule is command-line based this likely won't match; may need file-creation-based test instead",
    },
    "Msconfig.exe": {
        "spawn_style": "direct", "confidence": "low (likely Process-Name-only, same ambiguity as ilasm)",
        "args_variants": [lambda wd: []], "artifact": None,
        "qradar_logic": "UNKNOWN -- share your rule text",
    },
    "Dump64.exe": {
        "spawn_style": "direct", "confidence": "low (unverified vs your rule)",
        "args_variants": [lambda wd: ["-p", str(os.getpid()), "-o", str(wd / "decoy_dump.dmp")]],
        "artifact": None,
        "qradar_logic": "UNKNOWN -- share your rule text",
    },
    "Fsutil.exe": {
        "spawn_style": "direct", "confidence": "medium (unverified vs your rule)",
        "args_variants": [lambda wd: ["usn", "deletejournal", "/D", "C:"]],
        "artifact": None,
        "qradar_logic": "UNKNOWN -- share your rule text",
    },
    "Explorer.exe": {
        "spawn_style": "direct", "confidence": "low (unverified vs your rule)",
        "args_variants": [lambda wd: [str(wd / "decoy_target.exe")]],
        "artifact": None,
        "qradar_logic": "UNKNOWN -- share your rule text",
    },
    "Sc.exe": {
        "spawn_style": "direct", "confidence": "medium (Sigma-pattern guess, path now absolute)",
        "args_variants": [lambda wd: ["create", "decoysvc", "binpath=", str(wd / "decoy_payload.exe")]],
        "artifact": "decoy_payload.exe",
        "qradar_logic": "UNKNOWN -- guess: suspicious binPath outside System32",
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
    for p in base.glob("lolbin13_*"):
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
        return f"exited on its own (rc={proc.returncode})", False, proc.pid
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
        print("Windows only -- exiting without doing anything.")
        sys.exit(1)

    if not Path(SAFE_SOURCE_BINARY).exists() or not Path(SAFE_PARENT_BINARY).exists():
        print("Could not find hostname.exe or cmd.exe in System32 -- aborting.")
        sys.exit(1)

    source_hash = sha256_of(SAFE_SOURCE_BINARY)
    parent_hash = sha256_of(SAFE_PARENT_BINARY)

    stray = sweep_stray_runs()
    if stray:
        print(f"Swept {len(stray)} leftover folder(s) from a previous interrupted run.\n")

    work_dir = Path(tempfile.mkdtemp(prefix="lolbin13_"))
    print("=" * 78)
    print("LOLBin Tester -- 13 remaining, absolute-path fix applied")
    print("=" * 78)
    print(f"Canary tag: {CANARY_TAG}")
    print(f"Working directory: {work_dir}\n")

    log = []
    try:
        for name, cfg in LOLBIN_TEST_CASES.items():
            decoy_path = work_dir / name
            print(f"[*] {name}  [{cfg['confidence']}]")
            print(f"    QRadar logic: {cfg['qradar_logic']}")

            if cfg["spawn_style"] == "parent_child":
                shutil.copy2(SAFE_PARENT_BINARY, decoy_path)
                if sha256_of(decoy_path) != parent_hash:
                    print("    [!] hash mismatch -- ABORTED\n")
                    continue
                cmd = [str(decoy_path), "/c", SAFE_SOURCE_BINARY]
                print(f"    command: {' '.join(cmd)}")
                ts = datetime.now().isoformat()
                status, blocked, pid = run_and_classify(cmd)
                print(f"      -> {status}  pid={pid}\n")
                log.append({"decoy_name": name, "variant": 1, "timestamp": ts,
                            "command": " ".join(cmd), "status": status, "pid": pid})
                time.sleep(1)
                continue

            shutil.copy2(SAFE_SOURCE_BINARY, decoy_path)
            if sha256_of(decoy_path) != source_hash:
                print("    [!] hash mismatch -- ABORTED\n")
                continue

            if DROP_ARTIFACT_FILES and cfg["artifact"]:
                (work_dir / cfg["artifact"]).write_text(
                    f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\nCanary: {CANARY_TAG}\n"
                )

            for i, args_fn in enumerate(cfg["args_variants"], start=1):
                cmd = [str(decoy_path)] + args_fn(work_dir)
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
        results_file = Path.cwd() / f"lolbin13_results_{CANARY_TAG}.json"
        with open(results_file, "w") as f:
            json.dump({"canary_tag": CANARY_TAG, "results": log,
                       "work_dir_cleaned": cleaned}, f, indent=2)
        print(f"Results saved to: {results_file}")

    print(f"\nSearch QRadar for canary tag: {CANARY_TAG}")
    print("Compare which of these 13 fire now vs before -- that tells us whether")
    print("the absolute-path fix mattered, which is useful signal even for the")
    print("ones still guessed rather than confirmed.")


if __name__ == "__main__":
    main()

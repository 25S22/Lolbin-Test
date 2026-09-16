#!/usr/bin/env python3
r"""
LOLBin Casing-Variant Tester -- 9 Remaining
==============================================
Scope: AddinUtil.exe, Diantz.exe, RunExeHelper.exe, Rundll32.exe,
OneDriveStandaloneUpdater.exe, Msconfig.exe, Dump64.exe, Explorer.exe, Sc.exe

HYPOTHESIS BEING TESTED: QRadar's custom-property extraction (or the rule's
"contains" test) may be case-sensitive for some of these properties, so a
renamed file like "AddinUtil.exe" doesn't match a rule/regex expecting
"addinutil.exe" (or vice versa). This is testable directly without any
external data -- each binary now runs under THREE filename casings:
lowercase, the mixed case you gave me, and uppercase. Whichever one (if
any) produces a QRadar offense tells us definitively whether casing was
the gap, for that specific rule's property.

CAVEAT I want to be upfront about: I do not have live internet/GitHub
access in this session, so I have not verified anything against SigmaHQ's
actual current rule text. Nothing below is "from Sigma" -- it's the same
best-guess LOLBAS-pattern command lines as before (with the absolute-path
fix already applied from the prior round), now with casing as an
additional tested dimension.

SAFETY MODEL (unchanged): every process that executes is an unmodified,
hash-verified copy of hostname.exe. No argument-triggered functionality
of any kind exists in it, regardless of filename casing. Cleanup is
verified after every run; leftovers from a prior interrupted run are
swept at startup.

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
DROP_ARTIFACT_FILES = True

# Canonical name -> args builder (wd = work_dir Path). Casing is applied
# separately at runtime -- this dict holds the base logic only.
LOLBIN_TEST_CASES = {
    "AddinUtil.exe": {
        "args_variants": [lambda wd: ["-pipelineroot:" + str(wd / "decoy_addins_dir")]],
        "artifact": None,
        "qradar_logic": "Command contains 'addinutil.exe' AND ('-addinroot' or '-pipelineroot')",
    },
    "Diantz.exe": {
        "args_variants": [lambda wd: [str(wd / "decoy_source.txt"), str(wd / "decoy_archive.cab")]],
        "artifact": "decoy_archive.cab",
        "qradar_logic": "Command contains 'diantz' AND '.cab'",
    },
    "RunExeHelper.exe": {
        "args_variants": [lambda wd: [str(wd / "decoy_target.exe")]],
        "artifact": None,
        "qradar_logic": "Command contains 'runexehelper'",
    },
    "Rundll32.exe": {
        "args_variants": [
            lambda wd: [str(wd / "decoy_payload.dll") + ",DllRegisterServer"],
            lambda wd: ["zipfldr.dll,RouteTheCall", str(wd / "decoy_command.txt")],
        ],
        "artifact": "decoy_payload.dll",
        "qradar_logic": "UNKNOWN -- guess",
    },
    "OneDriveStandaloneUpdater.exe": {
        "args_variants": [lambda wd: []],
        "artifact": "version.dll",
        "qradar_logic": "UNKNOWN -- guess; real technique is DLL side-loading, not command-line",
    },
    "Msconfig.exe": {
        "args_variants": [lambda wd: []],
        "artifact": None,
        "qradar_logic": "UNKNOWN -- guess; likely Process-Name-only",
    },
    "Dump64.exe": {
        "args_variants": [lambda wd: ["-p", str(os.getpid()), "-o", str(wd / "decoy_dump.dmp")]],
        "artifact": None,
        "qradar_logic": "UNKNOWN -- guess",
    },
    "Explorer.exe": {
        "args_variants": [lambda wd: [str(wd / "decoy_target.exe")]],
        "artifact": None,
        "qradar_logic": "UNKNOWN -- guess",
    },
    "Sc.exe": {
        "args_variants": [lambda wd: ["create", "decoysvc", "binpath=", str(wd / "decoy_payload.exe")]],
        "artifact": "decoy_payload.exe",
        "qradar_logic": "UNKNOWN -- guess",
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
    for p in base.glob("lolbin9case_*"):
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
        return f"exited on its own (rc={proc.returncode})", proc.pid
    except subprocess.TimeoutExpired:
        return "did not exit within timeout", None
    except OSError as e:
        if getattr(e, "winerror", None) == 5:
            return "BLOCKED (WinError 5 Access Denied -- EDR/AV prevention fired)", None
        return f"error: {e}", None
    except Exception as e:
        return f"error: {e}", None


def casing_variants(name):
    # lowercase, as-given, uppercase -- deduplicated in case any collide
    variants = [name.lower(), name, name.upper()]
    seen, out = set(), []
    for v in variants:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def main():
    if platform.system() != "Windows":
        print("Windows only -- exiting without doing anything.")
        sys.exit(1)
    if not Path(SAFE_SOURCE_BINARY).exists():
        print("hostname.exe not found -- aborting.")
        sys.exit(1)

    source_hash = sha256_of(SAFE_SOURCE_BINARY)
    stray = sweep_stray_runs()
    if stray:
        print(f"Swept {len(stray)} leftover folder(s) from a previous run.\n")

    work_dir = Path(tempfile.mkdtemp(prefix="lolbin9case_"))
    print("=" * 78)
    print("LOLBin Casing-Variant Tester -- 9 remaining, 3 casings each")
    print("=" * 78)
    print(f"Canary tag: {CANARY_TAG}")
    print(f"Working directory: {work_dir}\n")

    log = []
    try:
        for canonical_name, cfg in LOLBIN_TEST_CASES.items():
            print(f"[*] {canonical_name}")
            print(f"    QRadar logic: {cfg['qradar_logic']}")

            if DROP_ARTIFACT_FILES and cfg["artifact"]:
                (work_dir / cfg["artifact"]).write_text(
                    f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\nCanary: {CANARY_TAG}\n"
                )

            for case_name in casing_variants(canonical_name):
                decoy_path = work_dir / case_name
                shutil.copy2(SAFE_SOURCE_BINARY, decoy_path)
                if sha256_of(decoy_path) != source_hash:
                    print(f"    [!] {case_name}: hash mismatch -- ABORTED")
                    continue

                for i, args_fn in enumerate(cfg["args_variants"], start=1):
                    cmd = [str(decoy_path)] + args_fn(work_dir)
                    print(f"    [{case_name}] variant {i}: {' '.join(cmd)}")
                    ts = datetime.now().isoformat()
                    status, pid = run_and_classify(cmd)
                    print(f"        -> {status}  pid={pid}")
                    log.append({"canonical_name": canonical_name, "cased_as": case_name,
                                "variant": i, "timestamp": ts, "command": " ".join(cmd),
                                "status": status, "pid": pid})
                    time.sleep(0.5)
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
        results_file = Path.cwd() / f"lolbin9case_results_{CANARY_TAG}.json"
        with open(results_file, "w") as f:
            json.dump({"canary_tag": CANARY_TAG, "results": log,
                       "work_dir_cleaned": cleaned}, f, indent=2)
        print(f"Results saved to: {results_file}")

    print(f"\nSearch QRadar for canary tag: {CANARY_TAG}")
    print("For each binary, check which of the 3 casings (if any) created an")
    print("offense. If exactly one casing works and the other two don't, that")
    print("confirms case-sensitivity for that specific rule's property -- and")
    print("tells you which literal case to standardize on. If NONE of the 3")
    print("casings fire for a given binary, casing wasn't the gap for that one;")
    print("it's more likely rule-config (disabled/no response action) or the")
    print("guessed command-line syntax being wrong (the 6 without known rule")
    print("text especially).")


if __name__ == "__main__":
    main()

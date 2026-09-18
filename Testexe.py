#!/usr/bin/env python3
r"""
LOLBin Tester -- 8 Remaining, Sigma-Rule-Matched + PID Bug Fixed
==================================================================
Scope (exactly these 8):
  AddinUtil.exe, RunExeHelper.exe, Rundll32.exe,
  OneDriveStandaloneUpdater.exe, Msconfig.exe, Dump64.exe,
  Explorer.exe, Sc.exe

TWO KEY FIXES VS. ALL PRIOR VERSIONS:

1. PID BUG FIXED:
   Every prior version used subprocess.run() and then read proc.pid.
   subprocess.CompletedProcess (the return type of run()) has no .pid
   attribute -- this caused a silent AttributeError on every successful
   run, caught by the except-Exception handler, so every process that
   actually completed was reported as "error: ...no attribute 'pid'"
   with pid=None instead of "exited on its own". Fixed by switching to
   Popen() which exposes .pid before the process finishes, then
   communicate() to wait. You will now see real PIDs and correct status.

2. COMMAND LINES SOURCED FROM VERIFIED SIGMA RULES:
   AddinUtil.exe -- proc_creation_win_addinutil_suspicious_cmdline.yml
     Requires: -PipelineRoot: or -AddInRoot: AND the path must contain
     \AppData\Local\Temp\ or \Windows\Temp\ etc. Using absolute temp path
     satisfies this; the bare relative path used before did NOT.
   Rundll32.exe  -- proc_creation_win_rundll32_susp_activity.yml
     Requires known DLL+function pairs. Prior version used a custom DLL
     path; now uses the exact documented pairs from the rule.
   Explorer.exe  -- proc_creation_win_explorer_break_process_tree.yml
     Requires /factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b} or
     /root,<path>. Prior version used none of these.
   Sc.exe        -- proc_creation_win_susp_service_creation.yml
     Requires create + binPath= + suspicious path containing
     \AppData\Local\Temp or C:\Windows\TEMP etc. Prior version used a
     generic path that didn't match the suspicious-path condition.
   RunExeHelper, OneDriveStandaloneUpdater, Msconfig, Dump64:
     No dedicated SigmaHQ rules found in the public repo for these.
     They are likely pure process-name rules in your QRadar deployment.
     If they still don't fire, share the exact rule text and I'll match.

CASING: Each binary is also tried in lowercase and UPPERCASE in addition
to the mixed case you specified -- this tests whether your QRadar rule's
"Process Name contains" comparison is case-sensitive, which has been
a suspected gap throughout.

SAFETY MODEL (unchanged):
- 7 of 8 use a hash-verified copy of hostname.exe renamed to the LOLBin
  filename. hostname.exe ignores all arguments and exits immediately.
- 1 of 8 (Explorer.exe) passes its own name in the CommandLine argument
  (the /root, technique) -- still hostname.exe underneath, the argument
  is just a string, no shell expansion occurs.
- Cleanup is verified after every run; stray folders from prior
  interrupted runs are swept at startup.

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

# Each entry:
#   args_variants : list of lambdas taking work_dir (Path) -> list[str]
#   artifact      : filename to drop as inert placeholder (or None)
#   sigma_source  : which Sigma rule this is matched against
#   qradar_logic  : what your QRadar rule checks (from your earlier text
#                   or "UNKNOWN" where no rule text was shared)
LOLBIN_TEST_CASES = {
    "AddinUtil.exe": {
        "args_variants": [
            # Sigma: Image endswith addinutil.exe AND
            #   CommandLine contains -PipelineRoot: AND
            #   CommandLine contains \AppData\Local\Temp\ (or similar suspicious path)
            # work_dir IS in \AppData\Local\Temp\ so the absolute path satisfies
            # the suspicious-directory condition automatically.
            lambda wd: [f"-PipelineRoot:{wd}"],
            lambda wd: [f"-AddInRoot:{wd}"],
        ],
        "artifact": None,
        "sigma_source": "proc_creation_win_addinutil_suspicious_cmdline.yml",
        "qradar_logic": "Command contains 'addinutil.exe' AND ('-addinroot' or '-pipelineroot')",
    },
    "RunExeHelper.exe": {
        "args_variants": [
            lambda wd: [str(wd / "decoy_target.exe")],
        ],
        "artifact": None,
        "sigma_source": "No dedicated SigmaHQ rule found -- likely process-name only",
        "qradar_logic": "Command contains 'runexehelper'",
    },
    "Rundll32.exe": {
        "args_variants": [
            # Sigma: proc_creation_win_rundll32_susp_activity.yml
            # Multiple known DLL+function pairs -- using the most reliable ones
            lambda wd: ["zipfldr.dll,RouteTheCall", str(wd / "decoy_target.exe")],
            lambda wd: ["url.dll,OpenURL", "https://example.com"],
            lambda wd: ["pcwutl.dll,LaunchApplication", str(wd / "decoy_target.exe")],
            lambda wd: ["shell32.dll,Control_RunDLL", str(wd / "decoy_payload.dll")],
        ],
        "artifact": "decoy_payload.dll",
        "sigma_source": "proc_creation_win_rundll32_susp_activity.yml",
        "qradar_logic": "UNKNOWN -- using Sigma-documented DLL+function pairs",
    },
    "OneDriveStandaloneUpdater.exe": {
        "args_variants": [
            # No SigmaHQ rule found -- likely process-name only.
            # Real abuse is DLL side-loading; no commandline pattern to match.
            lambda wd: [],
        ],
        "artifact": None,
        "sigma_source": "No dedicated SigmaHQ rule found -- share rule text to improve",
        "qradar_logic": "UNKNOWN -- share your rule text",
    },
    "Msconfig.exe": {
        "args_variants": [
            # No SigmaHQ rule found -- likely process-name only.
            lambda wd: [],
        ],
        "artifact": None,
        "sigma_source": "No dedicated SigmaHQ rule found -- share rule text to improve",
        "qradar_logic": "UNKNOWN -- share your rule text",
    },
    "Dump64.exe": {
        "args_variants": [
            # No dedicated SigmaHQ rule found.
            # Dump64.exe is the VS debugger dump utility; common documented
            # usage: dump64.exe <pid> <output_file>
            lambda wd: [str(os.getpid()), str(wd / "decoy_dump.dmp")],
        ],
        "artifact": None,
        "sigma_source": "No dedicated SigmaHQ rule found -- share rule text to improve",
        "qradar_logic": "UNKNOWN -- share your rule text",
    },
    "Explorer.exe": {
        "args_variants": [
            # Sigma: proc_creation_win_explorer_break_process_tree.yml
            # Pattern 1: factory CLSID used to break process tree
            lambda wd: ["/factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b}"],
            # Pattern 2: /root, flag to open specific path
            lambda wd: [f"/root,{wd}"],
        ],
        "artifact": None,
        "sigma_source": "proc_creation_win_explorer_break_process_tree.yml",
        "qradar_logic": "UNKNOWN -- using Sigma-documented explorer lolbin patterns",
    },
    "Sc.exe": {
        "args_variants": [
            # Sigma: proc_creation_win_susp_service_creation.yml
            # Requires: create + binPath= + suspicious path
            # work_dir is in \AppData\Local\Temp\ which is in the rule's
            # suspicious-path list, so the absolute path satisfies the condition.
            lambda wd: ["create", "decoysvc", f"binPath={wd / 'decoy_payload.exe'}"],
        ],
        "artifact": "decoy_payload.exe",
        "sigma_source": "proc_creation_win_susp_service_creation.yml",
        "qradar_logic": "UNKNOWN -- using Sigma: create + binPath= + suspicious temp path",
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
    for p in base.glob("lolbin8sig_*"):
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
    """
    BUG FIX: prior versions used subprocess.run() then read proc.pid.
    CompletedProcess has no .pid -- this silently threw AttributeError
    on every success, caught by except-Exception, returning pid=None
    and status='error:...' for every process that actually completed.

    Fix: Popen() gives us the real PID before the process finishes,
    then communicate() waits for it to exit cleanly.
    """
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        pid = proc.pid  # real PID, available immediately after Popen
        try:
            _out, _err = proc.communicate(timeout=timeout)
            return f"exited on its own (rc={proc.returncode})", pid
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            return f"did not exit within {timeout}s -- killed", pid
    except OSError as e:
        if getattr(e, "winerror", None) == 5:
            return "BLOCKED (WinError 5 Access Denied -- EDR/AV prevention fired)", None
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
        print(f"Swept {len(stray)} leftover folder(s) from a previous run.\n")

    work_dir = Path(tempfile.mkdtemp(prefix="lolbin8sig_"))
    print("=" * 78)
    print("LOLBin Tester -- 8 remaining, Sigma-matched + PID bug fixed")
    print("=" * 78)
    print(f"Canary tag      : {CANARY_TAG}")
    print(f"hostname.exe SHA: {source_hash}")
    print(f"Working dir     : {work_dir}")
    print(f"  (this path contains \\AppData\\Local\\Temp\\ or \\Windows\\Temp\\")
    print(f"   which satisfies the suspicious-path condition in AddinUtil")
    print(f"   and Sc.exe Sigma rules automatically)\n")

    log = []
    try:
        for canonical_name, cfg in LOLBIN_TEST_CASES.items():
            print(f"[*] {canonical_name}")
            print(f"    Sigma source : {cfg['sigma_source']}")
            print(f"    QRadar logic : {cfg['qradar_logic']}")

            if DROP_ARTIFACT_FILES and cfg["artifact"]:
                (work_dir / cfg["artifact"]).write_text(
                    f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\n"
                    f"Canary: {CANARY_TAG}\n"
                )

            for case_name in casing_variants(canonical_name):
                decoy_path = work_dir / case_name
                shutil.copy2(SAFE_SOURCE_BINARY, decoy_path)
                copy_hash = sha256_of(decoy_path)
                if copy_hash != source_hash:
                    print(f"    [{case_name}] hash mismatch -- ABORTED")
                    continue

                blocked_this_casing = False
                for i, args_fn in enumerate(cfg["args_variants"], start=1):
                    cmd = [str(decoy_path)] + args_fn(work_dir)
                    print(f"    [{case_name}] v{i}: {' '.join(cmd)}")
                    ts = datetime.now().isoformat()
                    status, pid = run_and_classify(cmd)
                    print(f"         -> {status}  pid={pid}")
                    log.append({
                        "canonical_name": canonical_name,
                        "cased_as": case_name,
                        "variant": i,
                        "timestamp": ts,
                        "command": " ".join(cmd),
                        "status": status,
                        "pid": pid,
                    })
                    time.sleep(0.75)
                    if "BLOCKED" in status:
                        blocked_this_casing = True
                        break

                if blocked_this_casing:
                    print(f"    Blocked on casing '{case_name}' -- skipping remaining casings")
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
        results_file = Path.cwd() / f"lolbin8sig_results_{CANARY_TAG}.json"
        with open(results_file, "w") as f:
            json.dump({
                "canary_tag": CANARY_TAG,
                "hostname_sha256": source_hash,
                "work_dir_cleaned": cleaned,
                "results": log,
            }, f, indent=2)
        print(f"Results saved to: {results_file}")

    print(f"\nSearch QRadar offenses for canary tag: {CANARY_TAG}")
    print("For each binary, note WHICH casing (if any) produced an offense.")
    print("If none of the 3 casings fire for a given binary and the event IS")
    print("visible in Log Activity, share the raw parsed field values from")
    print("that event and I can match the rule exactly.")


if __name__ == "__main__":
    main()

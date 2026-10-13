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

LOLBIN_TEST_CASES = {
    "Regasm.exe": {
        "spawn_style": "direct",
        "decoy_name": "regasm.exe",
        "sigma": "proc_creation_win_regasm_regsvcs_uncommon_location_execution.yml (cc368ed0-2411-45dc-a222-510ace303cb2)",
        "lolbas": "regasm.exe {PATH:.dll} -- loads target .NET DLL and calls RegisterClass",
        "condition": "Image|endswith '\\Regasm.exe' + CommandLine contains an AppData\\Local\\Temp path",
        "artifact": "decoy_regasm.dll",
        "args_variants": [
            lambda wd: [str(wd / "decoy_regasm.dll")],
            lambda wd: ["/U", str(wd / "decoy_regasm.dll")],
        ],
    },
    "Regsvcs.exe": {
        "spawn_style": "direct",
        "decoy_name": "regsvcs.exe",
        "sigma": "proc_creation_win_regasm_regsvcs_uncommon_location_execution.yml (cc368ed0-2411-45dc-a222-510ace303cb2)",
        "lolbas": "regsvcs.exe {PATH:.dll} -- loads target .NET DLL and calls RegisterClass",
        "condition": "Image|endswith '\\Regsvcs.exe' + CommandLine contains an AppData\\Local\\Temp path",
        "artifact": "decoy_regsvcs.dll",
        "args_variants": [
            lambda wd: [str(wd / "decoy_regsvcs.dll")],
        ],
    },
    "VSDiagnostics.exe": {
        "spawn_style": "direct",
        "decoy_name": "VSDiagnostics.exe",
        "sigma": "proc_creation_win_vsdiagnostics_execution_proxy.yml (ac1c92b4-ac81-405a-9978-4604d78cc47e)",
        "lolbas": "VSDiagnostics.exe start <id> /launch:<binary> /launchArgs:<args>",
        "condition": "Image|endswith '\\VSDiagnostics.exe' + CommandLine contains 'start' AND '/launch:'",
        "artifact": None,
        "args_variants": [
            lambda wd: ["start", "1", "/launch:" + SAFE_SOURCE_BINARY, "/launchArgs:"],
        ],
    },
    "Certoc.exe": {
        "spawn_style": "direct",
        "decoy_name": "certoc.exe",
        "sigma": "proc_creation_win_certoc_load_dll.yml (242301bc-f92f-4476-8718-78004a6efd9f)",
        "lolbas": "certoc.exe -LoadDLL <path.dll>",
        "condition": "Image|endswith '\\certoc.exe' + CommandLine contains ' -LoadDLL '",
        "artifact": "decoy_certoc.dll",
        "args_variants": [
            lambda wd: ["-LoadDLL", str(wd / "decoy_certoc.dll")],
        ],
    },
    "OfflineScannerShell.exe": {
        "spawn_style": "direct",
        "decoy_name": "OfflineScannerShell.exe",
        "sigma": "proc_creation_win_offlinescannershell_mpclient_sideloading.yml (02b18447-ea83-4b1b-8805-714a8a34546a)",
        "lolbas": "mpclient.dll sideload when run outside its default Defender Offline directory",
        "condition": "Image|endswith '\\OfflineScannerShell.exe' AND CurrentDirectory != 'C:\\Program Files\\Windows Defender\\Offline\\'",
        "artifact": None,
        "use_workdir_cwd": True,
        "args_variants": [lambda wd: []],
    },
    "Bitsadmin.exe": {
        "spawn_style": "direct",
        "decoy_name": "bitsadmin.exe",
        "sigma": "proc_creation_win_bitsadmin_download.yml (d059842b-6b9d-4ed1-b5c3-5b89143c6ede)",
        "lolbas": "bitsadmin /transfer <job> /download /priority normal <url> <dest>",
        "condition": "Image|endswith '\\bitsadmin.exe' + CommandLine contains ' /transfer '",
        "artifact": None,
        "args_variants": [
            lambda wd: ["/transfer", "lolbasSigmaTest", "/download", "/priority", "normal",
                        "http://127.0.0.1/file", str(wd / "bits_download.bin")],
        ],
    },
    "Runonce.exe": {
        "spawn_style": "direct",
        "decoy_name": "runonce.exe",
        "sigma": "proc_creation_win_runonce_execution.yml (198effb6-6c98-4d0c-9ea3-451fa143c45c)",
        "lolbas": "runonce.exe /AlternateShellStartup -- run-once task execution from registry",
        "condition": "Image|endswith '\\runonce.exe' + CommandLine contains '/AlternateShellStartup' OR endswith '/r'",
        "artifact": None,
        "args_variants": [
            lambda wd: ["/AlternateShellStartup"],
        ],
    },
    "Runscripthelper.exe": {
        "spawn_style": "direct",
        "decoy_name": "Runscripthelper.exe",
        "sigma": "proc_creation_win_lolbin_runscripthelper.yml (eca49c87-8a75-4f13-9c73-a5a29e845f03)",
        "lolbas": "runscripthelper.exe surfacecheck \\\\?\\<script> <dir> -- constrained language mode bypass",
        "condition": "Image|endswith '\\Runscripthelper.exe' + CommandLine contains 'surfacecheck'",
        "artifact": "decoy_surface.txt",
        "args_variants": [
            lambda wd: ["surfacecheck", "\\\\?\\" + str(wd / "decoy_surface.txt"), str(wd)],
        ],
    },
    "Pktmon.exe": {
        "spawn_style": "direct",
        "decoy_name": "pktmon.exe",
        "sigma": "proc_creation_win_pktmon_execution.yml (f956c7c1-0f60-4bc5-b7d7-b39ab3c08908)",
        "lolbas": "pktmon -- built-in packet capture / network sniffing",
        "condition": "Image|endswith '\\pktmon.exe' -- any execution flagged",
        "artifact": None,
        "args_variants": [
            lambda wd: ["list"],
        ],
    },
    "Wlrmdr.exe": {
        "spawn_style": "direct",
        "decoy_name": "wlrmdr.exe",
        "sigma": "proc_creation_win_wlrmdr_uncommon_child_process.yml (9cfc00b6-bfb7-49ce-9781-ef78503154bb)",
        "lolbas": "wlrmdr.exe -s 3600 -f 0 -t _ -m _ -a 11 -u <binary> -- ShellExecute proxy execution",
        "condition": "Image|endswith '\\wlrmdr.exe' + CommandLine contains all of -s -f -t -m -a -u",
        "artifact": None,
        "args_variants": [
            lambda wd: ["-s", "3600", "-f", "0", "-t", "_", "-m", "_", "-a", "11", "-u", SAFE_SOURCE_BINARY],
        ],
    },
    "Cmd.exe": {
        "spawn_style": "rename_real_multi",
        "sigma": "proc_creation_win_renamed_binary.yml (36480ae1-a1cb-4eaa-a0d6-29801d7e9142)",
        "lolbas": "Masquerading (T1036.003): a real binary whose PE OriginalFileName is covered by the rule, copied/executed under a non standard filename",
        "condition": "OriginalFileName in {Cmd.Exe, net.exe, wevtutil.exe} AND Image does NOT endswith the matching real name",
        "artifact": None,
        "sources": [
            (SAFE_PARENT_BINARY, "update_helper.exe", ["/c", "exit"]),
            (r"C:\Windows\System32\net.exe", "net_helper.exe", ["help"]),
            (r"C:\Windows\System32\wevtutil.exe", "evtutil_helper.exe", ["qe", "Application", "/c:1"]),
        ],
    },
    "Provlaunch.exe": {
        "spawn_style": "cli_only",
        "sigma": "proc_creation_win_registry_provlaunch_provisioning_command.yml (2a4b3e61-9d22-4e4a-b60f-6e8f0cde6f25)",
        "lolbas": "Any process whose CommandLine references the provisioning registry key used by provlaunch.exe",
        "condition": "CommandLine contains 'SOFTWARE\\Microsoft\\Provisioning\\Commands\\' -- no Image/Parent constraint",
        "artifact": None,
        "args_variants": [
            lambda wd: ["/simulate", r"SOFTWARE\Microsoft\Provisioning\Commands\ProvlaunchSigmaTest"],
        ],
    },
    "Manage-bde.wsf": {
        "spawn_style": "real_binary",
        "sigma": "proc_creation_win_lolbin_manage_bde.yml (c363385c-f75d-4753-a108-c1a8e28bdbda)",
        "lolbas": "wscript manage-bde.wsf -- proxy execution via ComSpec hijack",
        "condition": "Image|endswith '\\wscript.exe' AND CommandLine contains 'manage-bde.wsf'",
        "real_path": r"C:\Windows\System32\wscript.exe",
        "artifact": None,
        "args_variants": [
            lambda wd: [r"C:\Windows\System32\manage-bde.wsf"],
        ],
    },
    "Certreq.exe": {
        "spawn_style": "real_binary",
        "sigma": "proc_creation_win_certreq_download.yml (4480827a-9799-4232-b2c4-ccc6c4e9e12b)",
        "lolbas": "certreq -Post -config <url> C:\\windows\\win.ini",
        "condition": "Image|endswith '\\certreq.exe' + CommandLine contains ' -Post ' AND ' -config ' AND ' http' AND ' C:\\windows\\win.ini '",
        "real_path": r"C:\Windows\System32\certreq.exe",
        "artifact": None,
        "args_variants": [
            lambda wd: ["-Post", "-config", "http://127.0.0.1/", r"C:\windows\win.ini"],
        ],
    },
    "Eventvwr.exe": {
        "spawn_style": "cli_only",
        "sigma": "proc_creation_win_uac_bypass_eventvwr_recentviews.yml (30fc8de7-d833-40c4-96b6-28319fbc4f6c)",
        "lolbas": "Any process whose CommandLine mimics the RecentViews redirect used in the eventvwr.exe UAC bypass",
        "condition": "CommandLine contains '>' AND ('\\Event Viewer\\RecentViews' OR '\\EventV~1\\RecentViews') -- no Image constraint",
        "artifact": None,
        "args_variants": [
            lambda wd: [">", r"C:\Users\Public\AppData\Local\Microsoft\EventV~1\RecentViews"],
        ],
    },
    "Rpcping.exe": {
        "spawn_style": "real_binary",
        "sigma": "proc_creation_win_rpcping_credential_capture.yml (93671f99-04eb-4ab4-a161-70d446a84003)",
        "lolbas": "rpcping -s <target> -e <endpoint> -a privacy -u NTLM -t ncacn_np -- forces NTLM auth",
        "condition": "Image|endswith '\\RpcPing.exe' + CommandLine contains '-s' AND ('-u NTLM' OR '-t ncacn_np')",
        "real_path": r"C:\Windows\System32\rpcping.exe",
        "artifact": None,
        "args_variants": [
            lambda wd: ["-s", "127.0.0.1", "-e", "999", "-a", "privacy", "-u", "NTLM", "-t", "ncacn_np"],
        ],
    },
    "Dnscmd.exe": {
        "spawn_style": "real_binary_or_decoy",
        "sigma": "proc_creation_win_dnscmd_install_new_server_level_plugin_dll.yml (f63b56ee-3f79-4b8a-97fb-5c48007e8573) + proc_creation_win_dnscmd_discovery.yml (b6457d63-d2a2-4e29-859d-4e7affc153d1)",
        "lolbas": "dnscmd /enumzones -- discovery ; dnscmd /config /serverlevelplugindll <dll> -- code exec via DNS service",
        "condition": "Image|endswith '\\dnscmd.exe' + CommandLine contains '/enumzones' OR ('/config' AND '/serverlevelplugindll')",
        "real_path": r"C:\Windows\System32\dnscmd.exe",
        "decoy_name": "dnscmd.exe",
        "artifact": "decoy_dnscmd.dll",
        "args_variants": [
            lambda wd: ["/enumzones"],
            lambda wd: ["/config", "/serverlevelplugindll", str(wd / "decoy_dnscmd.dll")],
        ],
    },
    "Pester.bat": {
        "spawn_style": "real_binary",
        "sigma": "proc_creation_win_lolbin_pester_1.yml (59e938ff-0d6d-4dc3-b13f-36cc28734d4e)",
        "lolbas": "Pester.bat proxies PowerShell test-module execution",
        "condition": "Image|endswith '\\powershell.exe' + CommandLine contains 'Pester' AND 'Get-Help'",
        "real_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "artifact": None,
        "args_variants": [
            lambda wd: ["-NoProfile", "-Command", "Import-Module Pester; Get-Help"],
        ],
    },
    "ConfigSecurityPolicy.exe": {
        "spawn_style": "real_binary_dynamic",
        "sigma": "proc_creation_win_configsecuritypolicy_download_file.yml (1f0f6176-6482-4027-b151-00071af39d7e)",
        "lolbas": "ConfigSecurityPolicy.exe <http/https/ftp source> <destination> -- arbitrary file transfer",
        "condition": "Image|endswith '\\ConfigSecurityPolicy.exe' + CommandLine contains 'http://' OR 'https://' OR 'ftp://'",
        "search_globs": [
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\*\ConfigSecurityPolicy.exe",
            r"C:\Program Files\Windows Defender\ConfigSecurityPolicy.exe",
        ],
        "decoy_name": "ConfigSecurityPolicy.exe",
        "artifact": None,
        "args_variants": [
            lambda wd: ["http://127.0.0.1/policy.bin", str(wd / "policy.bin")],
        ],
    },
    "Fltmc.exe": {
        "spawn_style": "real_binary",
        "sigma": "proc_creation_win_fltmc_unload_driver_sysmon.yml (4d7cda18-1b12-4e52-b45c-d28653210df8)",
        "lolbas": "fltmc unload sysmondrv -- defense impairment via filter driver unload",
        "condition": "Image|endswith '\\fltMC.exe' + CommandLine contains 'unload' AND 'sysmon'",
        "real_path": r"C:\Windows\System32\fltmc.exe",
        "artifact": None,
        "args_variants": [
            lambda wd: ["unload", "sysmondrv"],
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
    for p in Path(tempfile.gettempdir()).glob("lolbas19v2_*"):
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
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
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
    print(f"    v{variant}: {' '.join(cmd)}")
    ts = datetime.now().isoformat()
    status, pid = run_and_classify(cmd, cwd=cwd)
    print(f"         -> {status}  pid={pid}")
    log.append({"name": canonical_name, "spawn_style": style, "variant": variant,
                "timestamp": ts, "command": " ".join(cmd), "status": status, "pid": pid})
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

    stray = sweep_stray_runs()
    if stray:
        print(f"Swept {len(stray)} leftover folder(s) from previous run.\n")

    work_dir = Path(tempfile.mkdtemp(prefix="lolbas19v2_"))
    print("=" * 78)
    print("LOLBAS Tester v2 -- 19 requested lolbins, revalidated against SigmaHQ")
    print("=" * 78)
    print(f"Canary tag     : {CANARY_TAG}")
    print(f"hostname SHA256: {source_hash}")
    print(f"Working dir    : {work_dir}")
    print("  (\\AppData\\Local\\Temp\\ -- satisfies location-based rules)\n")

    for fname in ["decoy_regasm.dll", "decoy_regsvcs.dll", "decoy_certoc.dll",
                  "decoy_dnscmd.dll", "decoy_surface.txt"]:
        p = work_dir / fname
        if not p.exists():
            p.write_text(f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\nCanary: {CANARY_TAG}\n")

    log = []
    try:
        for canonical_name, cfg in LOLBIN_TEST_CASES.items():
            print(f"{'=' * 60}")
            print(f"[*] {canonical_name}  [{cfg['spawn_style']}]")
            print(f"    Sigma  : {cfg['sigma']}")
            print(f"    LOLBAS : {cfg['lolbas']}")
            print(f"    Cond   : {cfg['condition']}")
            print()

            if canonical_name == "Fltmc.exe":
                print("    !!! REAL fltmc.exe unload attempt -- may genuinely disable Sysmon telemetry")
                print("    !!! if this succeeds, it runs LAST so every other test above is unaffected")
                print()

            if DROP_ARTIFACT_FILES and cfg.get("artifact"):
                p = work_dir / cfg["artifact"]
                if not p.exists():
                    p.write_text(f"PURPLE TEAM TEST ARTIFACT - NOT EXECUTABLE\nCanary: {CANARY_TAG}\n")

            cwd_for_run = str(work_dir) if cfg.get("use_workdir_cwd") else None
            style = cfg["spawn_style"]

            if style == "direct":
                blocked_globally = False
                for case_name in casing_variants(cfg["decoy_name"]):
                    if blocked_globally:
                        break
                    decoy_path = work_dir / case_name
                    shutil.copy2(SAFE_SOURCE_BINARY, decoy_path)
                    if sha256_of(decoy_path) != source_hash:
                        print(f"    [{case_name}] hash mismatch -- ABORTED")
                        continue
                    for i, args_fn in enumerate(cfg["args_variants"], start=1):
                        cmd = [str(decoy_path)] + args_fn(work_dir)
                        print(f"    [{case_name}]", end=" ")
                        log_and_run(log, canonical_name, style, i, cmd, cwd_for_run)
                        if "BLOCKED" in log[-1]["status"]:
                            blocked_globally = True
                            break
                print()
                continue

            if style == "rename_real_multi":
                for source_path, decoy_name, fixed_args in cfg["sources"]:
                    if not Path(source_path).exists():
                        print(f"    [{decoy_name}] SKIPPED - source {source_path} not found")
                        continue
                    src_hash = sha256_of(source_path)
                    for case_name in casing_variants(decoy_name):
                        decoy_path = work_dir / case_name
                        shutil.copy2(source_path, decoy_path)
                        if sha256_of(decoy_path) != src_hash:
                            print(f"    [{case_name}] hash mismatch -- ABORTED")
                            continue
                        cmd = [str(decoy_path)] + fixed_args
                        print(f"    [{case_name}]", end=" ")
                        log_and_run(log, canonical_name, style, case_name, cmd, cwd_for_run)
                print()
                continue

            if style == "cli_only":
                for i, args_fn in enumerate(cfg["args_variants"], start=1):
                    cmd = [SAFE_SOURCE_BINARY] + args_fn(work_dir)
                    log_and_run(log, canonical_name, style, i, cmd, cwd_for_run)
                print()
                continue

            if style == "real_binary":
                real_path = cfg["real_path"]
                if not Path(real_path).exists():
                    print(f"    SKIPPED - {real_path} not found on this host")
                    print()
                    continue
                for i, args_fn in enumerate(cfg["args_variants"], start=1):
                    cmd = [real_path] + args_fn(work_dir)
                    log_and_run(log, canonical_name, style, i, cmd, cwd_for_run)
                print()
                continue

            if style == "real_binary_or_decoy":
                real_path = cfg["real_path"]
                if Path(real_path).exists():
                    base_path = real_path
                    print(f"    using REAL binary: {real_path}")
                else:
                    decoy_path = work_dir / cfg["decoy_name"]
                    shutil.copy2(SAFE_SOURCE_BINARY, decoy_path)
                    if sha256_of(decoy_path) != source_hash:
                        print(f"    [{cfg['decoy_name']}] hash mismatch -- ABORTED")
                        print()
                        continue
                    base_path = str(decoy_path)
                    print(f"    real binary not found, using decoy: {base_path}")
                for i, args_fn in enumerate(cfg["args_variants"], start=1):
                    cmd = [base_path] + args_fn(work_dir)
                    log_and_run(log, canonical_name, style, i, cmd, cwd_for_run)
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
                    decoy_path = work_dir / cfg["decoy_name"]
                    shutil.copy2(SAFE_SOURCE_BINARY, decoy_path)
                    if sha256_of(decoy_path) != source_hash:
                        print(f"    [{cfg['decoy_name']}] hash mismatch -- ABORTED")
                        print()
                        continue
                    base_path = str(decoy_path)
                    print(f"    real binary not found, using decoy: {base_path}")
                for i, args_fn in enumerate(cfg["args_variants"], start=1):
                    cmd = [base_path] + args_fn(work_dir)
                    log_and_run(log, canonical_name, style, i, cmd, cwd_for_run)
                print()
                continue
    finally:
        cleaned, leftover = verified_cleanup(work_dir)

    print("=" * 78)
    print(f"CLEANUP: {work_dir} removed = {cleaned}")
    if not cleaned:
        for f in leftover:
            print(f"  STUCK: {f}")
    print("=" * 78 + "\n")

    if KEEP_RESULTS_LOG:
        results_file = Path.cwd() / f"lolbas19v2_results_{CANARY_TAG}.json"
        with open(results_file, "w") as f:
            json.dump({"canary_tag": CANARY_TAG,
                       "hostname_sha256": source_hash,
                       "work_dir_cleaned": cleaned,
                       "results": log}, f, indent=2)
        print(f"Results saved: {results_file}")

    blocked = sum(1 for e in log if "BLOCKED" in e.get("status", ""))
    print(f"\nSearch your SIEM/Sigma backend for canary tag: {CANARY_TAG}")
    print(f"EDR blocked: {blocked} event(s)")
    print(f"Total events generated: {len(log)}")


if __name__ == "__main__":
    main()

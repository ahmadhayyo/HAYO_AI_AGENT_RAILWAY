#!/usr/bin/env python3
"""
HAYO AI — Generic APK Static Auditing & Binary Patching Framework v1.0
======================================================================
Fully automated pipeline:
  1. Decompilation   (apktool d)
  2. Secret Discovery (regex scanner + colorama output)
  3. Generic Smali Patcher (text-based OpCode substitution)
  4. Recompilation   (apktool b)
  5. Memory Alignment (zipalign)
  6. Cryptographic Signing (keytool + apksigner v2/v3)

Usage:
  python3 apk_auditor.py <target.apk> [--patch-file <file> --search <old> --replace <new>]
  python3 apk_auditor.py target.apk
  python3 apk_auditor.py target.apk --patch-file LoginCheck.smali --search "const/4 v0, 0x0" --replace "const/4 v0, 0x1"

Environment:
  Requires: apktool, zipalign, apksigner (or keytool+jarsigner), java
"""

import os
import re
import sys
import glob
import shutil
import argparse
import subprocess
from pathlib import Path
from datetime import datetime

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except ImportError:
    # Fallback: no colour — define stubs
    class _Stub:
        def __getattr__(self, _):
            return ""
    Fore = _Stub()  # type: ignore
    Style = _Stub()  # type: ignore


# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════
KEYSTORE_FILE = "debug.keystore"
KEYSTORE_PASS = "android"
KEYSTORE_ALIAS = "androiddebugkey"
KEYSTORE_DNAME = "CN=HAYO, OU=RE, O=HAYO_AI, L=Baghdad, ST=Iraq, C=IQ"

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("API_KEY",         re.compile(r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']{8,})["\']', re.IGNORECASE)),
    ("SECRET",          re.compile(r'(?:secret|app[_-]?secret)\s*[=:]\s*["\']([^"\']{8,})["\']', re.IGNORECASE)),
    ("TOKEN",           re.compile(r'(?:token|access[_-]?token|auth[_-]?token)\s*[=:]\s*["\']([^"\']{8,})["\']', re.IGNORECASE)),
    ("PASSWORD",        re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', re.IGNORECASE)),
    ("HTTP_URL",        re.compile(r'https?://[^\s"\'<>]{6,}', re.IGNORECASE)),
    ("FIREBASE_URL",    re.compile(r'https://[\w-]+\.firebaseio\.com[^\s"\']*', re.IGNORECASE)),
    ("FIREBASE_KEY",    re.compile(r'AIza[A-Za-z0-9_-]{35}', re.IGNORECASE)),
    ("AWS_KEY",         re.compile(r'AKIA[A-Z0-9]{16}')),
    ("PRIVATE_KEY",     re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----')),
    ("JWT_TOKEN",       re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')),
    ("GOOGLE_OAUTH",    re.compile(r'[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com')),
    ("SLACK_TOKEN",     re.compile(r'xox[bprs]-[A-Za-z0-9-]{10,}')),
    ("TELEGRAM_TOKEN",  re.compile(r'[0-9]{5,}:AA[A-Za-z0-9_-]{33}')),
    ("STRIPE_KEY",      re.compile(r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}')),
    ("SENDGRID_KEY",    re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}')),
    ("TWILIO_SID",      re.compile(r'AC[a-f0-9]{32}')),
]


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════
def banner() -> None:
    print(f"""
{Fore.CYAN}{Style.BRIGHT}
 ██╗  ██╗ █████╗ ██╗   ██╗ ██████╗      █████╗ ██╗
 ██║  ██║██╔══██╗╚██╗ ██╔╝██╔═══██╗    ██╔══██╗██║
 ███████║███████║ ╚████╔╝ ██║   ██║    ███████║██║
 ██╔══██║██╔══██║  ╚██╔╝  ██║   ██║    ██╔══██║██║
 ██║  ██║██║  ██║   ██║   ╚██████╔╝    ██║  ██║██║
 ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝     ╚═╝  ╚═╝╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}APK Static Auditor & Binary Patcher v1.0{Style.RESET_ALL}
{Fore.WHITE}═══════════════════════════════════════════════════{Style.RESET_ALL}
""")


def log_step(phase: int, total: int, msg: str) -> None:
    print(f"\n{Fore.CYAN}{Style.BRIGHT}[{phase}/{total}]{Style.RESET_ALL} "
          f"{Fore.WHITE}{Style.BRIGHT}════ {msg} ════{Style.RESET_ALL}")


def log_ok(msg: str) -> None:
    print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def log_warn(msg: str) -> None:
    print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def log_err(msg: str) -> None:
    print(f"  {Fore.RED}[-]{Style.RESET_ALL} {msg}")


def log_info(msg: str) -> None:
    print(f"  {Fore.BLUE}[*]{Style.RESET_ALL} {msg}")


def log_secret(stype: str, value: str, filepath: str, line_no: int) -> None:
    short_path = filepath.split("decoded/")[-1] if "decoded/" in filepath else filepath
    print(f"  {Fore.RED}{Style.BRIGHT}[SECRET]{Style.RESET_ALL} "
          f"{Fore.MAGENTA}{stype:<16}{Style.RESET_ALL} "
          f"{Fore.YELLOW}{value[:80]}{Style.RESET_ALL} "
          f"{Fore.WHITE}({short_path}:{line_no}){Style.RESET_ALL}")


def run_command(cmd: list[str], cwd: str | None = None,
                timeout: int = 300) -> tuple[int, str, str]:
    """Run a subprocess and return (exit_code, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, "", f"Command timed out after {timeout}s"


def check_tool(name: str) -> bool:
    """Return True if a CLI tool is reachable."""
    try:
        subprocess.run([name, "--version"], capture_output=True, timeout=10)
        return True
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════
# PHASE 1 — DECOMPILATION
# ═══════════════════════════════════════════════════════════════
def decompile_apk(apk_path: str, output_dir: str) -> bool:
    """Decompile APK using apktool d."""
    log_step(1, 6, "Automated Decompilation (apktool)")
    log_info(f"Target: {apk_path}")
    log_info(f"Output: {output_dir}")

    code, stdout, stderr = run_command(
        ["apktool", "d", "-f", apk_path, "-o", output_dir]
    )

    if code != 0:
        log_err(f"apktool d failed (exit {code})")
        if stderr:
            for line in stderr.strip().split("\n")[:5]:
                log_err(f"  {line}")
        return False

    file_count = sum(1 for _ in Path(output_dir).rglob("*") if _.is_file())
    log_ok(f"Decompilation successful — {file_count} files extracted")
    return True


# ═══════════════════════════════════════════════════════════════
# PHASE 2 — SECRET DISCOVERY ENGINE
# ═══════════════════════════════════════════════════════════════
def discover_secrets(directory: str) -> list[dict[str, str | int]]:
    """Recursively scan decompiled directory for hardcoded secrets."""
    log_step(2, 6, "Automated Secret Discovery Engine")
    findings: list[dict[str, str | int]] = []
    scanned = 0
    skipped = 0

    text_extensions = {
        ".smali", ".xml", ".json", ".properties", ".yml", ".yaml",
        ".txt", ".cfg", ".conf", ".ini", ".java", ".kt", ".gradle",
        ".html", ".js", ".ts",
    }

    for root, _dirs, files in os.walk(directory):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in text_extensions:
                skipped += 1
                continue

            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    for line_no, line in enumerate(fh, start=1):
                        for stype, pattern in SECRET_PATTERNS:
                            for match in pattern.finditer(line):
                                value = match.group(0)
                                # skip trivial / placeholder values
                                if value.lower() in ("http://", "https://", "http://schemas.android.com"):
                                    continue
                                if len(value) < 8:
                                    continue
                                findings.append({
                                    "type": stype,
                                    "value": value,
                                    "file": fpath,
                                    "line": line_no,
                                })
                scanned += 1
            except (PermissionError, OSError):
                skipped += 1

    log_info(f"Scanned {scanned} text files ({skipped} binary/skipped)")

    if not findings:
        log_warn("No hardcoded secrets found")
        return findings

    # Deduplicate by value
    seen: set[str] = set()
    unique: list[dict[str, str | int]] = []
    for f in findings:
        val = str(f["value"])
        if val not in seen:
            seen.add(val)
            unique.append(f)

    # Print findings with colorama
    print(f"\n  {Fore.RED}{Style.BRIGHT}{'='*60}{Style.RESET_ALL}")
    print(f"  {Fore.RED}{Style.BRIGHT}  DISCOVERED {len(unique)} UNIQUE SECRETS / ENDPOINTS{Style.RESET_ALL}")
    print(f"  {Fore.RED}{Style.BRIGHT}{'='*60}{Style.RESET_ALL}")

    # Group by type
    by_type: dict[str, list[dict[str, str | int]]] = {}
    for f in unique:
        t = str(f["type"])
        by_type.setdefault(t, []).append(f)

    for stype, items in sorted(by_type.items()):
        print(f"\n  {Fore.MAGENTA}{Style.BRIGHT}[{stype}] — {len(items)} finding(s){Style.RESET_ALL}")
        for item in items[:25]:
            log_secret(stype, str(item["value"]), str(item["file"]), int(item["line"]))
        if len(items) > 25:
            log_warn(f"  ... and {len(items) - 25} more {stype} findings")

    print(f"\n  {Fore.RED}{Style.BRIGHT}{'='*60}{Style.RESET_ALL}")
    return unique


# ═══════════════════════════════════════════════════════════════
# PHASE 3 — GENERIC SMALI PATCHER
# ═══════════════════════════════════════════════════════════════
def apply_smali_patch(directory: str, target_file_name: str,
                      search_string: str, replace_string: str) -> int:
    """
    Locate a specific Smali file by name inside directory, perform a direct
    string substitution, save, and log the result.

    Returns the number of replacements made across all matching files.
    """
    log_step(3, 6, "Automated Generic Logic Patcher")
    log_info(f"Target file pattern : {target_file_name}")
    log_info(f"Search string       : {search_string}")
    log_info(f"Replace string      : {replace_string}")

    total_replacements = 0
    patched_files: list[str] = []

    # Find all matching smali files (could be in smali/, smali_classes2/, ...)
    for smali_path in Path(directory).rglob(target_file_name):
        if not smali_path.is_file():
            continue

        try:
            content = smali_path.read_text(encoding="utf-8", errors="ignore")
        except (PermissionError, OSError) as exc:
            log_err(f"Cannot read {smali_path}: {exc}")
            continue

        count = content.count(search_string)
        if count == 0:
            continue

        new_content = content.replace(search_string, replace_string)
        smali_path.write_text(new_content, encoding="utf-8")

        total_replacements += count
        patched_files.append(str(smali_path))
        short = str(smali_path).split("decoded/")[-1] if "decoded/" in str(smali_path) else str(smali_path)
        log_ok(f"Patched {short} ({count} replacement(s))")

    if total_replacements == 0:
        log_warn(f"No occurrences of '{search_string}' found in any '{target_file_name}'")
    else:
        log_ok(f"Total: {total_replacements} replacement(s) across {len(patched_files)} file(s)")

    return total_replacements


def apply_default_patches(directory: str) -> int:
    """Apply a set of common security/premium bypass patches."""
    total = 0
    default_patches: list[tuple[str, str, str]] = [
        # Unlock premium checks  (const/4 v0, 0x0 → const/4 v0, 0x1)
        ("*.smali", "const/4 v0, 0x0", "const/4 v0, 0x1"),
    ]

    smali_dirs = [
        os.path.join(directory, d)
        for d in os.listdir(directory)
        if d.startswith("smali") and os.path.isdir(os.path.join(directory, d))
    ]

    if not smali_dirs:
        log_warn("No smali directories found — skipping default patches")
        return 0

    # Scan for common guard methods and patch them
    guard_methods = [
        "isPremium", "isSubscribed", "isLicensed", "checkLicense",
        "isProUser", "hasPurchased", "isRegistered", "isActivated",
    ]

    for smali_dir in smali_dirs:
        for smali_file in Path(smali_dir).rglob("*.smali"):
            try:
                content = smali_file.read_text(encoding="utf-8", errors="ignore")
            except (PermissionError, OSError):
                continue

            modified = False
            for method_name in guard_methods:
                # Pattern: find the method, then change its return from 0x0 to 0x1
                pattern = re.compile(
                    rf'(\.method\s+[^\n]*{re.escape(method_name)}\([^)]*\)[^\n]*\n'
                    rf'(?:.*?\n)*?)'
                    rf'(\s+const/4\s+v0,\s+0x0\s*\n)',
                    re.MULTILINE
                )
                new_content, n = pattern.subn(r'\g<1>    const/4 v0, 0x1\n', content)
                if n > 0:
                    content = new_content
                    modified = True
                    total += n
                    short = str(smali_file).split("decoded/")[-1] if "decoded/" in str(smali_file) else str(smali_file)
                    log_ok(f"Patched {method_name}() → return true  in {short}")

            if modified:
                smali_file.write_text(content, encoding="utf-8")

    if total == 0:
        log_info("No guard methods found for default patching")
    else:
        log_ok(f"Default patches applied: {total} method(s) modified")

    return total


# ═══════════════════════════════════════════════════════════════
# PHASE 4 — RECOMPILATION
# ═══════════════════════════════════════════════════════════════
def recompile_apk(decoded_dir: str, output_apk: str) -> bool:
    """Rebuild the APK using apktool b."""
    log_step(4, 6, "Automated Recompilation (apktool b)")
    log_info(f"Source : {decoded_dir}")
    log_info(f"Output : {output_apk}")

    # Try with --use-aapt2 first
    code, stdout, stderr = run_command(
        ["apktool", "b", "--use-aapt2", decoded_dir, "-o", output_apk]
    )
    if code != 0:
        log_warn("aapt2 build failed — retrying without --use-aapt2")
        code, stdout, stderr = run_command(
            ["apktool", "b", decoded_dir, "-o", output_apk]
        )

    if code != 0 or not os.path.isfile(output_apk):
        log_err(f"apktool b failed (exit {code})")
        if stderr:
            for line in stderr.strip().split("\n")[:5]:
                log_err(f"  {line}")
        return False

    size_mb = os.path.getsize(output_apk) / (1024 * 1024)
    log_ok(f"Recompilation successful — {size_mb:.2f} MB")
    return True


# ═══════════════════════════════════════════════════════════════
# PHASE 5 — ZIPALIGN
# ═══════════════════════════════════════════════════════════════
def zipalign_apk(input_apk: str, aligned_apk: str) -> bool:
    """Apply strict 4-byte memory alignment with zipalign."""
    log_step(5, 6, "Strict Memory Alignment (zipalign)")
    log_info(f"Input  : {input_apk}")
    log_info(f"Output : {aligned_apk}")

    code, stdout, stderr = run_command(
        ["zipalign", "-p", "-f", "4", input_apk, aligned_apk]
    )

    if code != 0 or not os.path.isfile(aligned_apk):
        log_err(f"zipalign failed (exit {code})")
        if stderr:
            for line in stderr.strip().split("\n")[:5]:
                log_err(f"  {line}")
        log_warn("The APK may cause installation Parse Errors on modern Android")
        return False

    # Verify alignment
    v_code, v_out, _ = run_command(["zipalign", "-c", "4", aligned_apk])
    if v_code == 0:
        log_ok("Alignment verified — 4-byte boundary OK")
    else:
        log_warn("Alignment verification returned non-zero (may still work)")

    size_mb = os.path.getsize(aligned_apk) / (1024 * 1024)
    log_ok(f"Aligned APK size: {size_mb:.2f} MB")
    return True


# ═══════════════════════════════════════════════════════════════
# PHASE 6 — SIGNING
# ═══════════════════════════════════════════════════════════════
def ensure_keystore(work_dir: str) -> str:
    """Ensure debug.keystore exists; generate one if missing."""
    ks_path = os.path.join(work_dir, KEYSTORE_FILE)

    if os.path.isfile(ks_path):
        log_info(f"Using existing keystore: {ks_path}")
        return ks_path

    log_info("Generating new debug keystore with keytool ...")
    code, _, stderr = run_command([
        "keytool", "-genkeypair",
        "-v",
        "-keystore", ks_path,
        "-alias", KEYSTORE_ALIAS,
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-storepass", KEYSTORE_PASS,
        "-keypass", KEYSTORE_PASS,
        "-dname", KEYSTORE_DNAME,
    ])

    if code != 0 or not os.path.isfile(ks_path):
        log_err(f"keytool failed — {stderr.strip()[:200]}")
        return ""

    log_ok(f"Keystore generated: {ks_path}")
    return ks_path


def sign_apk(aligned_apk: str, work_dir: str) -> bool:
    """Sign APK with V2/V3 scheme using apksigner."""
    log_step(6, 6, "Cryptographic V2/V3 Signing")

    ks_path = ensure_keystore(work_dir)
    if not ks_path:
        log_err("No keystore available — signing aborted")
        return False

    # Remove old META-INF signatures if any
    try:
        run_command(["zip", "-d", aligned_apk, "META-INF/*"])
        log_info("Removed old META-INF signatures")
    except Exception:
        pass

    # Sign with apksigner (V2 + V3)
    code, stdout, stderr = run_command([
        "apksigner", "sign",
        "--ks", ks_path,
        "--ks-pass", f"pass:{KEYSTORE_PASS}",
        "--ks-key-alias", KEYSTORE_ALIAS,
        "--key-pass", f"pass:{KEYSTORE_PASS}",
        "--v2-signing-enabled", "true",
        "--v3-signing-enabled", "true",
        aligned_apk,
    ])

    if code != 0:
        log_warn(f"apksigner failed (exit {code}) — falling back to jarsigner")
        if stderr:
            log_warn(stderr.strip()[:200])

        # Fallback: jarsigner
        code2, _, stderr2 = run_command([
            "jarsigner",
            "-verbose",
            "-sigalg", "SHA256withRSA",
            "-digestalg", "SHA-256",
            "-keystore", ks_path,
            "-storepass", KEYSTORE_PASS,
            "-keypass", KEYSTORE_PASS,
            aligned_apk,
            KEYSTORE_ALIAS,
        ])
        if code2 != 0:
            log_err(f"jarsigner also failed — {stderr2.strip()[:200]}")
            return False
        log_ok("Signed with jarsigner (V1 scheme)")
        return True

    # Verify signature
    v_code, v_out, _ = run_command(["apksigner", "verify", "--verbose", aligned_apk])
    if v_code == 0:
        log_ok("Signature verified — V2/V3 OK")
        for line in v_out.strip().split("\n"):
            if "true" in line.lower() or "verified" in line.lower():
                log_info(f"  {line.strip()}")
    else:
        log_warn("Signature verification returned non-zero (may still install)")

    log_ok("APK signed successfully — ready for deployment")
    return True


# ═══════════════════════════════════════════════════════════════
# MAIN PIPELINE
# ═══════════════════════════════════════════════════════════════
def run_pipeline(apk_path: str, patch_file: str | None = None,
                 search: str | None = None,
                 replace: str | None = None) -> dict:
    """Execute the full 6-phase pipeline and return a result dict."""
    result: dict = {
        "success": False,
        "secrets": [],
        "patches": 0,
        "signed": False,
        "output_apk": "",
        "error": "",
    }

    apk_path = os.path.abspath(apk_path)
    if not os.path.isfile(apk_path):
        log_err(f"Target APK not found: {apk_path}")
        result["error"] = "APK file not found"
        return result

    basename = os.path.splitext(os.path.basename(apk_path))[0]
    work_dir = os.path.join(os.path.dirname(apk_path), f"hayo_audit_{basename}")
    decoded_dir = os.path.join(work_dir, "decoded")
    patched_apk = os.path.join(work_dir, f"patched-{basename}.apk")
    aligned_apk = os.path.join(work_dir, f"aligned-{basename}.apk")

    os.makedirs(work_dir, exist_ok=True)

    # ── Phase 1: Decompile ──
    if not decompile_apk(apk_path, decoded_dir):
        result["error"] = "Decompilation failed"
        return result

    # ── Phase 2: Secret Discovery ──
    secrets = discover_secrets(decoded_dir)
    result["secrets"] = secrets

    # ── Phase 3: Patch ──
    patches = 0
    if patch_file and search and replace:
        patches = apply_smali_patch(decoded_dir, patch_file, search, replace)
    else:
        log_step(3, 6, "Automated Generic Logic Patcher")
        log_info("No explicit patch target — applying default bypass patches")
        patches = apply_default_patches(decoded_dir)
    result["patches"] = patches

    # ── Phase 4: Recompile ──
    if not recompile_apk(decoded_dir, patched_apk):
        result["error"] = "Recompilation failed"
        return result

    # ── Phase 5: Zipalign ──
    if not zipalign_apk(patched_apk, aligned_apk):
        log_warn("Continuing without alignment — APK may not install on all devices")
        aligned_apk = patched_apk

    # ── Phase 6: Sign ──
    signed = sign_apk(aligned_apk, work_dir)
    result["signed"] = signed

    result["success"] = True
    result["output_apk"] = aligned_apk

    # ── Summary ──
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}  PIPELINE COMPLETE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'='*60}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Secrets discovered : {Fore.YELLOW}{len(secrets)}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Patches applied    : {Fore.YELLOW}{patches}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Signed             : {Fore.GREEN if signed else Fore.RED}{'Yes' if signed else 'No'}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Output APK         : {Fore.GREEN}{aligned_apk}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Timestamp          : {datetime.now().isoformat()}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'='*60}{Style.RESET_ALL}\n")

    return result


# ═══════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════
def main() -> None:
    banner()

    parser = argparse.ArgumentParser(
        description="HAYO AI — APK Static Auditor & Binary Patcher"
    )
    parser.add_argument("apk", help="Path to target APK file")
    parser.add_argument("--patch-file", dest="patch_file", default=None,
                        help="Smali file name to patch (e.g. LoginCheck.smali)")
    parser.add_argument("--search", default=None,
                        help="String to search for in the target file")
    parser.add_argument("--replace", default=None,
                        help="Replacement string")

    args = parser.parse_args()

    # Pre-flight tool checks
    print(f"{Fore.WHITE}{Style.BRIGHT}Pre-flight tool checks:{Style.RESET_ALL}")
    tools = {
        "apktool": check_tool("apktool"),
        "zipalign": check_tool("zipalign"),
        "apksigner": check_tool("apksigner"),
        "keytool": check_tool("keytool"),
        "java": check_tool("java"),
    }
    for name, ok in tools.items():
        status = f"{Fore.GREEN}OK" if ok else f"{Fore.RED}MISSING"
        print(f"  {name:<12} {status}{Style.RESET_ALL}")

    if not tools["apktool"]:
        log_err("apktool is required but not found. Install it first.")
        sys.exit(1)

    result = run_pipeline(args.apk, args.patch_file, args.search, args.replace)

    sys.exit(0 if result["success"] else 1)


if __name__ == "__main__":
    main()

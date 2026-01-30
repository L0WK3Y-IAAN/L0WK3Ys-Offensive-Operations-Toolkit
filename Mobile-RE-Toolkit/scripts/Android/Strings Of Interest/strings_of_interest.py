#!/usr/bin/env python3
# MRET: no_args
# ---------------------------------------------------------------------------
# Script by L0WK3Y
# https://github.com/L0WK3Y-IAAN
# ---------------------------------------------------------------------------

"""
Detects malicious indicators in extracted APK strings.

✅ Scans CSV output from string_extraction.py and multi-dex CSVs
✅ Detects C2 URLs, permissions, encryption, obfuscation, and more
✅ Removes duplicate CSV entries & subfolder duplicates
✅ Ignores potential_indicators.csv to avoid re-scanning results
✅ Uses multi-threading for faster processing
✅ Findings saved as potential_indicators.csv next to the input CSV
✅ Uses rich for an enhanced UI
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import re
import os
import sys
import threading
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress
from rich.markup import escape  # Ensure literal rendering, no markup parsing


def get_toolkit_root() -> Path:
    """Get the absolute path to the Mobile-RE-Toolkit root."""
    script_dir = Path(__file__).resolve().parent
    toolkit_root = script_dir
    for _ in range(10):  # Safety limit
        if (toolkit_root / "main.py").exists():
            return toolkit_root
        toolkit_root = toolkit_root.parent
    return script_dir.parent.parent.parent  # Fallback


TOOLKIT_ROOT = get_toolkit_root()
OUTPUT_DIR = TOOLKIT_ROOT / "src" / "output"

# Set the CSV field size limit to avoid overflow errors
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))  # Cap at ~2GB

# Initialize rich console
console = Console()

# Thread-safe results storage
results_lock = threading.Lock()
findings = {}

# Suspicious Indicators List
SUSPICIOUS_INDICATORS = {
    "Permissions": [
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.CALL_PHONE",
        "android.permission.INTERNET",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.GET_TASKS",
        "android.permission.FOREGROUND_SERVICE",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
    ],
    "URLs": re.compile(r"https?://[a-zA-Z0-9.-]+(/\S*)?", re.IGNORECASE),
    "IP_Addresses": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),

    # Obfuscation & Encoding Methods
    "Obfuscation_Methods": [
        "Base64.decode",
        "XOR",
        "AES",
        "RC4",
        "MD5",
        "Class.forName",
        "DexClassLoader",
        "Method.invoke",
        "loadClass",
        "System.loadLibrary",
    ],
    "Smali_Obfuscation": re.compile(r"invoke-static \{.*\}, Landroid/util/Base64;->decode"),

    # Anti-Debugging & Emulator Detection
    "Anti_Debugging": [
        "isDebuggerConnected",
        "android.os.Debug",
        "Build.FINGERPRINT",
        "Build.MODEL",
        "ro.product.device",
        "QEMU",
        "Debug.isDebuggerConnected",
        "android.os.Debug.waitForDebugger",
    ],
    "Smali_Anti_Debugging": re.compile(r"invoke-static \{.*\}, Landroid/os/Debug;->isDebuggerConnected"),
    "Smali_Emulator_Checks": re.compile(r"invoke-static \{.*\}, Ljava/lang/System;->getProperty\(Ljava/lang/String;\)Ljava/lang/String;"),

    # Network & Suspicious API Calls
    "Suspicious_API_Calls": [
        "java.net.Socket",
        "java.net.URL",
        "java.lang.Runtime.exec",
        "android.webkit.WebView.loadUrl",
        "android.telephony.TelephonyManager.getDeviceId",
        "android.telephony.TelephonyManager.getSubscriberId",
        "android.telephony.TelephonyManager.getSimCountryIso",
        "android.telephony.TelephonyManager.getNetworkCountryIso",
        "android.telephony.TelephonyManager.getLine1Number",
    ],
    "Smali_Sockets": re.compile(r"new-instance .* Ljava/net/Socket"),
    "Smali_Runtime_Exec": re.compile(r"invoke-virtual \{.*\}, Ljava/lang/Runtime;->exec"),
    "Smali_WebView_LoadUrl": re.compile(r"invoke-virtual \{.*\}, Landroid/webkit/WebView;->loadUrl"),

    # Dynamic Code Loading
    "Dynamic_Code_Loading": [
        "DexClassLoader",
        "PathClassLoader",
        ".dex",
        "loadClass",
        "java.lang.reflect.Method.invoke",
    ],
    "Smali_Dex_Loading": re.compile(r"new-instance .* Ldalvik/system/DexClassLoader"),
    "Smali_Reflection_LoadClass": re.compile(r"invoke-static \{.*\}, Ljava/lang/Class;->forName"),

    # Native Code Execution
    "Native_Code_Execution": [
        "System.loadLibrary",
        "JNI_OnLoad",
        "registerNatives",
        "android.app.NativeActivity",
    ],
    "Smali_Native_Code": re.compile(r"invoke-static \{.*\}, Ljava/lang/System;->loadLibrary"),

    # Reflection
    "Reflection": re.compile(r"invoke-static \{.*\}, Ljava/lang/Class;->forName"),

    # Encryption
    "AES_Encryption": re.compile(r"invoke-virtual \{.*\}, Ljavax/crypto/Cipher;->doFinal"),
    "Smali_AES_Encryption": re.compile(r"invoke-virtual \{.*\}, Ljavax/crypto/Cipher;->doFinal"),

    # Root Detection
    "Root_Detection": re.compile(r"invoke-static {}, Ljava/lang/System;->getProperty"),
    "Smali_Root_Detection": re.compile(r"invoke-static \{.*\}, Ljava/lang/System;->getProperty"),

    # Asset Manipulation
    "Asset_Manipulation": [
        "getAssets()",
        "getResources()",
        "openRawResource",
        "open",
        "openFd",
        "getIdentifier",
        "loadXmlResourceParser",
        "getResourceEntryName",
        "getResourcePackageName",
        "getResourceTypeName",
        "getResourceName",
        "getResourceValue",
        "Resources.getSystem()",
    ],
    "Smali_Asset_Manipulation": [
        re.compile(r"invoke-virtual \{.*\}, Landroid/content/res/AssetManager;->open"),
        re.compile(r"invoke-virtual \{.*\}, Landroid/content/res/Resources;->getIdentifier"),
        re.compile(r"invoke-virtual \{.*\}, Landroid/content/res/Resources;->openRawResource"),
        re.compile(r"invoke-virtual \{.*\}, Landroid/content/res/Resources;->loadXmlResourceParser"),
        re.compile(r"invoke-virtual \{.*\}, Landroid/content/res/Resources;->getResourceEntryName"),
        re.compile(r"invoke-virtual \{.*\}, Landroid/content/res/Resources;->getResourcePackageName"),
        re.compile(r"invoke-virtual \{.*\}, Landroid/content/res/Resources;->getResourceTypeName"),
        re.compile(r"invoke-virtual \{.*\}, Landroid/content/res/Resources;->getResourceValue"),
        re.compile(r"invoke-static {}, Landroid/content/res/Resources;->getSystem"),
    ],

    # Hidden Asset Decryption
    "Hidden_Asset_Decryption": [
        "Ljava/io/InputStream;->read",
        "Ljava/io/ByteArrayOutputStream;->toByteArray",
        "Ljava/security/Cipher;->doFinal",
        "Ljava/security/Cipher;->doFinal",
        "Ljavax/crypto/spec/SecretKeySpec",
    ],

    # XOR Obfuscation Detection (Dynamic)
    "Smali_XOR_Obfuscation": re.compile(r"xor-(int|long|int/lit8|long/lit8|byte|short)"),
    "Smali_XOR_Key_Usage": re.compile(r"const/4 v\d+, \d+\s+xor-"),

    # High Entropy Data (Base64, Encrypted Payloads)
    "High_Entropy_Data": re.compile(r"[A-Za-z0-9+/]{50,}={0,2}"),
}

EXCLUDE_FROM_ENTROPY = ["smali", "xml"]  # Ignore Smali & XML files for entropy scanning

def detect_csv_schema(fieldnames):
    """
    Return:
      - 'source' for CSVs with columns ['file','string'],
      - 'dex' for CSVs with columns like ['dex_file','index','offset_hex','string'] or missing dex_file,
      - None for unknown schema.
    """
    f = {fn.strip().lower() for fn in (fieldnames or [])}
    if {"file", "string"}.issubset(f):
        return "source"
    if {"index", "offset_hex", "string"}.issubset(f):
        return "dex"
    if {"dex_file", "index", "offset_hex", "string"}.issubset(f):
        return "dex"
    return None

def normalize_row(row, schema):
    """
    Return (file_path, string) for downstream processing, regardless of schema.
    - source: file=row['file'], string=row['string']
    - dex:   file synthesized as 'DEX: <dex_file> index=<idx> offset=<off>' (no brackets to avoid Rich markup)
    """
    if schema == "source":
        return row.get("file", ""), row.get("string", "")

    if schema == "dex":
        idx = row.get("index", "")
        off = row.get("offset_hex", "")
        dex_file = row.get("dex_file") or ""
        # Use a colon-based prefix to avoid square brackets that trigger Rich markup parsing
        if dex_file:
            pseudo = f"DEX: {dex_file} index={idx} offset={off}"
        else:
            pseudo = f"DEX: index={idx} offset={off}"
        return pseudo, row.get("string", "")

    # Unknown schema
    s = row.get("string") or row.get("value") or ""
    return "", s

def find_csv_files():
    csv_files = set()
    if OUTPUT_DIR.exists():
        for root, _, files in os.walk(str(OUTPUT_DIR)):
            for file in files:
                if file.lower().endswith(".csv") and "potential_indicators.csv" not in file:
                    absolute_path = os.path.abspath(os.path.join(root, file))
                    csv_files.add(absolute_path)
    return sorted(csv_files)

def list_and_select_csv():
    """Lists found CSV files and lets the user pick one."""
    csv_files = find_csv_files()
    if not csv_files:
        console.print(f"[red]❌ No CSV files found in `{OUTPUT_DIR}/`. Please run string extraction first.[/]")
        console.print(f"[dim]Searched in: {OUTPUT_DIR}[/dim]")
        input("Press Enter to exit...")
        sys.exit(1)

    console.print("\n[cyan]📄 Found the following CSV files:[/]")
    table = Table(title=escape("Available CSV Files"), show_header=True, header_style="bold magenta")
    table.add_column("Index", justify="center", style="cyan", no_wrap=True)
    table.add_column("File Path", style="green")
    for i, csv_file in enumerate(csv_files, 1):
        table.add_row(str(i), escape(csv_file))
    console.print(table)

    while True:
        choice = Prompt.ask("[bold cyan]Enter the number of the CSV file to analyze[/]").strip()
        if choice.isdigit():
            choice = int(choice)
            if 1 <= choice <= len(csv_files):
                return csv_files[choice - 1]
        console.print("[bold red]⚠ Invalid selection. Try again.[/]")

def process_row(row, schema):
    """Processes a single CSV row for malicious indicators."""
    file_path, string = normalize_row(row, schema)

    if not string:
        return

    entropy_scan = True
    if schema == "source" and any(file_path.endswith(ext) for ext in EXCLUDE_FROM_ENTROPY):
        entropy_scan = False

    row_findings = {}

    for category, patterns in SUSPICIOUS_INDICATORS.items():
        if category == "High_Entropy_Data" and not entropy_scan:
            continue

        if isinstance(patterns, list):
            matched = False
            if any((isinstance(p, str) and p in string) for p in patterns):
                matched = True
            if any((isinstance(p, re.Pattern) and p.search(string)) for p in patterns):
                matched = True
            if matched:
                row_findings.setdefault(category, []).append((file_path, string))

        elif isinstance(patterns, re.Pattern):
            if patterns.search(string):
                row_findings.setdefault(category, []).append((file_path, string))

    if row_findings:
        with results_lock:
            for key, value in row_findings.items():
                findings.setdefault(key, []).extend(value)

def analyze_csv(file_path):
    """Processes CSV file with multi-threading and updates progress bar dynamically."""
    if not os.path.exists(file_path):
        console.print(f"[red]❌ Error: File not found -> {escape(file_path)}[/]")
        return

    global findings
    findings = {category: [] for category in SUSPICIOUS_INDICATORS.keys()}

    indicators_output = os.path.join(os.path.dirname(file_path), "potential_indicators.csv")
    console.print(f"[cyan]🔍 Scanning CSV: {escape(file_path)}[/]")

    with open(file_path, "r", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        schema = detect_csv_schema(reader.fieldnames)
        if schema is None:
            console.print("[yellow]⚠ Unrecognized CSV schema; attempting best-effort scan (looking for a 'string' column).[/]")

        with Progress() as progress:
            task = progress.add_task("[cyan]Processing entries, please wait...", total=0)

            with ThreadPoolExecutor() as executor:
                futures = []
                for row in reader:
                    futures.append(executor.submit(process_row, row, schema))
                    # Increment total lazily as we enqueue work
                    progress.update(task, total=progress.tasks[task].total + 1)

                for future in as_completed(futures):
                    future.result()
                    progress.update(task, advance=1)

    display_findings(findings, indicators_output)

def display_findings(findings, output_csv):
    """Displays results in a structured table and saves to a CSV file."""
    found_something = False
    all_results = []

    for category, results in findings.items():
        if results:
            found_something = True
            table = Table(title=escape(f"🚨 {category} Detected"), show_header=True, header_style="bold red")
            table.add_column("File", style="cyan", no_wrap=True)
            table.add_column("Suspicious String", style="yellow")

            for file, string in results:
                short = string if len(string) <= 80 else string[:80] + "..."
                table.add_row(escape(file or ""), escape(short or ""))
                all_results.append({"category": category, "file": file, "string": string})

            console.print(table)

    if found_something:
        save_findings_to_csv(all_results, output_csv)
    else:
        console.print("[green]✅ No suspicious indicators found![/]")

def save_findings_to_csv(results, output_csv):
    """Saves findings to potential_indicators.csv."""
    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["category", "file", "string"])
        writer.writeheader()
        writer.writerows(results)

    console.print(f"[bold green]✅ Findings saved to:[/] {escape(output_csv)}")
    input("Press Enter to continue...")

def main():
    console.print("\n[bold magenta]🔎 Android Malicious Indicator Scanner 🔍[/]\n")
    csv_file = list_and_select_csv()
    analyze_csv(csv_file)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Cancelled by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        sys.exit(1)

#!/usr/bin/env python3
# MRET: no_args
# ---------------------------------------------------------------------------
# Script by L0WK3Y
# https://github.com/L0WK3Y-IAAN
# ---------------------------------------------------------------------------

"""
Detects malicious indicators AND potential vulnerabilities in extracted
strings (Android APK strings or iOS binary strings).

✅ Scans CSV output from string_extraction.py, multi-dex CSVs, and plain
   strings dumps (the IPA decompiler's <binary>-strings.txt)
✅ Pattern-matches strings to vulnerability classes (injection templates,
   hardcoded secrets, weak crypto, TLS issues, debug leftovers) with
   severity, CWE and a why-it-matters note per finding
✅ Flags high-entropy key-sized base64/hex blobs (Shannon entropy)
✅ Detects C2 URLs, permissions, encryption, obfuscation, and more
✅ Removes duplicate CSV entries & subfolder duplicates
✅ Ignores potential_indicators.csv to avoid re-scanning results
✅ Uses multi-threading for faster processing
✅ Findings saved as potential_indicators.csv next to the input file
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
vuln_findings = []
vuln_seen = set()

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

# ---------------------------------------------------------------------------
# Vulnerability rules: pattern -> what it probably means.
# Each rule maps a string pattern to a vulnerability class with enough
# context (CWE, severity, why) to act on the finding without re-researching.
# ---------------------------------------------------------------------------

VULN_RULES = [
    # --- Injection ---
    {"id": "query-splice", "vuln": "Query/NSPredicate injection", "severity": "high", "cwe": "CWE-89", "platform": "any",
     "why": "Quoted query/predicate template built by string concatenation - input can break out of the quotes",
     "pattern": re.compile(r"'\s*(AND|OR)\s+[\w.]+\s*(==|!=|>=|<=|CONTAINS|LIKE|MATCHES)\s*'")},
    {"id": "sql-statement", "vuln": "SQL built in code", "severity": "medium", "cwe": "CWE-89", "platform": "any",
     "why": "SQL statement string - verify it uses bound parameters, not concatenation",
     "pattern": re.compile(r"(?i)\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[\s\S]{0,120}\b(WHERE|VALUES|SET)\b")},
    {"id": "cmd-concat", "vuln": "Command injection candidate", "severity": "high", "cwe": "CWE-78", "platform": "any",
     "why": "Shell command construction - check what flows into it",
     "pattern": re.compile(r"(?i)(Runtime\.exec|ProcessBuilder|NSTask|popen\s*\(|system\s*\()[^\n]{0,80}(\+|%s|append|String\.format)")},

    # --- Secrets & credentials ---
    {"id": "assigned-secret", "vuln": "Hardcoded credential/secret", "severity": "high", "cwe": "CWE-798", "platform": "any",
     "why": "Secret-looking value assigned inline in code",
     "pattern": re.compile(r"(?i)\b(api[_-]?key|secret|passwd|password|token|auth(entication)?|credential)\s*[:=]\s*[\"'][^\"']{6,}[\"']")},
    {"id": "url-credentials", "vuln": "Credentials embedded in URL", "severity": "high", "cwe": "CWE-598", "platform": "any",
     "why": "user:pass@ URLs leak via logs, referrers and history",
     "pattern": re.compile(r"https?://[^/\s:@]+:[^/\s:@]+@")},
    {"id": "url-secret-param", "vuln": "Secret in URL query string", "severity": "medium", "cwe": "CWE-598", "platform": "any",
     "why": "Tokens in query strings end up in logs and analytics",
     "pattern": re.compile(r"(?i)[?&](api[_-]?key|access[_-]?token|token|secret|password|passwd|auth)=[^&\s\"']{4,}")},
    {"id": "aws-access-key", "vuln": "AWS access key ID", "severity": "high", "cwe": "CWE-798", "platform": "any",
     "why": "Live cloud credential format (AKIA...)",
     "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b")},
    {"id": "google-api-key", "vuln": "Google API key", "severity": "high", "cwe": "CWE-798", "platform": "any",
     "why": "AIza... key format - check quota abuse / what it unlocks",
     "pattern": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")},
    {"id": "github-token", "vuln": "GitHub token", "severity": "high", "cwe": "CWE-798", "platform": "any",
     "why": "ghp_/gho_/ghs_ tokens grant repo access",
     "pattern": re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")},
    {"id": "jwt", "vuln": "Hardcoded JWT", "severity": "medium", "cwe": "CWE-798", "platform": "any",
     "why": "Decode it (jwt.io) - may hold claims or a crackable signature",
     "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")},
    {"id": "private-key", "vuln": "Private key material", "severity": "high", "cwe": "CWE-321", "platform": "any",
     "why": "PEM private key embedded in the app",
     "pattern": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----")},
    {"id": "ctf-flag", "vuln": "Flag/answer string", "severity": "info", "cwe": "-", "platform": "any",
     "why": "CTF-style flag format - sometimes left in production apps too",
     "pattern": re.compile(r"(?i)\b(MHC|FLAG|CTF|HTB|PICOCTF|DUCTF)\{[^}\s]{3,}\}")},

    # --- Crypto weaknesses ---
    {"id": "weak-cipher", "vuln": "Weak cipher mode/algorithm", "severity": "medium", "cwe": "CWE-327", "platform": "any",
     "why": "ECB/DES/RC4 are broken or leak patterns - look for how keys/IVs are chosen",
     "pattern": re.compile(r"(?i)\b(AES/ECB|AES-ECB|DESede?|ARC4|RC4|RC2|Blowfish|ECB[\s_-]?mode)\b")},
    {"id": "weak-hash", "vuln": "Weak hash", "severity": "low", "cwe": "CWE-328", "platform": "any",
     "why": "MD5/SHA-1 are collision-broken - fine for checksums, bad for passwords/signatures",
     "pattern": re.compile(r"(?i)\b(md5|sha-?1)\b(?![-\w])")},
    {"id": "static-iv", "vuln": "Static IV", "severity": "medium", "cwe": "CWE-329", "platform": "any",
     "why": "Hardcoded IVs make identical plaintexts produce identical ciphertexts",
     "pattern": re.compile(r"(?i)(IvParameterSpec\s*\(\s*[\"']|[^a-z]iv\s*[:=]\s*[\"'][A-Za-z0-9+/=]{8,}[\"'])")},
    {"id": "static-salt", "vuln": "Static salt", "severity": "medium", "cwe": "CWE-760", "platform": "any",
     "why": "Fixed salts defeat rainbow-table resistance",
     "pattern": re.compile(r"(?i)\bsalt\s*[:=]\s*[\"'][^\"']{4,}[\"']")},

    # --- TLS / transport ---
    {"id": "trust-all-tls", "vuln": "TLS validation disabled", "severity": "high", "cwe": "CWE-295", "platform": "any",
     "why": "Trust-all / hostname-verify-all / ATS disabled - MITM is possible",
     "pattern": re.compile(r"(?i)(TrustAll|ALLOW_ALL_HOSTNAME|NullHostnameVerifier|setHostnameVerifier|kSecTrustResultProceed|continueWithoutCredentialForAuthenticationChallenge|NSAllowsArbitraryLoads)")},

    # --- Debug leftovers & info leaks ---
    {"id": "debug-logging", "vuln": "Debug logging shipped", "severity": "medium", "cwe": "CWE-489", "platform": "any",
     "why": "Debug logs often narrate auth/crypto logic and leak internals",
     "pattern": re.compile(r"(?i)(\[DEBUG\]|\bdebug\s*(mode|log(ging)?|enabled)\b)")},
    {"id": "dev-hint", "vuln": "Developer hint/answer leak", "severity": "high", "cwe": "CWE-200", "platform": "any",
     "why": "Hint/answer text reveals secret format - often defines the brute-force space",
     "pattern": re.compile(r"(?i)(password\s*hint|hint\s*(is|:)|the\s*(flag|answer|secret)\s*(is|:))")},
    {"id": "priv-boundary", "vuln": "Privilege boundary", "severity": "info", "cwe": "CWE-269", "platform": "any",
     "why": "Role/admin checks mark where privilege escalation targets live",
     "pattern": re.compile(r"(?i)\bis_admin\b|\bisAdmin\b|\brole\s*==\s*[\"']?admin|admin\s*only")},
    {"id": "api-endpoint", "vuln": "Interesting API endpoint", "severity": "info", "cwe": "-", "platform": "any",
     "why": "Auth/data endpoints are attack surface reachable without the app",
     "pattern": re.compile(r"https?://[^\s\"']*(/api/|/fetch|/auth|/login|/token|/admin|/graphql|/upload)[^\s\"']*")},

    # --- Platform-dangerous APIs ---
    {"id": "ios-insecure-storage", "vuln": "Insecure iOS data protection", "severity": "medium", "cwe": "CWE-922", "platform": "ios",
     "why": "Files/keychain readable while locked or always",
     "pattern": re.compile(r"NSFileProtectionNone|kSecAttrAccessibleAlways\b")},
    {"id": "ios-uiwebview", "vuln": "Deprecated UIWebView", "severity": "low", "cwe": "CWE-1004", "platform": "ios",
     "why": "UIWebView lacks modern cookie/JS isolation and ATS behavior",
     "pattern": re.compile(r"\bUIWebView\b")},
    {"id": "ios-anti-debug", "vuln": "Anti-debug/anti-tamper", "severity": "info", "cwe": "-", "platform": "ios",
     "why": "Detectable protections - worth mapping what they guard",
     "pattern": re.compile(r"\bptrace\s*\(|PT_DENY_ATTACH|P_TRACED|sysctl\s*\(\s*CTL_KERN")},
    {"id": "android-webview-js", "vuln": "WebView JS bridge", "severity": "medium", "cwe": "CWE-749", "platform": "android",
     "why": "JS enabled + JS interfaces = XSS-to-native bridge risk",
     "pattern": re.compile(r"setJavaScriptEnabled\s*\(\s*true|addJavascriptInterface")},
    {"id": "android-world-mode", "vuln": "World-readable/writable storage", "severity": "high", "cwe": "CWE-732", "platform": "android",
     "why": "Any app on the device can read/write it",
     "pattern": re.compile(r"MODE_WORLD_(READABLE|WRITABLE)")},
]

BASE64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")

import math
from bisect import bisect_right

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# What to actually DO about each rule - the "so what" next step.
RULE_NEXT = {
    "query-splice": "Break out of the quotes and test injection: ' OR 1 == 1 OR username == 'x ; hook the predicate/SQL evaluation to watch it live",
    "sql-statement": "Confirm it uses bound parameters - try classic payloads (' OR 1=1 --) on any input feeding it",
    "cmd-concat": "Fuzz metacharacters (; | ` $()) into anything that flows here",
    "assigned-secret": "Test if the value is live (curl/CLI login) and check git history for rotation",
    "url-credentials": "Try the creds, then strip them - they leak via logs/referrers",
    "url-secret-param": "Replay the request without the param to see if it's actually enforced",
    "aws-access-key": "Validate with `aws sts get-caller-identity`; check S3 exposure",
    "google-api-key": "Probe allowed APIs/restrictions in Google Cloud console",
    "github-token": "Check scopes with `gh api /user`; look for private repo access",
    "jwt": "Decode it (jwt.io) - inspect claims and try alg=none / weak-secret cracking",
    "private-key": "Extract it; check what it unlocks (servers, other builds, git)",
    "ctf-flag": "Verify it's the answer; in real apps look for hidden debug screens it guards",
    "weak-cipher": "Map how keys/IVs are chosen - ECB/static IVs are the real bug",
    "weak-hash": "If used for passwords/signatures, it's crackable - pivot to the stored hashes",
    "static-iv": "Identical plaintexts will produce identical ciphertexts - look for patterns",
    "static-salt": "Rainbow-table the password hashes this salt protects",
    "trust-all-tls": "MITM the traffic with a proxy (mitmproxy/Burp) - no pinning to defeat",
    "debug-logging": "Run the app and watch logs (logcat/os_log) - debug paths often leak auth logic",
    "dev-hint": "The hint defines the secret's format -> brute-force that space",
    "priv-boundary": "Target it: predicate/SQLi role bypass, or patch the check in frida",
    "api-endpoint": "curl it directly - map methods, params, and auth requirements",
    "ios-insecure-storage": "Check what lands in those files/keychain items (device backup, filesystem)",
    "ios-uiwebview": "Test JS injection / cookie isolation; migrate findings to WKWebView context",
    "ios-anti-debug": "Map what the check guards - patch it (frida) and diff the behavior",
    "android-webview-js": "Test XSS into the bridge - @JavascriptInterface methods are callable from JS",
    "android-world-mode": "Read/write the files as any app on the device (adb run-as or a test APK)",
    "key-material-blob": "Try as AES key/IV (raw and SHA256'd) against any captured ciphertext",
}

# Optional YARA rules: drop *.yar files into ./rules next to this script.
# Requires `pip install yara-python`; silently skipped when unavailable.
try:
    import yara as _yara
    _yara_dir = Path(__file__).resolve().parent / "rules"
    _yara_rules = None
    if _yara.is_dir(str(_yara_dir)) if hasattr(_yara, "is_dir") else _yara_dir.is_dir():
        _sources = {p.stem: str(p) for p in _yara_dir.glob("*.yar")}
        if _sources:
            _yara_rules = _yara.compile(filepaths=_sources)
except Exception:
    _yara = None
    _yara_rules = None


# --- Code cross-referencing --------------------------------------------------
# otool annotates literal-pool loads: `add x0, x0, #0x2f2 ; literal pool for:
# "username == '"`. Combined with the symbol table that maps an address to its
# function, a matched string can be traced to the code that references it.

_xref_cache = {}

def build_xref_index(strings_path: str):
    """Lazily index a strings dump's sibling -disassembly.asm/-symbols.txt."""
    if strings_path in _xref_cache:
        return _xref_cache[strings_path]
    index = None
    p = Path(strings_path)
    stem = p.name
    for suffix in ("-strings.txt", ".txt"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    disasm = p.parent / f"{stem}-disassembly.asm"
    symbols = p.parent / f"{stem}-symbols.txt"
    if disasm.exists() and symbols.exists():
        funcs = []
        for line in symbols.read_text(errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] in ("T", "t") and re.fullmatch(r"[0-9a-fA-F]+", parts[0]):
                funcs.append((int(parts[0], 16), parts[2]))
        funcs.sort()
        lits = []
        lit_re = re.compile(r"^([0-9a-f]{6,16})\s.*literal pool for: \"(.*)\"")
        for line in disasm.read_text(errors="replace").splitlines():
            m = lit_re.match(line)
            if m:
                lits.append((int(m.group(1), 16), m.group(2)))
        index = (funcs, lits)
    _xref_cache[strings_path] = index
    return index

def find_code_xrefs(string: str, strings_path: str, limit: int = 3):
    """Best-effort: which functions reference this string (via otool's
    literal-pool annotations). Needs the sibling disassembly + symbols."""
    index = build_xref_index(strings_path)
    if not index:
        return ""
    funcs, lits = index
    needle = string.strip()
    short = needle[:40] if len(needle) > 40 else needle
    xrefs = []
    for addr, literal in lits:
        lit = literal.strip()
        if len(lit) < 6:
            continue  # empty/tiny literal-pool entries match everything
        matched = lit == needle or lit == short
        if not matched and len(lit) >= 10:
            matched = short in lit or lit in needle
        if matched:
            if funcs:
                i = bisect_right(funcs, (addr, "\uffff")) - 1
                if i >= 0:
                    xrefs.append(f"{funcs[i][1].split('$s')[-1][:60]} @ 0x{addr:x}")
            else:
                xrefs.append(f"@ 0x{addr:x}")
        if len(xrefs) >= limit:
            break
    return "; ".join(dict.fromkeys(xrefs))


def score_confidence(severity: str, context: str, entropy_bonus: bool = False) -> str:
    """Cheap confidence: severity base + corroboration from surrounding
    strings + entropy quality. 'high' when multiple signals agree."""
    score = {"high": 2, "medium": 1, "low": 0, "info": 0}.get(severity, 0)
    if re.search(r"(?i)\b(key|aes|crypto|secret|password|token|admin|auth|cert)\b", context):
        score += 1
    if entropy_bonus:
        score += 1
    return "high" if score >= 3 else ("medium" if score == 2 else "low")


def probe_endpoints(urls):
    """Optional live verification: GET the discovered endpoints and report
    what they say. Off by default - only runs when the user opts in."""
    try:
        import requests
    except Exception:
        console.print("[yellow]⚠ 'requests' not installed - skipping endpoint probing.[/]")
        return
    table = Table(title=escape("🌐 Endpoint Probe"), show_header=True, header_style="bold blue")
    table.add_column("URL", style="cyan")
    table.add_column("Status", style="yellow")
    table.add_column("Server", style="white")
    table.add_column("Content-Type / Size", style="white")
    for url in sorted(set(urls))[:20]:
        try:
            r = requests.get(url, timeout=10, allow_redirects=False,
                             headers={"User-Agent": "Mozilla/5.0 (strings-of-interest probe)"})
            table.add_row(escape(url), str(r.status_code),
                          escape(r.headers.get("Server", "-")),
                          escape(f"{r.headers.get('Content-Type', '-')} / {len(r.content)}B"))
        except Exception as e:
            table.add_row(escape(url), "ERR", "-", escape(str(e)[:60]))
    console.print(table)

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
    """CSVs and plain strings dumps (.txt) under src/output - the .txt side
    covers the IPA decompiler's <binary>-strings.txt output."""
    csv_files = set()
    if OUTPUT_DIR.exists():
        for root, _, files in os.walk(str(OUTPUT_DIR)):
            for file in files:
                lower = file.lower()
                if "potential_indicators.csv" in lower:
                    continue
                if lower.endswith(".csv") or lower.endswith(".txt"):
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

SOURCE_PATH = ""  # set per run; used to locate sibling disassembly/symbols

def process_entry(idx, entries):
    """Scans one (file, string) entry for indicators and vulnerabilities."""
    file_path, string = entries[idx]
    if not string:
        return

    # Context window: query/predicate templates are only dangerous when
    # seen assembled - show the neighborhood around every match.
    lo = max(0, idx - 3)
    hi = min(len(entries), idx + 4)
    context = "\n".join(s for _, s in entries[lo:hi])

    entropy_scan = not any(file_path.endswith(ext) for ext in EXCLUDE_FROM_ENTROPY)

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

    # Vulnerability-oriented rules: (rule, entropy_bonus) pairs.
    row_vulns = []
    for rule in VULN_RULES:
        if rule["pattern"].search(string):
            row_vulns.append((rule, False))

    # Key-material heuristic: high-entropy base64 blobs that decode to a
    # plausible key size (16/24/32/48/64 bytes).
    import base64 as _b64
    for m in BASE64_BLOB.finditer(string):
        blob = m.group(0)
        ent = shannon_entropy(blob)
        if ent >= 4.5:
            try:
                raw = _b64.b64decode(blob + "=" * (-len(blob) % 4))
            except Exception:
                continue
            if len(raw) in (16, 24, 32, 48, 64):
                row_vulns.append(({
                    "id": "key-material-blob", "vuln": "Possible key material", "severity": "high",
                    "cwe": "CWE-321",
                    "why": f"entropy {ent:.2f}, decodes to {len(raw)} bytes - key/secret-sized high-entropy blob",
                }, True))

    # Optional YARA rules (./rules/*.yar, requires yara-python).
    if _yara_rules is not None:
        try:
            for m in _yara_rules.match(data=string.encode("utf-8", "replace"), timeout=2):
                row_vulns.append(({
                    "id": f"yara:{m.rule}", "vuln": f"YARA: {m.rule}", "severity": "high",
                    "cwe": "-", "why": f"matched custom YARA rule '{m.rule}'",
                }, False))
        except Exception:
            pass

    if row_vulns:
        xrefs = find_code_xrefs(string, SOURCE_PATH)
        with results_lock:
            for rule, ent_bonus in row_vulns:
                key = (rule["id"], file_path, string)
                if key in vuln_seen:
                    continue
                vuln_seen.add(key)
                vuln_findings.append({
                    "rule": rule["id"], "vuln": rule["vuln"], "severity": rule["severity"],
                    "cwe": rule["cwe"], "why": rule["why"],
                    "next": RULE_NEXT.get(rule["id"], "Review the match in context"),
                    "confidence": score_confidence(rule["severity"], context, ent_bonus),
                    "xref": xrefs,
                    "context": " | ".join(s for _, s in entries[lo:hi])[:300],
                    "file": file_path, "string": string,
                })

def analyze_csv(file_path):
    """Processes a CSV (or plain strings .txt) with multi-threading."""
    if not os.path.exists(file_path):
        console.print(f"[red]❌ Error: File not found -> {escape(file_path)}[/]")
        return

    global findings, vuln_findings, vuln_seen, SOURCE_PATH
    SOURCE_PATH = file_path
    findings = {category: [] for category in SUSPICIOUS_INDICATORS.keys()}
    vuln_findings = []
    vuln_seen = set()

    indicators_output = os.path.join(os.path.dirname(file_path), "potential_indicators.csv")
    console.print(f"[cyan]🔍 Scanning: {escape(file_path)}[/]")

    # Load (file, string) entries up front so matches can carry context.
    entries = []
    if file_path.lower().endswith(".txt"):
        base = os.path.basename(file_path)
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if line.strip():
                    entries.append((base, line))
    else:
        with open(file_path, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            schema = detect_csv_schema(reader.fieldnames)
            if schema is None:
                console.print("[yellow]⚠ Unrecognized CSV schema; attempting best-effort scan (looking for a 'string' column).[/]")
            for row in reader:
                f, s = normalize_row(row, schema)
                if s:
                    entries.append((f, s))

    with Progress() as progress:
        task = progress.add_task("[cyan]Processing entries, please wait...", total=len(entries))

        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(process_entry, i, entries) for i in range(len(entries))]
            for future in as_completed(futures):
                future.result()
                progress.update(task, advance=1)

    display_findings(findings, indicators_output)

    # Optional live verification of discovered endpoints (network requests).
    urls = []
    for v in vuln_findings:
        if v["rule"] in ("api-endpoint", "url-credentials", "url-secret-param"):
            m = re.search(r"https?://\S+", v["string"])
            if m:
                urls.append(m.group(0))
    if urls:
        ans = Prompt.ask(
            f"[bold cyan]Probe {len(set(urls))} discovered endpoint(s) now?[/] (live network request)",
            choices=["y", "n"], default="n")
        if ans == "y":
            probe_endpoints(urls)

def display_findings(findings, output_csv):
    """Displays results in a structured table and saves to a CSV file."""
    found_something = False
    all_results = []

    # Vulnerability findings first, sorted by severity then confidence.
    sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    conf_order = {"high": 0, "medium": 1, "low": 2}
    vulns = sorted(vuln_findings, key=lambda v: (sev_order.get(v["severity"], 9),
                                                conf_order.get(v["confidence"], 9), v["rule"]))
    if vulns:
        found_something = True
        table = Table(title=escape("🧩 Potential Vulnerabilities (pattern-matched)"), show_header=True, header_style="bold red")
        table.add_column("Sev", style="red", no_wrap=True)
        table.add_column("Conf", style="magenta", no_wrap=True)
        table.add_column("Vulnerability", style="magenta")
        table.add_column("String", style="yellow")
        table.add_column("Why → Next step", style="white")
        table.add_column("Code xref", style="green")
        for v in vulns:
            short = v["string"] if len(v["string"]) <= 55 else v["string"][:55] + "..."
            why_next = escape(v["why"]) + "\n→ " + escape(v["next"])
            table.add_row(
                v["severity"].upper(), v["confidence"].upper(),
                escape(f"{v['vuln']} [{v['cwe']}]"), escape(short),
                why_next, escape(v["xref"] or "-"),
            )
            all_results.append({
                "category": v["rule"], "severity": v["severity"], "confidence": v["confidence"],
                "vuln": v["vuln"], "rule": v["rule"], "cwe": v["cwe"], "why": v["why"],
                "next": v["next"], "xref": v["xref"], "context": v.get("context", ""),
                "file": v["file"], "string": v["string"],
            })
        console.print(table)

    for category, results in findings.items():
        if results:
            found_something = True
            table = Table(title=escape(f"🚨 {category} Detected"), show_header=True, header_style="bold red")
            table.add_column("File", style="cyan", no_wrap=True)
            table.add_column("Suspicious String", style="yellow")

            for file, string in results:
                short = string if len(string) <= 80 else string[:80] + "..."
                table.add_row(escape(file or ""), escape(short or ""))
                all_results.append({
                    "category": category, "severity": "info", "confidence": "",
                    "vuln": category, "rule": "", "cwe": "", "why": "",
                    "next": "", "xref": "", "context": "",
                    "file": file, "string": string,
                })

            console.print(table)

    if found_something:
        save_findings_to_csv(all_results, output_csv)
    else:
        console.print("[green]✅ No suspicious indicators found![/]")

def save_findings_to_csv(results, output_csv):
    """Saves findings to potential_indicators.csv."""
    fields = ["category", "severity", "confidence", "vuln", "rule", "cwe",
              "why", "next", "xref", "context", "file", "string"]
    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)

    console.print(f"[bold green]✅ Findings saved to:[/] {escape(output_csv)}")
    input("Press Enter to continue...")

def main():
    console.print("\n[bold magenta]🔎 Mobile String Indicator & Vulnerability Scanner 🔍[/]\n")
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

# Semgrep Android Security Scanner

**Scan Android codebases for security vulnerabilities using Semgrep with specialized Android security rules. Generates both JSON and beautiful HTML reports with syntax highlighting.**

## Features

- **APK Selection** with fuzzy search and autocomplete
- **Automatic Decompilation** using jadx-cli with deobfuscation
- **Progress Indicators** with animated spinners during scanning
- **Android-Specific Rules** from mindedsecurity/semgrep-rules-android-security
- **Dual Report Format**: JSON for tooling + styled HTML for humans
- **Syntax Highlighting** with highlight.js (Java, Kotlin, XML)
- **Severity Classification**: HIGH, MEDIUM, LOW based on OWASP impact
- **Code Snippets** extracted and displayed with line numbers
- **Organized Reports** saved to `reports/<package_or_codebase_name>/`

## Modes

### `scan` - APK Mode
1. Displays all APKs from `src/pulled_apks` with fuzzy search
2. Decompiles the selected APK using jadx (with deobfuscation)
3. Runs Semgrep security scan with **progress indicator**
4. Saves JSON + HTML reports to `reports/<APK_PACKAGE_NAME>/`

### `code` - Codebase Mode
1. Opens a GUI file dialog to select a directory
2. Runs Semgrep security scan with **progress indicator**
3. Saves JSON + HTML reports to `reports/<CODEBASE_NAME>/`

## Requirements

| Dependency | Required For | Installation |
|------------|--------------|--------------|
| git | Both modes | Pre-installed on macOS |
| semgrep | Both modes | `brew install semgrep` or `pip install semgrep` |
| jadx | `scan` mode | `brew install jadx` |
| rich | APK selection UI | `pip install rich` |
| prompt_toolkit | APK selection UI | `pip install prompt_toolkit` |

### Quick Install

```bash
# macOS
brew install semgrep jadx

# Python dependencies
pip install rich prompt_toolkit
```

## Usage

```bash
# APK Mode - Select from pulled APKs, decompile with jadx, and scan
python semgrep_scan.py scan

# Codebase Mode - Select directory via GUI dialog
python semgrep_scan.py code

# With verbose output
python semgrep_scan.py scan --verbose
python semgrep_scan.py code --verbose
```

## Example Workflow

### APK Mode (`scan`)
```
$ python semgrep_scan.py scan

📱 Semgrep Android Security Scanner
APK selection mode - select an APK to decompile and scan

✅ jadx found: /opt/homebrew/bin/jadx
🔍 Scanning for APKs...
📦 Found 3 APK files

┌──────────────────────────────────────────────────────────┐
│ Index │ APK Name              │ Full Path                │
├───────┼───────────────────────┼──────────────────────────┤
│   1   │ com.example.app.apk   │ src/output/pulled_apks/  │
│   2   │ target-app.apk        │ src/output/pulled_apks/  │
│   3   │ vulnerable.apk        │ src/                     │
└──────────────────────────────────────────────────────────┘

💡 You can either:
  • Type a number (e.g., '1', '2', '3')
  • Start typing an APK name for fuzzy search
  • Use Tab for autocompletion

Enter # or start typing name: 1

🎯 Selected: com.example.app.apk
📁 Output directory: reports/com.example.app
📦 Decompiling APK: com.example.app.apk
✅ Decompilation complete

🔄 Cloning Android security rules... ✅ Rules cloned successfully

🔍 Running Semgrep security scan...
This may take several minutes depending on codebase size

⠸ Scanning files... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ analyzing...

┌──────────────── Scan Results ────────────────┐
│ ✅ Scan Complete!                            │
│                                              │
│ Total Findings: 23                           │
│ Errors: 2                                    │
│                                              │
│ Severity Breakdown:                          │
│   • HIGH: 5                                  │
│   • MEDIUM: 12                               │
│   • LOW: 6                                   │
└──────────────────────────────────────────────┘

✅ HTML report saved

✅ Scan complete!

📊 Reports saved to:
   JSON: reports/com.example.app/semgrep_findings_20260129_150000.json
   HTML: reports/com.example.app/semgrep_findings_20260129_150000.html
```

## HTML Report Features

The generated HTML report includes:

- **Summary Cards** showing HIGH/MEDIUM/LOW counts
- **Findings grouped by Rule** (MSTG-*, CWE-*, etc.)
- **Collapsible sections** for easy navigation
- **Syntax highlighted code** with line numbers
- **Confidence badges** and OWASP Mobile references
- **Dark theme** optimized for readability

## What It Detects

- Hardcoded secrets and API keys
- Insecure cryptographic implementations
- SQL injection vulnerabilities
- Insecure data storage (SharedPreferences, files)
- Improper certificate validation
- WebView security issues
- Intent injection vulnerabilities
- Insecure broadcast receivers
- Logging sensitive data
- And many more Android-specific security issues

## Output Structure

```
Mobile-RE-Toolkit/
└── reports/
    ├── com.example.app/                       # APK scan results
    │   ├── sources/                           # Decompiled Java/Kotlin code
    │   │   ├── com/
    │   │   ├── resources/
    │   │   └── ...
    │   ├── semgrep_findings_20260129_150000.json   # Machine-readable
    │   └── semgrep_findings_20260129_150000.html   # Human-readable
    │
    └── my-android-project/                    # Codebase scan results
        ├── semgrep_findings_20260129_160000.json
        └── semgrep_findings_20260129_160000.html
```

## Notes

- The rules repository is temporarily cloned and deleted after each scan
- Decompiled APKs are preserved in `src/output/semgrep/<apk_name>/sources/` for manual review
- jadx's `--deobf` flag is enabled for better readability of obfuscated code
- HTML reports auto-expand the first 3 rule groups on page load

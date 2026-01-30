# MobSF Scan

**Automated mobile security analysis using MobSF (Mobile Security Framework)**

## Overview

This script provides a streamlined interface to MobSF for automated security analysis of Android APKs and iOS IPAs. It handles the complete workflow from starting the MobSF container to generating detailed security reports.

## Features

- **Docker Integration**: Automatically pulls and manages MobSF Docker container
- **Interactive File Selection**: Rich table with fuzzy search for APK/IPA selection
- **Automated Scanning**: Uploads files to MobSF and triggers security analysis
- **Report Generation**: Creates JSON, HTML, and PDF reports
- **API Key Management**: Saves API key for future sessions (no re-entry needed)
- **Cross-Platform**: Supports both Android (APK) and iOS (IPA) files

## Requirements

- **Docker**: Must be installed and running
- **Python packages**: `requests`, `rich`, `prompt-toolkit`

## Usage

Run without arguments - the script will guide you through file selection:

```bash
python mobsf_scan.py
```

## Workflow

1. **Start MobSF**: Pulls/starts the Docker container (or connects to existing instance)
2. **API Key**: Retrieves API key automatically or prompts for manual entry
3. **File Selection**: Shows available APK/IPA files with fuzzy search
4. **Upload & Scan**: Uploads selected file and runs security analysis
5. **Reports**: Generates and saves reports to `reports/mobsf_reports/<app_name>/`

## Output

Reports are saved to:
```
Mobile-RE-Toolkit/reports/mobsf_reports/<app_name>/
├── <app_name>_mobsf_report.json    # Full JSON report
├── <app_name>_mobsf_report.html    # Styled HTML report
└── <app_name>_mobsf_report.pdf     # PDF report (if available)
```

## Configuration

The API key is automatically saved to `.mobsf_config` for future use. You can also set it via environment variable:

```bash
export MOBSF_API_KEY="your-api-key-here"
```

## MobSF Web Interface

After starting, MobSF is accessible at `http://127.0.0.1:8000` (or next available port) for manual analysis, viewing detailed results, and additional features.

## Supported Analysis

MobSF performs comprehensive security analysis including:

- **Static Analysis**: Code review, manifest analysis, permissions audit
- **Security Scoring**: Overall security rating with detailed breakdown
- **Vulnerability Detection**: Known security issues and misconfigurations
- **Malware Analysis**: Detection of malicious patterns and behaviors
- **Certificate Analysis**: Signing certificate validation
- **API Analysis**: Sensitive API usage detection

## Notes

- First run may take a few minutes to pull the MobSF Docker image
- Large APKs/IPAs may take several minutes to scan
- MobSF container persists between runs for faster subsequent scans

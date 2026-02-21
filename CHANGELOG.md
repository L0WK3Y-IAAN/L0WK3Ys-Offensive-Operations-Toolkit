## Changelog

All notable changes to **L0WK3Y's Offensive Operations Toolkit (LOOT)** are documented in this file.

Dates use `YYYY‑MM‑DD` and entries are listed in chronological order from the initial public release.

---

## 2026-01-30 – Initial Release & Early Polish

- **Initial LOOT release** (`a461aa8`)
  - First public version of **L0WK3Y’s Offensive Operations Toolkit (LOOT)**.
  - Introduced the root LOOT launcher and initial toolkit layout (e.g. Mobile RE Toolkit, Geiger, etc.).
  - Added base documentation in `README.md`.

- **Geiger documentation & credits** (`073f16b`, `0053e7c`)
  - Updated **Geiger** README with clearer usage information.
  - Updated Geiger description in the root `README.md`.
  - Added explicit credit to **reAVS** and its author for static analysis capabilities used by Geiger.

- **Visual assets & branding** (`e426c0d`, `2549cb5`, `e862451`)
  - Added early demo GIF assets showcasing toolkit behaviour.
  - Replaced the static LOOT logo with an animated **glitch LOOT logo** for a more distinctive brand.

- **README layout & screenshot tweaks** (`971be62`, `5a40cef`)
  - Removed an outdated “LOOT Launcher” section from `README.md`.
  - Adjusted screenshot width (from 400px to 1000px) to improve visibility and readability on modern displays.

---

## 2026-01-31 – Demos, Geiger Improvements, Donations

- **Geiger demo and demos section** (`dec3fb4`, `fe5f6d3`, `dc697dc`)
  - Added animated **Geiger demo GIF** to better illustrate Geiger’s behaviour.
  - Added a **Screenshots** section (later renamed to **Demos**) to the root `README.md`.
  - Cleaned up media by removing a redundant static image while keeping high‑signal GIFs.

- **Verbose reAVS logging in Geiger** (`1e908ba`)
  - Integrated the rich **reAVS** console logging into **Geiger**:
    - Live streaming of reAVS scan output during taint analysis.
    - Severity‑aware, color‑coded log messages to highlight CRITICAL/HIGH findings.
  - Enabled Geiger to show reAVS results inline with nuclei findings for a unified report.

- **Donations & toolkit overview improvements** (`5848c81`, `e94f86d`, `6a5f52c`)
  - Added a **Donations** section/page to the project documentation.
  - Refined the **“Included Toolkits”** section in `README.md` to more clearly describe the scope of LOOT and its sub‑tools.
  - Performed additional wording/layout tweaks to improve the first‑time overview of the project.

- **Semgrep Scan demo** (`2204bda`)
  - Added a **Semgrep Scan demo GIF** showing the Semgrep integration in the Mobile RE Toolkit.
  - Demonstrated the APK/codebase selection, scanning flow, and report generation.

- **Sponsor button removal** (`dc89aaa`)
  - Removed `.github/FUNDING.yml` and the GitHub **Sponsor** button.
  - Ensured the repository’s support model matched personal/project preferences.

---

## 2026-02-01 – Jadx UX & Launcher / MRET Hardening

- **Open In Jadx: correct APK discovery & deduplication** (`b935aac`)
  - Fixed **`Open In Jadx`** to reliably find APKs regardless of where it is launched from:
    - Added a robust toolkit‑root resolver that locates `Mobile-RE-Toolkit` by walking upward to find `main.py` and `src/`.
    - Updated search paths to use absolute locations:
      - `Mobile-RE-Toolkit/`
      - `Mobile-RE-Toolkit/src/`
      - `Mobile-RE-Toolkit/src/output/pulled_apks/`
  - Implemented **APK deduplication**:
    - Tracks canonical paths (`os.path.realpath`) and only lists each APK once even if discovered via overlapping directories.
    - Prevents duplicate rows like multiple `dont.reload.apk` / `InsecureShop.apk` entries in the Textual/Rich table.

- **LOOT: manual and automatic update checking** (`4a4f8da`)
  - Added git‑aware update helpers:
    - `check_for_updates(repo_root)`:
      - Verifies the repo is a git repository.
      - Runs `git fetch origin` and compares `HEAD` with `origin/<current-branch>`.
      - Detects how many commits the local branch is **behind** and returns a human‑readable message.
    - `pull_updates(repo_root)`:
      - Determines the current branch and runs `git pull origin <branch> --no-edit`.
      - Returns success/failure status and any output or error details.
  - Integrated update actions into the LOOT Textual UI:
    - Added **`U` keybinding** and `action_update`:
      - On `U`, runs `check_for_updates`.
      - If up‑to‑date, shows a small notification (“Already up to date.”).
      - If updates exist, runs `pull_updates` and notifies on success or failure.
    - Updated the status bar to show:  
      `📁 Repo: <path> | 1-5 categories | U update`
  - Implemented **automatic update checks on launch**:
    - Added `on_mount()` to the LOOT app:
      - Calls `check_for_updates` once at startup.
      - If the remote has new commits, shows a notification such as  
        “X new commit(s) on origin/main. Press U to update.”
      - Leaves the actual pull under user control via `U`.

- **MRET launcher: syntax and stability fixes** (`4a4f8da`)
  - Fixed multiple indentation and structural issues in `Mobile-RE-Toolkit/main.py`:
    - **`discover_scripts`**:
      - Corrected placement of the `ThreadPoolExecutor` block so platforms are scanned in parallel and results merged correctly.
      - Repaired the cross‑platform deduplication logic:
        - Uses a `seen_names` map keyed by script name.
        - Merges `supported_platforms` when duplicates are found.
        - Prefers scripts located in **Misc** as the “canonical” entry when merging.
    - **Initialization / on‑mount logic**:
      - Ensured `organize_scripts()` and `scan_wip_and_update_gitignore()` run inside the correct method body.
      - Keeps WIP scripts in dedicated directories and updates `.gitignore` accordingly.
    - **Drag‑and‑drop file import**:
      - Fixed indentation in `on_import_path_submitted` so early returns and notifications behave as expected.
      - Corrected the `try/except` structure so `PermissionError` and generic exceptions are caught separately and reported via Textual notifications.
    - **`__main__` guard**:
      - Ensured `main()` is properly called inside a `try/except KeyboardInterrupt` block so Ctrl+C is handled gracefully.

---

## 2026-02-04 – Hermes Decompiler & Geiger/Windows Improvements

- **Hermes Bytecode Decompiler integration** (`1601dc1`)
  - Added a **Hermes Bytecode Decompiler** tool to support analysis of React Native / Hermes‑based Android apps.
  - Integrated it into the LOOT / MRET structure so it can be launched and tracked like other toolkit modules.

- **Dependencies & Windows compatibility improvements** (`a3b61d3`)
  - Added **GitPython** and other dependency updates to the relevant `requirements.txt` files to support template management and git operations (particularly for Geiger).
  - Improved **Windows compatibility**:
    - Adjusted path handling and virtual‑environment detection to account for Windows directory layouts.
    - Hardened subprocess calls (e.g., shell vs direct invocation) for cross‑platform behaviour.

- **Geiger reliability & tooling fixes** (`e02aad6`)
  - Resolved multiple issues in **Geiger**:
    - Corrected **reAVS path resolution** and virtual environment discovery, especially on Windows.
    - Tuned apktool execution and timeouts to better handle large or complex APKs.
    - Strengthened **nuclei** installation checks:
      - Ensured user‑friendly messaging when nuclei is missing or misconfigured.
      - Reduced silent failures by surfacing stderr details where appropriate.
  - Overall result: more robust end‑to‑end scans when combining apktool, nuclei, and reAVS.

---

## 2026-02-20 – Geiger Report TUI & Hermes Dec Robustness

- **Geiger report TUI and selector** (`report_tui.py`, `report_selector.py`, `geiger/main.py`)
  - Restored and fixed the **Geiger report viewer** (Textual TUI) for JSON reports:
    - **Report selector**: `geiger/utils/report_selector.py` scans `reports/geiger_reports` for `*_report.json`, lists them in a table, and supports selection by number or fuzzy name (prompt_toolkit).
    - **Report TUI** (`geiger/report_tui.py`): DataTable of findings (index, severity, name, file); detail panel with severity, location, snippet, description; file path as a single clickable control that opens the file in Cursor or VS Code with `--goto path:line` when a line is available; **Open in jadx** button that resolves the APK from the report and launches jadx-gui/jadx.
    - Resolves finding paths from class names to extraction smali paths under `src/output/geiger/<apk>_EXTRACTION/apktool`.
  - **CSS and behaviour fixes** for the report TUI:
    - Replaced invalid `text-decoration` with Textual’s `text-style: underline` / `text-style: none`.
    - Set `#detail-file-link` to `min-height: 1` and `height: 1` (no `auto`) to avoid `StyleValueError: 'auto' not allowed here`.
    - Fixed `DataTable.RowSelected` handler to use `event.cursor_row` instead of `event.row_index`.
  - Wired `run_report_tui` into `geiger main.py` so `geiger view` and post-scan report opening use the TUI.

- **Hermes Dec: skip clone when present & support new repo layout** (`Hermes Dec/hermes_dec.py`)
  - **Skip cloning when tool already exists**: If `Tools/hermes-dec` already exists, the script no longer runs `git clone` (avoiding “destination path already exists”). It uses the existing directory and, if the decompiler script is missing, runs `git pull` and re-checks before failing.
  - **Support current hermes-dec repo layout**: The P1sec hermes-dec repo now uses `src/decompilation/`, `src/disassembly/`, `src/parsers/` and root symlinks (`hbc-decompiler`, `hbc-disassembler`, `hbc-file-parser`). Added `_hermes_dec_script_paths(hermes_dir)` to resolve decompiler, disassembler, and parser scripts for both the old flat layout and the new layout, so existing clones work without re-cloning.

---

## 2026-02-21 – Screen Mirror & APK Builder UX

- **Screen Mirror: scrcpy-tool in Mobile-RE-Toolkit/Tools** (`Screen Mirror/screen_mirror.py`)
  - Scrcpy is now installed under **`Mobile-RE-Toolkit/Tools/scrcpy-tool`** instead of the current working directory.
  - Added `_get_toolkit_tools_dir()` to resolve the toolkit root (directory with `main.py` and `src/`) from the script path and return `Tools`; creates the directory if needed. Works regardless of where the script is run from (e.g. MRET launcher or terminal).

- **APK Builder + Installer: auto-select single device** (`Apk Builder + Installer/apk_builder + installer.py`)
  - When only one ADB device is connected, the script **automatically selects it** and skips the device selection prompt.
  - Shows a short message: “Using the only connected device: &lt;serial&gt;”. When multiple devices are connected, the device table and number prompt behave as before.

---

## Unreleased

- (No unreleased changes recorded at this time.)


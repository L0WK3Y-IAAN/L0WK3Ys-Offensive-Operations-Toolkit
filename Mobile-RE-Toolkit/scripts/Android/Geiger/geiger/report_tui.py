"""Textual TUI for viewing Geiger JSON reports."""

import json
import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Static,
    DataTable,
    Button,
    Label,
)
from textual.reactive import reactive
from rich.text import Text
from rich.style import Style

from geiger.utils.apk_selector import scan_multiple_directories


def load_report(path: Path) -> tuple[str, str, list[dict]]:
    """Load report JSON. Returns (apk_name, scan_date, findings)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    apk_name = data.get("apk_name", path.stem.replace("_report", ""))
    scan_date = data.get("scan_date", "")
    findings = data.get("findings", [])
    return apk_name, scan_date, findings


def _snippet_for_finding(f: dict) -> str:
    """Extract a one-line snippet from finding (evidence notes or matched_line)."""
    reavs = f.get("reavs_info") or {}
    evidence = reavs.get("evidence", [])
    for e in evidence:
        notes = e.get("notes")
        if notes:
            return (notes or "").strip()
    sinks = f.get("sinks", [])
    for s in sinks:
        notes = s.get("notes")
        if notes:
            return (notes or "").strip()
    nuclei = f.get("nuclei_info") or {}
    matched = (nuclei.get("matched_line") or "").strip()
    if matched:
        return matched
    return f.get("component", "") or ""


def _get_workspace_from_report_path(report_path: Path) -> Path:
    """Infer workspace root from report path (has reports/geiger_reports)."""
    p = report_path.resolve()
    for parent in p.parents:
        if (parent / "main.py").exists() and (parent / "src").exists():
            return parent
    return p.parents[5] if len(p.parents) > 5 else Path.cwd()


def _extraction_dir_for_report(report_path: Path, apk_name: str) -> Path:
    """Return apktool extraction dir for this report's APK."""
    workspace = _get_workspace_from_report_path(report_path)
    return workspace / "src" / "output" / "geiger" / f"{apk_name}_EXTRACTION" / "apktool"


def _resolve_file_path(
    file_val: str, report_path: Path, apk_name: str
) -> tuple[Optional[Path], Optional[int]]:
    """
    Resolve finding 'file' to (Path, line).
    If file_val is absolute and exists, return (Path, line_or_None).
    Else treat as class name and resolve under extraction to smali path.
    """
    if not file_val:
        return None, None
    # Absolute path that exists
    if file_val.startswith("/"):
        p = Path(file_val)
        if p.exists():
            line = None
            if ":" in file_val:
                try:
                    line = int(file_val.split(":")[-1])
                except ValueError:
                    pass
            return p, line
        return None, None
    # Class name -> smali path under extraction
    ext_dir = _extraction_dir_for_report(report_path, apk_name)
    if not ext_dir.exists():
        return None, None
    class_path = file_val.replace(".", "/") + ".smali"
    for base in ["smali", "smali_classes2", "smali_classes3", "smali_classes4", "smali_classes5", "smali_classes6", "smali_classes7"]:
        candidate = ext_dir / base / class_path
        if candidate.exists():
            return candidate, None
    return None, None


def _find_apk_for_report(report_path: Path, apk_name: str) -> Optional[Path]:
    """Find APK file for this report (same workspace + name match)."""
    workspace = _get_workspace_from_report_path(report_path)
    dirs = [
        workspace / "src",
        workspace / "src" / "output" / "pulled_apks",
    ]
    apks = scan_multiple_directories(dirs)
    stem = apk_name.replace("_EXTRACTION", "").split("_EXTRACTION")[0]
    for apk in apks:
        if apk.stem == stem or apk.stem == apk_name:
            return apk
    for apk in apks:
        if apk_name in apk.stem or stem in apk.stem:
            return apk
    return apks[0] if apks else None


SEVERITY_STYLES = {
    "CRITICAL": Style(bold=True, color="red"),
    "HIGH": Style(color="red"),
    "MEDIUM": Style(color="yellow"),
    "LOW": Style(color="blue"),
    "INFO": Style(dim=True),
}


@dataclass
class FindingRow:
    index: int
    severity: str
    name: str
    file: str
    component: str
    snippet: str
    file_path: Optional[Path]
    line: Optional[int]
    description: str
    source: str


class GeigerReportApp(App[None]):
    """Textual app to view a Geiger JSON report."""

    TITLE = "Geiger Report"
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("j", "jadx", "Open in jadx"),
    ]

    report_path: reactive[Optional[Path]] = reactive(None)
    apk_name = ""
    scan_date = ""
    rows: list[FindingRow] = []

    def __init__(self, report_path: Path, **kwargs):
        super().__init__(**kwargs)
        self.report_path = report_path
        self.apk_name, self.scan_date, findings = load_report(report_path)
        self.rows = []
        for i, f in enumerate(findings):
            file_str = f.get("file", "") or ""
            file_path, line = _resolve_file_path(file_str, report_path, self.apk_name)
            self.rows.append(
                FindingRow(
                    index=i + 1,
                    severity=(f.get("severity") or "INFO").upper(),
                    name=f.get("name", ""),
                    file=file_str,
                    component=f.get("component", ""),
                    snippet=_snippet_for_finding(f),
                    file_path=file_path,
                    line=line,
                    description=f.get("description", ""),
                    source=f.get("source", ""),
                )
            )

    def compose(self) -> ComposeResult:
        header = Static(
            f"[bold]APK:[/bold] {self.apk_name}  [dim]Scan: {self.scan_date}[/dim]",
            id="report-header",
        )
        yield header

        with Container(id="main-container"):
            table = DataTable(id="findings-table", cursor_type="row")
            table.add_columns("#", "Severity", "Name", "File")
            table.cursor_type = "row"
            for r in self.rows:
                sev_text = Text(r.severity, style=SEVERITY_STYLES.get(r.severity, Style()))
                table.add_row(
                    str(r.index),
                    sev_text,
                    r.name[:60] + "..." if len(r.name) > 60 else r.name,
                    (r.file[:50] + "...") if len(r.file) > 50 else r.file,
                )
            yield table

            with Vertical(id="detail-panel"):
                yield Static("Finding detail", id="detail-title")
                yield Static("Select a row", id="detail-placeholder")
                file_link = Button(
                    "",
                    id="detail-file-link",
                    classes="path-link",
                    variant="default",
                )
                file_link.disabled = True
                yield file_link
                yield Label("", id="detail-line")
                yield Static("", id="detail-snippet")
                yield Static("", id="detail-description")
                with Horizontal(id="buttons"):
                    yield Button("Open in jadx", id="jadx-btn", variant="primary")

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.focus()
        if self.rows:
            table.move_cursor(row=0)
            self._refresh_detail(0)

    def _refresh_detail(self, row_index: int) -> None:
        if row_index < 0 or row_index >= len(self.rows):
            return
        r = self.rows[row_index]
        title = self.query_one("#detail-title", Static)
        title.update(f"[bold]#{r.index} {r.name}[/bold]")
        placeholder = self.query_one("#detail-placeholder", Static)
        placeholder.visible = False
        file_link = self.query_one("#detail-file-link", Button)
        line_label = self.query_one("#detail-line", Label)
        snippet_block = self.query_one("#detail-snippet", Static)
        desc_block = self.query_one("#detail-description", Static)

        if r.file_path:
            path_str = str(r.file_path)
            file_link.label = path_str
            file_link.disabled = False
        else:
            file_link.label = r.file or "(no path)"
            file_link.disabled = True
        line_label.update(f"Line: {r.line}" if r.line is not None else "")
        snippet_block.update(r.snippet or "")
        desc_block.update(r.description or "")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_idx = event.cursor_row
        self._refresh_detail(row_idx)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "detail-file-link":
            row_idx = self.query_one("#findings-table", DataTable).cursor_row
            if 0 <= row_idx < len(self.rows):
                r = self.rows[row_idx]
                if r.file_path and not event.button.disabled:
                    path_arg = str(r.file_path)
                    if r.line is not None:
                        path_arg += f":{r.line}"
                    cursor = shutil.which("cursor")
                    if cursor:
                        subprocess.Popen([cursor, "--goto", path_arg], start_new_session=True)
                    else:
                        code = shutil.which("code")
                        if code:
                            subprocess.Popen([code, "--goto", path_arg], start_new_session=True)
            return
        if event.button.id == "jadx-btn":
            self.action_jadx()

    def action_jadx(self) -> None:
        apk = _find_apk_for_report(self.report_path or Path(), self.apk_name)
        if not apk or not apk.exists():
            self.notify("APK not found for this report.", severity="warning")
            return
        jadx_gui = shutil.which("jadx-gui") or shutil.which("jadx")
        if not jadx_gui:
            self.notify("jadx-gui or jadx not in PATH.", severity="error")
            return
        subprocess.Popen([jadx_gui, str(apk)], start_new_session=True)
        self.notify(f"Opening {apk.name} in jadx.")

    CSS = """
    Screen {
        layout: vertical;
    }
    #report-header {
        padding: 0 1 1 0;
        border-bottom: solid #333;
    }
    #main-container {
        layout: horizontal;
        height: 1fr;
        min-height: 8;
    }
    #findings-table {
        width: 1fr;
        height: 1fr;
        min-height: 8;
        scrollbar-size: 1 1;
    }
    #detail-panel {
        width: 50%;
        max-width: 60;
        height: 1fr;
        min-height: 8;
        padding: 0 1 0 1;
        border-left: solid #333;
        layout: vertical;
    }
    #detail-title {
        padding: 0 0 1 0;
        border-bottom: solid #333;
    }
    #detail-placeholder {
        color: #888;
    }
    #detail-file-link {
        width: 100%;
        min-height: 1;
        height: 1;
        padding: 0 0 1 0;
        border: none;
        background: transparent;
        color: #aed6f1;
        text-style: underline;
    }
    #detail-file-link:hover {
        background: transparent;
        color: #5dade2;
    }
    #detail-file-link:disabled {
        text-style: none;
        color: #aab7b8;
    }
    #detail-snippet {
        padding: 1 0;
        border-bottom: solid #333;
        margin-bottom: 1;
        color: #bdc3c7;
    }
    #buttons {
        height: auto;
        padding: 1 0 0 0;
    }
    #buttons Button {
        margin: 0 1 0 0;
        min-width: 18;
    }
    .severity-critical { color: #ff6b6b; text-style: bold; }
    .severity-high    { color: #ee5a5a; text-style: bold; }
    .severity-medium  { color: #f7dc6f; }
    .severity-low     { color: #5dade2; }
    .severity-info    { color: #aab7b8; }
    """


def run_report_tui(report_path: Path) -> None:
    """Run the Geiger report TUI for the given report JSON path."""
    app = GeigerReportApp(report_path)
    app.run()

"""Report selection for Geiger TUI viewer"""

from pathlib import Path
from typing import Optional, List

from rich.console import Console
from rich.table import Table
from prompt_toolkit import prompt as pt_prompt
from prompt_toolkit.completion import Completer, Completion, FuzzyCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.validation import Validator, ValidationError

console = Console()


def _scan_reports(reports_dir: Path) -> List[Path]:
    """Find all *_report.json under reports_dir (one level of subdirs)."""
    out: List[Path] = []
    if not reports_dir.exists() or not reports_dir.is_dir():
        return out
    for path in reports_dir.iterdir():
        if path.is_dir():
            for f in path.glob("*_report.json"):
                if f.is_file():
                    out.append(f.resolve())
        elif path.suffix == ".json" and "_report" in path.stem:
            out.append(path.resolve())
    out.sort(key=lambda p: (p.parent.name, p.name))
    return out


class ReportCompleter(Completer):
    """Completer for report index or fuzzy report name."""

    def __init__(self, report_paths: List[Path]):
        self.report_paths = report_paths
        self.names = [p.stem.replace("_report", "") for p in report_paths]

    def get_completions(self, document, complete_event):
        text = document.text.strip()
        if text.isdigit():
            idx = int(text)
            if 1 <= idx <= len(self.report_paths):
                yield Completion(text, start_position=-len(text), display=f"#{idx}")
            return
        lower = text.lower()
        for i, name in enumerate(self.names):
            if not text or lower in name.lower():
                yield Completion(name, start_position=-len(text), display=name)


class NumberOrNameValidator(Validator):
    def __init__(self, count: int, names: List[str]):
        self.count = count
        self.names = set(names)

    def validate(self, document):
        t = document.text.strip()
        if not t:
            raise ValidationError(message="Type # or report name")
        if t.isdigit():
            idx = int(t)
            if 1 <= idx <= self.count:
                return
            raise ValidationError(message=f"Number must be 1..{self.count}")


def select_report(reports_dir: Path) -> Optional[Path]:
    """
    Interactive report selection. Scans reports_dir for *_report.json.

    Returns:
        Selected report JSON Path or None if cancelled / none found.
    """
    console.print("[bold cyan]Geiger - Report Selector[/bold cyan]\n")
    reports = _scan_reports(reports_dir)
    if not reports:
        console.print(f"[red]No reports found in {reports_dir}[/red]")
        return None

    console.print(f"[cyan]Scanning: {reports_dir}[/cyan]")
    console.print(f"[green]Found {len(reports)} report(s)[/green]\n")

    table = Table(title="Reports", show_header=True, header_style="bold magenta")
    table.add_column("#", justify="right", style="cyan", width=4)
    table.add_column("Report", style="green")
    table.add_column("Path", style="dim", overflow="ellipsis")
    for i, p in enumerate(reports, 1):
        name = p.stem.replace("_report", "")
        table.add_row(str(i), name, str(p))
    console.print(table)

    names = [p.stem.replace("_report", "") for p in reports]
    completer = FuzzyCompleter(ReportCompleter(reports))
    validator = NumberOrNameValidator(len(reports), names)

    console.print("\n[cyan]Enter # or report name:[/cyan] ")
    try:
        answer = pt_prompt(
            HTML("<cyan># or name: </cyan>"),
            completer=completer,
            complete_while_typing=True,
            validator=validator,
            validate_while_typing=True,
        ).strip()
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled.[/yellow]")
        return None

    if answer.isdigit():
        selected = reports[int(answer) - 1]
    else:
        lower = answer.lower()
        selected = None
        for p in reports:
            if lower in p.stem.replace("_report", "").lower():
                selected = p
                break
        if selected is None:
            selected = reports[0]

    console.print(f"\n[green]Selected: {selected.name}[/green]")
    console.print(f"[dim]{selected}[/dim]\n")
    return selected

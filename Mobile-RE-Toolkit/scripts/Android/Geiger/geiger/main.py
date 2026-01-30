"""Main CLI entry point for Geiger"""

import sys
from pathlib import Path
from typing import Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
from rich.panel import Panel

from geiger.config import DEFAULT_OUTPUT_DIR, DEFAULT_THREADS
from geiger.core.templates import TemplateManager
from geiger.core.decompiler import Decompiler
from geiger.core.scanner import NucleiScanner
from geiger.core.reavs_scanner import ReavsScanner
from geiger.utils.output import print_findings_table, save_json_report, save_html_report
from geiger.utils.cleanup import cleanup_directory
from geiger.utils.apk_selector import select_apk
from geiger.utils.nuclei_installer import ensure_nuclei_installed

app = typer.Typer(
    name="geiger",
    help="🔍 Android APK static analysis tool using apktool and nuclei",
    add_completion=False
)
console = Console()

def _get_workspace_root() -> Path:
    """
    Best-effort workspace root discovery so we can place persistent extraction output in
    src/output/geiger regardless of the current working directory.
    """
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "main.py").exists() and (parent / "src").exists():
            return parent
    # Fallback: project root is typically 5 levels up from geiger/main.py
    return current.parents[5] if len(current.parents) > 5 else Path.cwd()


DEFAULT_EXTRACTION_DIR = _get_workspace_root() / "src" / "output" / "geiger"
DEFAULT_EXTRACTION_DIR.mkdir(parents=True, exist_ok=True)


def scan_single_apk(
    apk_path: Path,
    output_dir: Path,
    templates_dir: Path,
    keep_source: bool,
    use_jadx: bool,
    use_reavs: bool = False
) -> tuple[Path, List[dict], Optional[str]]:
    """
    Scan a single APK file.
    
    Returns:
        Tuple of (apk_path, findings, error_message)
    """
    try:
        # Initialize components
        decompiler = Decompiler()
        scanner = NucleiScanner(templates_dir)
        
        # Initialize reAVS scanner if requested
        reavs_scanner = None
        if use_reavs:
            reavs_scanner = ReavsScanner(auto_setup=True)  # Auto-clone from GitHub if not found
            if not reavs_scanner.is_available():
                console.print("[yellow]⚠ reAVS not available. Continuing with nuclei scan only.[/yellow]")
                reavs_scanner = None
        
        # Decompile
        apk_name = apk_path.stem
        # Reports go here:
        base_output = output_dir / apk_name
        # Persistent extraction cache goes here:
        extraction_base = DEFAULT_EXTRACTION_DIR / f"{apk_name}_EXTRACTION"
        
        apktool_dir, jadx_dir, decomp_error = decompiler.decompile(
            apk_path,
            extraction_base,
            use_jadx=use_jadx,
            keep_source=True  # cached extractions are always kept
        )
        
        if decomp_error:
            return apk_path, [], decomp_error
        
        # Scan with nuclei (use apktool output as it has smali files)
        findings = scanner.scan(apktool_dir)
        
        # Scan with reAVS if available (taint analysis)
        if reavs_scanner and reavs_scanner.is_available():
            console.print("[cyan]Running reAVS taint analysis...[/cyan]")
            reavs_findings = reavs_scanner.scan(apk_path, deep=True, depth=3)
            
            if reavs_findings:
                # Convert reAVS findings to nuclei format and merge
                converted_findings = ReavsScanner.convert_findings_to_nuclei_format(reavs_findings)
                findings.extend(converted_findings)
                console.print(f"[green]✓ reAVS found {len(reavs_findings)} additional findings[/green]")
        
        # Always save reports (JSON and HTML)
        if findings:
            # Ensure base_output directory exists
            base_output.mkdir(parents=True, exist_ok=True)
            json_path = base_output / f"{apk_name}_report.json"
            html_path = base_output / f"{apk_name}_report.html"
            if save_json_report(findings, json_path, apk_name):
                console.print(f"[green]✓ JSON report saved: {json_path}[/green]")
            if save_html_report(findings, html_path, apk_name):
                console.print(f"[green]✓ HTML report saved: {html_path}[/green]")
        
        # Note: extraction is cached under src/output/geiger/ and intentionally not deleted.
        
        return apk_path, findings, None
        
    except Exception as e:
        return apk_path, [], str(e)


@app.command()
def scan(
    target: Optional[Path] = typer.Argument(None, help="APK file or directory containing APKs (optional - will show interactive selector if not provided)"),
    output: Path = typer.Option(
        DEFAULT_OUTPUT_DIR,
        "--output", "-o",
        help="Output directory for reports"
    ),
    keep_source: bool = typer.Option(
        False,
        "--keep-source",
        help="Keep decompiled source files after scanning"
    ),
    use_jadx: bool = typer.Option(
        True,
        "--use-jadx/--no-jadx",
        help="Also decompile with jadx for Java source (if available)"
    ),
    threads: int = typer.Option(
        DEFAULT_THREADS,
        "--threads", "-t",
        help="Number of parallel threads for batch scanning"
    ),
    update_templates: bool = typer.Option(
        True,
        "--update-templates/--no-update-templates",
        help="Update nuclei templates before scanning"
    ),
    use_reavs: bool = typer.Option(
        False,
        "--reavs/--no-reavs",
        help="Also run reAVS taint analysis for deeper vulnerability detection"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Verbose output"
    )
):
    """
    Scan APK file(s) for vulnerabilities using apktool and nuclei.
    
    If no target is provided, an interactive APK selector will be shown.
    
    Examples:
    
    \b
    # Interactive APK selection
    geiger scan
    
    \b
    # Scan single APK
    geiger scan app.apk
    
    \b
    # Scan directory of APKs with custom output
    geiger scan ./apks/ -o ./reports/ --threads 8
    
    \b
    # Keep decompiled source files
    geiger scan app.apk --keep-source
    """
    # If no target provided, show interactive selector
    if target is None:
        selected_apk = select_apk()
        if selected_apk is None:
            console.print("[yellow]No APK selected. Exiting.[/yellow]")
            sys.exit(0)
        target = selected_apk
    
    # Ensure nuclei is installed first
    console.print("[cyan]🔍 Checking for nuclei...[/cyan]")
    nuclei_path = ensure_nuclei_installed(install_if_missing=True)
    if not nuclei_path:
        console.print("[red]✗ Nuclei is required but could not be installed. Exiting.[/red]")
        sys.exit(1)
    
    # Ensure templates are available
    template_manager = TemplateManager()
    if not template_manager.ensure_templates(update=update_templates):
        console.print("[red]✗ Failed to setup templates. Exiting.[/red]")
        sys.exit(1)
    
    templates_dir = template_manager.get_template_path()
    if not templates_dir:
        console.print("[red]✗ Templates directory not found. Exiting.[/red]")
        sys.exit(1)
    
    template_count = template_manager.template_count()
    console.print(f"[green]✓ Using {template_count} nuclei templates[/green]")
    
    # Collect APK files
    apk_files: List[Path] = []
    
    if target.is_file():
        if target.suffix.lower() != ".apk":
            console.print(f"[red]✗ {target} is not an APK file[/red]")
            sys.exit(1)
        apk_files = [target]
    elif target.is_dir():
        apk_files = list(target.glob("*.apk"))
        if not apk_files:
            console.print(f"[red]✗ No APK files found in {target}[/red]")
            sys.exit(1)
        console.print(f"[cyan]Found {len(apk_files)} APK file(s)[/cyan]")
    else:
        console.print(f"[red]✗ Target does not exist: {target}[/red]")
        sys.exit(1)
    
    # Create output directory
    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Reports are always generated (JSON and HTML)
    
    # Scan APKs
    all_findings = {}
    errors = {}
    
    if len(apk_files) == 1:
        # Single APK - no need for threading
        apk_path = apk_files[0]
        console.print(Panel.fit(f"[bold cyan]Scanning: {apk_path.name}[/bold cyan]"))
        
        apk_path, findings, error = scan_single_apk(
            apk_path,
            output_dir,
            templates_dir,
            keep_source,
            use_jadx,
            use_reavs
        )
        
        all_findings[apk_path] = findings
        if error:
            errors[apk_path] = error
        
        # Print results
        console.print(f"\n[bold]Results for {apk_path.name}:[/bold]")
        print_findings_table(findings, apk_path.stem)
        
    else:
        # Multiple APKs - use parallel processing
        console.print(f"[cyan]Scanning {len(apk_files)} APKs with {threads} threads...[/cyan]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Scanning APKs...", total=len(apk_files))
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_apk = {
                    executor.submit(
                        scan_single_apk,
                        apk_path,
                        output_dir,
                        templates_dir,
                        keep_source,
                        use_jadx,
                        use_reavs
                    ): apk_path
                    for apk_path in apk_files
                }
                
                for future in as_completed(future_to_apk):
                    apk_path = future_to_apk[future]
                    try:
                        apk_path, findings, error = future.result()
                        all_findings[apk_path] = findings
                        if error:
                            errors[apk_path] = error
                        progress.update(task, advance=1)
                    except Exception as e:
                        errors[apk_path] = str(e)
                        progress.update(task, advance=1)
    
    # Print summary
    total_findings = sum(len(f) for f in all_findings.values())
    total_errors = len(errors)
    
    console.print("\n" + "="*60)
    console.print(Panel.fit(
        f"[bold]Scan Complete[/bold]\n\n"
        f"APKs Scanned: {len(apk_files)}\n"
        f"Total Findings: {total_findings}\n"
        f"Errors: {total_errors}",
        border_style="green" if total_errors == 0 else "yellow"
    ))
    
    if errors:
        console.print("\n[bold red]Errors:[/bold red]")
        for apk_path, error in errors.items():
            console.print(f"  [red]✗ {apk_path.name}: {error}[/red]")
    
    # Exit with appropriate code
    if total_errors > 0:
        sys.exit(1)
    elif total_findings > 0:
        sys.exit(2)  # Findings found
    else:
        sys.exit(0)  # No findings


@app.command()
def templates(
    update: bool = typer.Option(
        True,
        "--update/--no-update",
        help="Update templates if they already exist"
    )
):
    """
    Manage nuclei templates repository.
    
    Clones or updates the mobile-nuclei-templates repository.
    """
    template_manager = TemplateManager()
    
    if template_manager.ensure_templates(update=update):
        template_count = template_manager.template_count()
        console.print(f"[green]✓ Templates ready: {template_count} templates available[/green]")
        console.print(f"[dim]Location: {template_manager.templates_dir}[/dim]")
    else:
        console.print("[red]✗ Failed to setup templates[/red]")
        sys.exit(1)


def main():
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Cancelled by user[/yellow]")
        raise SystemExit(0)

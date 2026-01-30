"""Output formatting with rich"""

import json
import re
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


def _extract_class_name_from_path(file_path: str) -> str:
    """
    Extract class name from a file path (smali or java).
    
    Examples:
      "/path/to/smali/b3nac/injuredandroid/MainActivity.smali" -> "b3nac.injuredandroid.MainActivity"
      "/path/to/smali/b/b/d.smali" -> "b.b.d"
      "com.dns.insecurepass.AccountDetailsView" -> "com.dns.insecurepass.AccountDetailsView" (already a class name)
    """
    if not file_path:
        return ""
    
    # If it's already a class name (no slashes, has dots), return as-is
    if "/" not in file_path and "." in file_path:
        return file_path
    
    # Extract from file path
    path = Path(file_path)
    
    # For smali files: convert path to class name
    if path.suffix == ".smali":
        # Find the smali or smali_classesX directory in the path
        path_str = str(path)
        smali_pattern = re.search(r'/(smali(?:_classes\d+)?)/(.+)\.smali$', path_str)
        if smali_pattern:
            # Extract everything after smali/smali_classesX and convert / to .
            relative_path = smali_pattern.group(2)
            return relative_path.replace("/", ".")
        # Fallback: try to extract from the end of the path
        parts = path.parts
        for i, part in enumerate(parts):
            if part.startswith("smali"):
                # Get everything after this directory
                class_parts = parts[i + 1:-1] + (path.stem,)  # Exclude .smali, include filename
                return ".".join(class_parts) if class_parts else ""
    
    # For other files (XML, etc.), return empty (no class name)
    return ""


def print_findings_table(findings: List[Dict], apk_name: str = "") -> None:
    """
    Print findings in a formatted table.
    
    Args:
        findings: List of nuclei findings (dictionaries)
        apk_name: Name of APK being scanned
    """
    if not findings:
        console.print("[green]✓ No vulnerabilities found![/green]")
        return
    
    # Create table
    # Use flexible column widths so full file paths and matches are visible (may wrap).
    table = Table(
        title=f"Vulnerability Findings - {apk_name}",
        show_header=True,
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("Severity", style="bold", no_wrap=True, width=10)
    table.add_column("Name", style="cyan")
    table.add_column("File", style="yellow", overflow="fold")
    table.add_column("Match", style="dim", overflow="fold")
    
    # Severity color mapping
    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim"
    }
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda x: severity_order.get(x.get("info", {}).get("severity", "info").lower(), 4)
    )
    
    # Add rows
    for finding in sorted_findings:
        info = finding.get("info", {})
        severity = info.get("severity", "unknown").lower()
        name = info.get("name", "Unknown")
        matched_at = finding.get("matched-at", "")
        file_path = matched_at.split(":")[0] if ":" in matched_at else matched_at
        
        # Extract entrypoint method (like reAVS format: ClassName->methodName)
        match_text = ""
        
        # For reAVS findings: show entrypoint_method (e.g., "com.avs.test.VulnerableService->onStartCommand")
        if "reavs_metadata" in finding:
            reavs_meta = finding.get("reavs_metadata", {})
            match_text = reavs_meta.get("entrypoint_method", "")
            # Fallback to primary_method or sink_method if entrypoint_method not available
            if not match_text:
                match_text = reavs_meta.get("primary_method", "") or reavs_meta.get("sink_method", "")
        
        # For nuclei findings: try to extract method from matched-line or derive from file path
        if not match_text:
            matched_line = finding.get("matched-line", "")
            if matched_line:
                # Try to extract method signature from matched line (e.g., "->methodName(")
                method_match = re.search(r'->(\w+)\s*\(', matched_line)
                if method_match and file_path:
                    # Construct entrypoint format: ClassName->methodName
                    class_name = _extract_class_name_from_path(file_path)
                    if class_name:
                        match_text = f"{class_name}->{method_match.group(1)}"
                else:
                    # Show matched line as-is if we can't extract method
                    match_text = matched_line
            
            # If no matched_line or couldn't extract method, try to get class name from file path
            if not match_text and file_path:
                class_name = _extract_class_name_from_path(file_path)
                if class_name:
                    match_text = class_name  # Show class name for file-level matches
        
        # Fallback to extracted-results (e.g., API keys, URLs, Firebase domains)
        if not match_text:
            extracted = finding.get("extracted-results", "")
            if isinstance(extracted, list) and extracted:
                match_text = ", ".join(str(x) for x in extracted[:2])
            elif extracted:
                match_text = str(extracted)
        
        # Clean and truncate
        match_text = str(match_text).strip()
        if len(match_text) > 100:
            match_text = match_text[:97] + "..."
        
        color = severity_colors.get(severity, "white")
        table.add_row(
            f"[{color}]{severity.upper()}[/{color}]",
            name,
            file_path,
            match_text
        )
    
    console.print(table)
    
    # Print summary
    severity_counts = {}
    for finding in findings:
        severity = finding.get("info", {}).get("severity", "unknown").lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    summary_text = "Summary: "
    summary_parts = [f"{count} {sev.upper()}" for sev, count in severity_counts.items()]
    summary_text += ", ".join(summary_parts)
    
    console.print(Panel(summary_text, title="[bold]Summary[/bold]", border_style="cyan"))


def save_json_report(findings: List[Dict], output_path: Path, apk_name: str = "") -> bool:
    """
    Save findings as detailed JSON report with vulnerability information.
    
    Args:
        findings: List of findings
        output_path: Path to output JSON file
        apk_name: Name of APK
    
    Returns:
        True if successful
    """
    try:
        # Process findings to extract detailed information
        processed_findings = []
        severity_counts = {}
        source_counts = {"nuclei": 0, "reavs": 0}
        
        for finding in findings:
            # Determine source (nuclei or reAVS)
            is_reavs = "reavs_metadata" in finding
            source = "reavs" if is_reavs else "nuclei"
            source_counts[source] = source_counts.get(source, 0) + 1
            
            # Extract basic info
            info = finding.get("info", {})
            severity = info.get("severity", "unknown").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Extract file path
            file_path = finding.get("matched-at", "")
            if ":" in file_path:
                file_path = file_path.split(":")[0]
            
            # Build detailed finding
            detailed_finding = {
                "id": finding.get("template-id", finding.get("id", "unknown")),
                "name": info.get("name", "Unknown"),
                "severity": severity.upper(),
                "source": source.upper(),
                "description": info.get("description", ""),
                "file": file_path,
                "component": finding.get("matched-at", ""),
            }
            
            # Add nuclei-specific fields
            if not is_reavs:
                detailed_finding["nuclei_info"] = {
                    "template_path": finding.get("template-path", ""),
                    "matched_line": finding.get("matched-line", ""),
                    "extracted_results": finding.get("extracted-results", ""),
                    "matcher_status": finding.get("matcher-status", False),
                    "timestamp": finding.get("timestamp", "")
                }
            
            # Add reAVS-specific fields (detailed taint analysis)
            if is_reavs:
                reavs_meta = finding.get("reavs_metadata", {})
                detailed_finding["reavs_info"] = {
                    "confidence": reavs_meta.get("confidence", ""),
                    "confidence_basis": reavs_meta.get("confidence_basis", ""),
                    "entrypoint_method": reavs_meta.get("entrypoint_method", ""),
                    "primary_method": reavs_meta.get("primary_method", ""),
                    "sink_method": reavs_meta.get("sink_method", ""),
                    "recommendation": reavs_meta.get("recommendation", ""),
                    "evidence": reavs_meta.get("evidence", [])
                }
                
                # Extract sources and sinks from evidence
                sources = []
                sinks = []
                for evidence_item in reavs_meta.get("evidence", []):
                    kind = evidence_item.get("kind", "")
                    if kind == "SOURCE":
                        sources.append({
                            "description": evidence_item.get("description", ""),
                            "method": evidence_item.get("method", ""),
                            "notes": evidence_item.get("notes", "")
                        })
                    elif kind == "SINK":
                        sinks.append({
                            "description": evidence_item.get("description", ""),
                            "method": evidence_item.get("method", ""),
                            "notes": evidence_item.get("notes", "")
                        })
                
                if sources:
                    detailed_finding["sources"] = sources
                if sinks:
                    detailed_finding["sinks"] = sinks
            
            # Add tags/references
            tags = info.get("tags", [])
            if tags:
                detailed_finding["references"] = tags
            
            processed_findings.append(detailed_finding)
        
        # Sort by severity (critical -> high -> medium -> low -> info)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        processed_findings.sort(key=lambda x: (
            severity_order.get(x.get("severity", "unknown").lower(), 5),
            x.get("name", "")
        ))
        
        # Build comprehensive report
        report = {
            "apk_name": apk_name,
            "scan_date": datetime.now().isoformat(),
            "summary": {
                "total_findings": len(findings),
                "by_severity": severity_counts,
                "by_source": source_counts
            },
            "findings": processed_findings
        }
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return True
    except Exception as e:
        console.print(f"[red]✗ Error saving JSON report: {e}[/red]")
        return False


def save_html_report(findings: List[Dict], output_path: Path, apk_name: str = "") -> bool:
    """
    Save findings as HTML report.
    
    Args:
        findings: List of findings
        output_path: Path to output HTML file
        apk_name: Name of APK
    
    Returns:
        True if successful
    """
    try:
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
            "info": "#6c757d"
        }
        
        # Generate HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Geiger Report - {apk_name}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }}
        .summary {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 6px;
            margin: 20px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #007bff;
            color: white;
            font-weight: bold;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
        .severity {{
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            color: white;
            display: inline-block;
        }}
        .finding {{
            margin: 15px 0;
            padding: 15px;
            border-left: 4px solid #007bff;
            background: #f8f9fa;
        }}
        .code {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Geiger Analysis Report</h1>
        <div class="summary">
            <p><strong>APK:</strong> {apk_name}</p>
            <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Total Findings:</strong> {len(findings)}</p>
        </div>
"""
        
        if findings:
            html += """
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Name</th>
                    <th>File</th>
                    <th>Match</th>
                </tr>
            </thead>
            <tbody>
"""
            for finding in findings:
                info = finding.get("info", {})
                severity = info.get("severity", "unknown").lower()
                name = info.get("name", "Unknown")
                matched_at = finding.get("matched-at", "")
                file_path = matched_at.split(":")[0] if ":" in matched_at else matched_at
                match_text = finding.get("matched-line", "") or finding.get("extracted-results", "")
                if isinstance(match_text, list):
                    match_text = ", ".join(str(x) for x in match_text)
                match_text = str(match_text)[:200]
                
                color = severity_colors.get(severity, "#6c757d")
                
                html += f"""
                <tr>
                    <td><span class="severity" style="background: {color}">{severity.upper()}</span></td>
                    <td>{name}</td>
                    <td><code>{file_path}</code></td>
                    <td><div class="code">{match_text}</div></td>
                </tr>
"""
            
            html += """
            </tbody>
        </table>
"""
        else:
            html += "<p>No vulnerabilities found!</p>"
        
        html += """
    </div>
</body>
</html>
"""
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return True
    except Exception as e:
        console.print(f"[red]✗ Error saving HTML report: {e}[/red]")
        return False

"""Nuclei scanner wrapper"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class NucleiScanner:
    """Wrapper for running nuclei scans."""
    
    def __init__(self, templates_dir: Path, auto_install: bool = True):
        """
        Initialize nuclei scanner.
        
        Args:
            templates_dir: Path to nuclei templates directory
            auto_install: Whether to automatically install nuclei if not found
        """
        self.templates_dir = templates_dir
        self.nuclei = self._ensure_nuclei(auto_install)
        
        if not self.nuclei:
            raise RuntimeError(
                "nuclei not found. Please install nuclei and ensure it's in PATH.\n"
                "See: https://docs.projectdiscovery.io/nuclei/getting-started/installation"
            )
    
    @staticmethod
    def _find_nuclei() -> Optional[str]:
        """Find nuclei binary in PATH."""
        import shutil
        return shutil.which("nuclei")
    
    @staticmethod
    def _ensure_nuclei(auto_install: bool = True) -> Optional[str]:
        """Ensure nuclei is available, installing if needed."""
        from geiger.utils.nuclei_installer import ensure_nuclei_installed
        return ensure_nuclei_installed(install_if_missing=auto_install)
    
    def scan(
        self,
        target_dir: Path,
        output_file: Optional[Path] = None,
        progress: Optional[Progress] = None
    ) -> List[Dict]:
        """
        Run nuclei scan against decompiled directory.
        
        Args:
            target_dir: Directory to scan
            output_file: Optional output file for JSON results
            progress: Optional progress bar
        
        Returns:
            List of parsed findings (dictionaries)
        """
        if not target_dir.exists():
            console.print(f"[red]✗ Target directory does not exist: {target_dir}[/red]")
            return []
        
        # Create temporary output file if not provided
        if output_file is None:
            # Use NamedTemporaryFile for secure temporary file creation
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix=".json", delete=False)
            temp_file.close()
            output_file = Path(temp_file.name)
            cleanup_output = True
        else:
            cleanup_output = False
            output_file.parent.mkdir(parents=True, exist_ok=True)
        
        task = None
        if progress:
            task = progress.add_task(
                f"[cyan]Scanning with nuclei...",
                total=None
            )
        
        try:
            # Construct nuclei command
            # Note: -j/-jsonl outputs JSONL format (one JSON object per line)
            # -file flag is required to enable file-based templates (they're disabled by default)
            # -target can accept a directory for file-based scanning
            cmd = [
                self.nuclei,
                "-target", str(target_dir),
                "-t", str(self.templates_dir),
                "-file",  # Enable file-based templates (required for mobile security templates)
                "-j",  # JSONL output format (one JSON object per line)
                "-o", str(output_file),
                "-silent",
                "-nc"  # -nc is short for -no-color
            ]
            
            # Run nuclei
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minute timeout
            )
            
            if progress and task:
                progress.update(task, completed=True)
            
            # Parse results
            findings = []
            if output_file.exists():
                try:
                    with open(output_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                try:
                                    finding = json.loads(line)
                                    findings.append(finding)
                                except json.JSONDecodeError:
                                    # Skip invalid JSON lines
                                    continue
                except Exception as e:
                    console.print(f"[yellow]⚠ Error reading nuclei output: {e}[/yellow]")
            
            # Check for errors
            if result.returncode != 0 and not findings:
                # Only show error if no findings were found
                if result.stderr:
                    console.print(f"[yellow]⚠ Nuclei warning: {result.stderr[:200]}[/yellow]")
            
            return findings
            
        except subprocess.TimeoutExpired:
            if progress and task:
                progress.update(task, completed=True)
            console.print("[red]✗ Nuclei scan timed out (exceeded 30 minutes)[/red]")
            return []
        except Exception as e:
            if progress and task:
                progress.update(task, completed=True)
            console.print(f"[red]✗ Nuclei scan error: {e}[/red]")
            return []
        finally:
            # Clean up temporary file if we created it
            if cleanup_output and output_file.exists():
                try:
                    output_file.unlink()
                except Exception:
                    pass

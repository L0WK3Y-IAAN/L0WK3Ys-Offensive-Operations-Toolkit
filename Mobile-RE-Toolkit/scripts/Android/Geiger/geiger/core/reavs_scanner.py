"""reAVS scanner integration for enhanced static analysis"""

import json
import subprocess
import sys
import platform
import threading
from pathlib import Path
from typing import List, Dict, Optional

from rich.console import Console

console = Console()


def _stream_output(pipe, is_stderr: bool = False, verbose: bool = True):
    """Read and display output from subprocess pipe in real-time."""
    try:
        for line in iter(pipe.readline, ''):
            if not line:
                break
            line = line.rstrip()
            if line and verbose:
                if is_stderr:
                    console.print(f"[red]{line}[/red]")
                else:
                    # Color-code reAVS output for better readability
                    if line.startswith("[*]"):
                        # Parse and colorize scanner info
                        if "scanner start" in line:
                            console.print(f"[cyan]{line}[/cyan]")
                        elif "scanner end" in line:
                            if "findings=0" in line:
                                console.print(f"[dim]{line}[/dim]")
                            else:
                                console.print(f"[yellow]{line}[/yellow]")
                        elif "findings CRITICAL" in line or "HIGH" in line:
                            console.print(f"[bold red]{line}[/bold red]")
                        elif "loading apk" in line or "scan mode" in line:
                            console.print(f"[blue]{line}[/blue]")
                        elif "components" in line or "methods analyzed" in line:
                            console.print(f"[green]{line}[/green]")
                        else:
                            console.print(f"[dim]{line}[/dim]")
                    elif line.startswith("[+]"):
                        console.print(f"[green]{line}[/green]")
                    elif line.startswith("[-]") or line.startswith("[!]"):
                        console.print(f"[yellow]{line}[/yellow]")
                    elif line.startswith("SEVERITY"):
                        # Table header
                        console.print(f"\n[bold]{line}[/bold]")
                    elif line.startswith("─") or line.startswith("-"):
                        console.print(f"[dim]{line}[/dim]")
                    elif "CRITICAL" in line or "HIGH" in line:
                        console.print(f"[red]{line}[/red]")
                    elif "MEDIUM" in line:
                        console.print(f"[yellow]{line}[/yellow]")
                    elif "LOW" in line or "INFO" in line:
                        console.print(f"[dim]{line}[/dim]")
                    else:
                        console.print(f"[dim]{line}[/dim]")
    except Exception:
        pass
    finally:
        pipe.close()

REAVS_REPO_URL = "https://github.com/aimardcr/reAVS.git"


class ReavsScanner:
    """Wrapper for running reAVS scans with taint analysis."""
    
    def __init__(self, reavs_dir: Optional[Path] = None, auto_setup: bool = True):
        """
        Initialize reAVS scanner.
        
        Args:
            reavs_dir: Path to reAVS directory (Tools/reAVS)
            auto_setup: Whether to automatically set up reAVS if not found
        """
        self.reavs_dir = reavs_dir or self._find_reavs_dir()
        self.avs_py = None
        self.python_exe = None
        
        # If reAVS not found and auto_setup is enabled, clone and setup
        if (not self.reavs_dir or not (self.reavs_dir / "avs.py").exists()) and auto_setup:
            self.reavs_dir = self._auto_setup_reavs()
        
        if self.reavs_dir and (self.reavs_dir / "avs.py").exists():
            self.avs_py = self.reavs_dir / "avs.py"
            # Try to find Python executable (prefer venv if exists)
            # Check multiple possible venv locations
            venv_locations = [
                self.reavs_dir / ".venv" / "bin" / "python",
                self.reavs_dir / "venv" / "bin" / "python",
                self.reavs_dir / ".venv" / "bin" / "python3",
                self.reavs_dir / "venv" / "bin" / "python3",
            ]
            
            for venv_python in venv_locations:
                if venv_python.exists():
                    self.python_exe = str(venv_python)
                    break
            
            # Fall back to system Python if no venv found
            if not self.python_exe:
                self.python_exe = sys.executable
    
    @staticmethod
    def _find_reavs_dir() -> Optional[Path]:
        """Try to find reAVS directory relative to workspace."""
        # Try common locations
        current = Path(__file__).resolve()
        
        # Go up from geiger/core/ to workspace root
        workspace_root = current.parent.parent.parent.parent.parent
        
        # Check Tools/reAVS
        reavs_dir = workspace_root / "Tools" / "reAVS"
        if reavs_dir.exists() and (reavs_dir / "avs.py").exists():
            return reavs_dir
        
        # Try alternative path
        alt_reavs = workspace_root.parent / "Tools" / "reAVS"
        if alt_reavs.exists() and (alt_reavs / "avs.py").exists():
            return alt_reavs
        
        return None
    
    @staticmethod
    def _get_tools_dir() -> Path:
        """Get the Tools directory path."""
        current = Path(__file__).resolve()
        # Go up from geiger/core/ to workspace root (Mobile-RE-Toolkit)
        workspace_root = current.parent.parent.parent.parent.parent
        return workspace_root / "Tools"
    
    def _auto_setup_reavs(self) -> Optional[Path]:
        """Automatically clone and set up reAVS if not available."""
        tools_dir = self._get_tools_dir()
        reavs_dir = tools_dir / "reAVS"
        
        console.print("[cyan]🔧 reAVS not found. Setting up automatically...[/cyan]")
        
        # Create Tools directory if it doesn't exist
        tools_dir.mkdir(parents=True, exist_ok=True)
        
        # Clone reAVS repository
        if not reavs_dir.exists() or not (reavs_dir / "avs.py").exists():
            console.print(f"[cyan]📥 Cloning reAVS from {REAVS_REPO_URL}...[/cyan]")
            try:
                result = subprocess.run(
                    ["git", "clone", REAVS_REPO_URL, str(reavs_dir)],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                if result.returncode != 0:
                    console.print(f"[red]✗ Failed to clone reAVS: {result.stderr}[/red]")
                    return None
                console.print("[green]✓ reAVS cloned successfully[/green]")
            except FileNotFoundError:
                console.print("[red]✗ Git not found. Please install git first.[/red]")
                return None
            except subprocess.TimeoutExpired:
                console.print("[red]✗ Clone timed out. Check your internet connection.[/red]")
                return None
            except Exception as e:
                console.print(f"[red]✗ Failed to clone reAVS: {e}[/red]")
                return None
        
        # Set up virtual environment and install dependencies
        if not self._setup_reavs_venv(reavs_dir):
            console.print("[yellow]⚠ reAVS cloned but dependencies not installed.[/yellow]")
            console.print("[yellow]  Run manually: cd Tools/reAVS && python -m venv .venv && .venv/bin/pip install -r requirements.txt[/yellow]")
        
        return reavs_dir
    
    def _setup_reavs_venv(self, reavs_dir: Path) -> bool:
        """Set up virtual environment and install reAVS dependencies."""
        venv_dir = reavs_dir / ".venv"
        requirements_file = reavs_dir / "requirements.txt"
        
        # Determine pip path based on OS
        if platform.system() == "Windows":
            venv_pip = venv_dir / "Scripts" / "pip.exe"
        else:
            venv_pip = venv_dir / "bin" / "pip"
        
        # Create venv if it doesn't exist
        if not venv_dir.exists():
            console.print("[cyan]📦 Creating virtual environment...[/cyan]")
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "venv", str(venv_dir)],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if result.returncode != 0:
                    console.print(f"[red]✗ Failed to create venv: {result.stderr}[/red]")
                    return False
            except Exception as e:
                console.print(f"[red]✗ Failed to create venv: {e}[/red]")
                return False
        
        # Install dependencies if requirements.txt exists
        if requirements_file.exists():
            console.print("[cyan]📥 Installing reAVS dependencies (this may take a few minutes)...[/cyan]")
            try:
                result = subprocess.run(
                    [str(venv_pip), "install", "-r", str(requirements_file)],
                    capture_output=True,
                    text=True,
                    timeout=600  # 10 minutes for dependency installation
                )
                if result.returncode != 0:
                    console.print(f"[yellow]⚠ Some dependencies may have failed: {result.stderr[:200]}[/yellow]")
                    return False
                console.print("[green]✓ reAVS dependencies installed[/green]")
                return True
            except subprocess.TimeoutExpired:
                console.print("[red]✗ Dependency installation timed out[/red]")
                return False
            except Exception as e:
                console.print(f"[red]✗ Failed to install dependencies: {e}[/red]")
                return False
        else:
            console.print("[yellow]⚠ No requirements.txt found in reAVS[/yellow]")
            return False
    
    def is_available(self) -> bool:
        """Check if reAVS is available and dependencies are installed."""
        if not self.avs_py or not self.avs_py.exists():
            return False
        
        # Check if Python executable can import androguard (required dependency)
        if self.python_exe:
            try:
                result = subprocess.run(
                    [self.python_exe, "-c", "import androguard"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return result.returncode == 0
            except Exception:
                return False
        
        return False
    
    def scan(
        self,
        apk_path: Path,
        output_file: Optional[Path] = None,
        deep: bool = True,
        depth: int = 3,
        verbose: bool = True
    ) -> List[Dict]:
        """
        Run reAVS scan on APK file with optional live output streaming.
        
        Args:
            apk_path: Path to APK file
            output_file: Optional output file for JSON results
            deep: Use deep scan mode (taint analysis)
            depth: Helper propagation depth for deep mode
            verbose: Stream reAVS output in real-time
        
        Returns:
            List of parsed findings (dictionaries)
        """
        if not self.is_available():
            console.print("[yellow]⚠ reAVS not available. Skipping taint analysis.[/yellow]")
            return []
        
        if not apk_path.exists():
            console.print(f"[red]✗ APK file does not exist: {apk_path}[/red]")
            return []
        
        # Create temporary output file if not provided
        if output_file is None:
            import tempfile
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix=".json", delete=False)
            temp_file.close()
            output_file = Path(temp_file.name)
            cleanup_output = True
        else:
            cleanup_output = False
            output_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # Build reAVS command
            cmd = [
                self.python_exe,
                str(self.avs_py),
                str(apk_path),
                "--out", str(output_file)
            ]
            
            if deep:
                cmd.append("--deep")
                if depth:
                    cmd.extend(["--depth", str(depth)])
            else:
                cmd.append("--fast")
            
            if verbose:
                # Display scan info
                console.print(f"\n[cyan]Running reAVS scan on {apk_path.name}...[/cyan]")
                console.print(f"[dim]Mode: {'deep' if deep else 'fast'} | Depth: {depth}[/dim]")
                console.print(f"[dim]Output: {output_file}[/dim]\n")
                
                # Run with live output streaming using Popen
                proc = subprocess.Popen(
                    cmd,
                    cwd=str(self.reavs_dir),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                # Start threads to stream stdout and stderr
                stdout_thread = threading.Thread(
                    target=_stream_output, 
                    args=(proc.stdout, False, verbose)
                )
                stderr_thread = threading.Thread(
                    target=_stream_output, 
                    args=(proc.stderr, True, verbose)
                )
                
                stdout_thread.daemon = True
                stderr_thread.daemon = True
                
                stdout_thread.start()
                stderr_thread.start()
                
                # Wait for process to complete
                return_code = proc.wait()
                
                # Wait for threads to finish reading
                stdout_thread.join(timeout=2)
                stderr_thread.join(timeout=2)
                
                if return_code != 0:
                    console.print(f"\n[red]✗ reAVS scan failed with return code {return_code}[/red]")
                    return []
            else:
                # Run silently with capture_output
                result = subprocess.run(
                    cmd,
                    cwd=str(self.reavs_dir),
                    capture_output=True,
                    text=True,
                    timeout=1800  # 30 minute timeout
                )
                
                # Check for errors
                if result.returncode != 0:
                    error_msg = result.stderr or result.stdout
                    if error_msg:
                        if "ModuleNotFoundError" in error_msg or "No module named" in error_msg:
                            console.print("[red]✗ reAVS dependencies not installed[/red]")
                            console.print("[yellow]💡 Tip: Run the reAVS scan script first to set up dependencies:[/yellow]")
                            console.print(f"[dim]   python scripts/Android/reAVS\\ Scan/reavs_scan.py[/dim]")
                        else:
                            console.print(f"[red]✗ reAVS scan failed:[/red]")
                            console.print(f"[dim]{error_msg[:500]}[/dim]")
                    return []
            
            # Parse results
            findings = []
            if output_file.exists() and output_file.stat().st_size > 0:
                try:
                    with open(output_file, 'r', encoding='utf-8') as f:
                        content = f.read().strip()
                        if not content:
                            console.print("[yellow]⚠ reAVS produced empty output[/yellow]")
                            return []
                        data = json.loads(content)
                        findings = data.get("findings", [])
                except json.JSONDecodeError as e:
                    console.print(f"[yellow]⚠ Error parsing reAVS output: {e}[/yellow]")
                    if output_file.exists():
                        with open(output_file, 'r', encoding='utf-8') as f:
                            content = f.read()[:200]
                            console.print(f"[dim]Output preview: {content}[/dim]")
                except Exception as e:
                    console.print(f"[yellow]⚠ Error reading reAVS output: {e}[/yellow]")
            elif output_file.exists():
                console.print("[yellow]⚠ reAVS output file is empty[/yellow]")
            
            return findings
            
        except subprocess.TimeoutExpired:
            console.print("[red]✗ reAVS scan timed out (exceeded 30 minutes)[/red]")
            return []
        except Exception as e:
            console.print(f"[red]✗ reAVS scan error: {e}[/red]")
            return []
        finally:
            # Clean up temporary file if we created it
            if cleanup_output and output_file.exists():
                try:
                    output_file.unlink()
                except Exception:
                    pass
    
    @staticmethod
    def convert_findings_to_nuclei_format(findings: List[Dict]) -> List[Dict]:
        """
        Convert reAVS findings to nuclei-like format for unified reporting.
        
        Args:
            findings: List of reAVS findings
        
        Returns:
            List of findings in nuclei-compatible format
        """
        converted = []
        
        for finding in findings:
            # Map reAVS severity to nuclei format
            severity_map = {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "INFO": "info"
            }
            
            severity = severity_map.get(finding.get("severity", "info").upper(), "info")
            
            # Create nuclei-compatible finding
            nuclei_finding = {
                "template-id": finding.get("id", "unknown"),
                "info": {
                    "name": finding.get("title", finding.get("id", "Unknown")),
                    "severity": severity,
                    "author": ["reAVS"],
                    "description": finding.get("description", ""),
                    "tags": finding.get("references", [])
                },
                "type": "file",
                "matched-at": finding.get("component_name") or finding.get("class_name", ""),
                "timestamp": finding.get("timestamp", ""),
                "matcher-status": True,
                "reavs_metadata": {
                    "confidence": finding.get("confidence", ""),
                    "confidence_basis": finding.get("confidence_basis", ""),
                    "entrypoint_method": finding.get("entrypoint_method", ""),
                    "primary_method": finding.get("primary_method", ""),
                    "sink_method": finding.get("sink_method", ""),
                    "evidence": finding.get("evidence", []),
                    "recommendation": finding.get("recommendation", "")
                }
            }
            
            converted.append(nuclei_finding)
        
        return converted

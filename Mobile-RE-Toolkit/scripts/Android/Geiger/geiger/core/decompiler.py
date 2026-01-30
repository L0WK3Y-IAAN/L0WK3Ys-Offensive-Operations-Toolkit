"""APK decompilation using apktool and jadx"""

import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()


class Decompiler:
    """Handles APK decompilation with apktool and optionally jadx."""
    
    def __init__(self):
        """Initialize decompiler, checking for required tools."""
        self.apktool = shutil.which("apktool")
        self.jadx = shutil.which("jadx")
        
        if not self.apktool:
            raise RuntimeError(
                "apktool not found. Please install apktool and ensure it's in PATH.\n"
                "See: https://ibotpeaches.github.io/Apktool/install/"
            )
    
    def decompile_apktool(
        self,
        apk_path: Path,
        output_dir: Path,
        progress: Optional[Progress] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Decompile APK using apktool.
        
        Args:
            apk_path: Path to APK file
            output_dir: Output directory for decompiled files
            progress: Optional progress bar
        
        Returns:
            Tuple of (success, error_message)
        """
        task = None
        if progress:
            task = progress.add_task(
                f"[cyan]Decompiling {apk_path.name} with apktool...",
                total=None
            )
        
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            
            cmd = [
                self.apktool,
                "d",
                str(apk_path),
                "-o",
                str(output_dir),
                "-f",  # Force overwrite
                "-q"   # Quiet mode
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            if progress and task:
                progress.update(task, completed=True)
            
            if result.returncode != 0:
                error_msg = result.stderr or result.stdout or "Unknown error"
                return False, error_msg
            
            return True, None
            
        except subprocess.TimeoutExpired:
            if progress and task:
                progress.update(task, completed=True)
            return False, "apktool decompilation timed out (exceeded 10 minutes)"
        except Exception as e:
            if progress and task:
                progress.update(task, completed=True)
            return False, str(e)
    
    def decompile_jadx(
        self,
        apk_path: Path,
        output_dir: Path,
        progress: Optional[Progress] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Decompile APK using jadx to get Java source (optional).
        
        Args:
            apk_path: Path to APK file
            output_dir: Output directory for Java source
            progress: Optional progress bar
        
        Returns:
            Tuple of (success, error_message)
        """
        if not self.jadx:
            return False, "jadx not found (optional, skipping Java decompilation)"
        
        task = None
        if progress:
            task = progress.add_task(
                f"[cyan]Decompiling {apk_path.name} with jadx...",
                total=None
            )
        
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            
            cmd = [
                self.jadx,
                "-d",
                str(output_dir),
                "-j",  # Number of threads
                "4",
                "-q",  # Quiet mode
                str(apk_path)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=900  # 15 minute timeout
            )
            
            if progress and task:
                progress.update(task, completed=True)
            
            if result.returncode != 0:
                error_msg = result.stderr or result.stdout or "Unknown error"
                return False, error_msg
            
            return True, None
            
        except subprocess.TimeoutExpired:
            if progress and task:
                progress.update(task, completed=True)
            return False, "jadx decompilation timed out (exceeded 15 minutes)"
        except Exception as e:
            if progress and task:
                progress.update(task, completed=True)
            return False, str(e)
    
    def decompile(
        self,
        apk_path: Path,
        base_output_dir: Path,
        use_jadx: bool = True,
        keep_source: bool = False
    ) -> Tuple[Path, Optional[Path], Optional[str]]:
        """
        Decompile APK using both apktool and optionally jadx.
        
        Args:
            apk_path: Path to APK file
            base_output_dir: Base output directory
            use_jadx: Whether to also decompile with jadx
            keep_source: Whether to keep decompiled source after scanning
        
        Returns:
            Tuple of (apktool_dir, jadx_dir, error_message)
        """
        apk_name = apk_path.stem
        base_output_dir.mkdir(parents=True, exist_ok=True)

        # Persistent layout (cache-friendly):
        #   <base_output_dir>/
        #     apktool/
        #     jadx/
        apktool_dir = base_output_dir / "apktool"
        jadx_dir = (base_output_dir / "jadx") if use_jadx else None

        # Heuristics to decide whether cached outputs are "good enough" to reuse
        def _apktool_ready(d: Path) -> bool:
            return d.exists() and d.is_dir() and (
                (d / "AndroidManifest.xml").exists()
                or (d / "smali").exists()
                or (d / "smali_classes2").exists()
            )

        def _jadx_ready(d: Optional[Path]) -> bool:
            if d is None:
                return True
            return d.exists() and d.is_dir() and (
                (d / "sources").exists() or (d / "resources").exists()
            )
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            # Decompile with apktool (required) — reuse cached output if present
            if _apktool_ready(apktool_dir):
                console.print(f"[green]✓ Reusing cached apktool extraction:[/green] {apktool_dir}")
            else:
                success, error = self.decompile_apktool(apk_path, apktool_dir, progress)
                if not success:
                    return apktool_dir, jadx_dir, f"apktool failed: {error}"
            
            # Decompile with jadx (optional)
            if use_jadx:
                if _jadx_ready(jadx_dir):
                    console.print(f"[green]✓ Reusing cached jadx extraction:[/green] {jadx_dir}")
                else:
                    success, error = self.decompile_jadx(apk_path, jadx_dir, progress)
                    if not success:
                        console.print(f"[yellow]⚠ jadx warning: {error}[/yellow]")
        
        return apktool_dir, jadx_dir, None

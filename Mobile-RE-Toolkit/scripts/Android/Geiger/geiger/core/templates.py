"""Template manager for mobile-nuclei-templates repository"""

import shutil
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from geiger.config import TEMPLATES_DIR, TEMPLATES_REPO_URL

console = Console()


class TemplateManager:
    """Manages the mobile-nuclei-templates repository."""
    
    def __init__(self, templates_dir: Path = TEMPLATES_DIR):
        """
        Initialize template manager.
        
        Args:
            templates_dir: Directory where templates are stored
        """
        self.templates_dir = templates_dir
    
    def ensure_templates(self, update: bool = True) -> bool:
        """
        Ensure templates are available, cloning or updating as needed.
        
        Args:
            update: Whether to update if templates already exist
        
        Returns:
            True if templates are available, False otherwise
        """
        try:
            import git
        except ImportError:
            console.print("[red]✗ GitPython not installed. Install with: pip install GitPython[/red]")
            return False
        
        if self.templates_dir.exists() and (self.templates_dir / ".git").exists():
            # Repository exists, update if requested
            if update:
                with console.status("[cyan]Updating templates repository..."):
                    try:
                        repo = git.Repo(self.templates_dir)
                        repo.remotes.origin.pull()
                        console.print(f"[green]✓ Templates updated[/green]")
                    except Exception as e:
                        console.print(f"[yellow]⚠ Could not update templates: {e}[/yellow]")
                        console.print("[yellow]Using existing templates...[/yellow]")
            return True
        else:
            # Clone repository
            with console.status("[cyan]Cloning mobile-nuclei-templates repository..."):
                try:
                    # Remove directory if it exists but isn't a git repo
                    if self.templates_dir.exists():
                        shutil.rmtree(self.templates_dir)
                    
                    git.Repo.clone_from(TEMPLATES_REPO_URL, self.templates_dir)
                    console.print(f"[green]✓ Templates cloned to {self.templates_dir}[/green]")
                    return True
                except Exception as e:
                    console.print(f"[red]✗ Failed to clone templates: {e}[/red]")
                    return False
    
    def get_template_path(self) -> Optional[Path]:
        """
        Get the path to the templates directory.
        
        Returns:
            Path to templates or None if not available
        """
        if self.templates_dir.exists():
            return self.templates_dir
        return None
    
    def template_count(self) -> int:
        """Count the number of template files."""
        if not self.templates_dir.exists():
            return 0
        
        count = 0
        for ext in ['.yaml', '.yml']:
            count += len(list(self.templates_dir.rglob(f'*{ext}')))
        return count

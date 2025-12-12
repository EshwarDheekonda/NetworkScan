"""
Training UI

CLI-based user interface for baseline training data upload and management.
"""

import sys
from pathlib import Path
from typing import Optional, List
import logging

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Warning: rich library not available. Install with: pip install rich")

from baseline_training.training_api import (
    upload_training_data,
    get_training_status,
    get_training_statistics,
    clear_baseline,
    switch_agent_mode
)

logger = logging.getLogger(__name__)

console = Console() if RICH_AVAILABLE else None


class TrainingUI:
    """CLI-based training UI."""
    
    def __init__(self):
        """Initialize training UI."""
        if not RICH_AVAILABLE:
            raise ImportError("rich library is required for training UI. Install with: pip install rich")
        self.console = Console()
    
    def show_main_menu(self):
        """Show main menu."""
        self.console.print("\n" + "="*60)
        self.console.print(Panel.fit(
            "[bold cyan]Baseline Training System[/bold cyan]",
            border_style="cyan"
        ))
        self.console.print("="*60 + "\n")
        
        menu = Table(show_header=False, box=box.SIMPLE)
        menu.add_row("1", "Upload Training Data")
        menu.add_row("2", "View Training Status")
        menu.add_row("3", "View Training Statistics")
        menu.add_row("4", "Switch Agent Mode")
        menu.add_row("5", "Clear Baseline")
        menu.add_row("6", "Exit")
        
        self.console.print(menu)
        self.console.print()
    
    def select_agent(self) -> Optional[str]:
        """Select agent type."""
        self.console.print("\n[bold]Select Agent Type:[/bold]")
        agent_table = Table(show_header=False, box=box.SIMPLE)
        agent_table.add_row("1", "Router (Network Traffic)")
        agent_table.add_row("2", "Computer (System Logs)")
        agent_table.add_row("3", "Email (Email Traffic)")
        agent_table.add_row("4", "Cancel")
        self.console.print(agent_table)
        
        choice = Prompt.ask("\nEnter choice", choices=["1", "2", "3", "4"], default="4")
        
        agent_map = {
            "1": "router",
            "2": "computer",
            "3": "email"
        }
        
        return agent_map.get(choice)
    
    def select_format(self) -> Optional[str]:
        """Select data format."""
        self.console.print("\n[bold]Select Data Format:[/bold]")
        format_table = Table(show_header=False, box=box.SIMPLE)
        format_table.add_row("1", "JSON")
        format_table.add_row("2", "CSV")
        format_table.add_row("3", "JSONL")
        format_table.add_row("4", "Auto-detect from extension")
        self.console.print(format_table)
        
        choice = Prompt.ask("\nEnter choice", choices=["1", "2", "3", "4"], default="4")
        
        format_map = {
            "1": "json",
            "2": "csv",
            "3": "jsonl",
            "4": None
        }
        
        return format_map.get(choice)
    
    def upload_data(self):
        """Upload training data."""
        agent_id = self.select_agent()
        if not agent_id:
            return
        
        data_format = self.select_format()
        
        file_path = Prompt.ask("\nEnter file path")
        file_path = Path(file_path).expanduser().resolve()
        
        if not file_path.exists():
            self.console.print(f"[red]Error: File not found: {file_path}[/red]")
            return
        
        self.console.print(f"\n[bold]Uploading training data for {agent_id} agent...[/bold]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("Processing...", total=None)
            result = upload_training_data(agent_id, str(file_path), data_format)
            progress.update(task, completed=True)
        
        if result.success:
            self.console.print(f"\n[green]✓ Training completed successfully![/green]")
            self.console.print(f"  Records processed: {result.records_processed}")
            self.console.print(f"  Records valid: {result.records_valid}")
            self.console.print(f"  Records invalid: {result.records_invalid}")
            self.console.print(f"  Baseline ready: {result.status.baseline_ready}")
        else:
            self.console.print(f"\n[red]✗ Training failed[/red]")
            self.console.print(f"  Error: {result.error_message}")
            if result.status.errors:
                self.console.print(f"  Errors: {len(result.status.errors)}")
                for error in result.status.errors[:5]:
                    self.console.print(f"    - {error}")
    
    def view_status(self):
        """View training status."""
        agent_id = self.select_agent()
        if not agent_id:
            return
        
        status = get_training_status(agent_id)
        
        self.console.print(f"\n[bold]Training Status for {agent_id} agent:[/bold]")
        
        status_table = Table(show_header=True, box=box.ROUNDED)
        status_table.add_column("Property", style="cyan")
        status_table.add_column("Value", style="green")
        
        status_table.add_row("Mode", status.get('mode', 'unknown'))
        status_table.add_row("Is Training", str(status.get('is_training', False)))
        status_table.add_row("Baseline Ready", str(status.get('baseline_ready', False)))
        status_table.add_row("Records Processed", str(status.get('records_processed', 0)))
        status_table.add_row("Records Valid", str(status.get('records_valid', 0)))
        status_table.add_row("Records Invalid", str(status.get('records_invalid', 0)))
        
        if status.get('started_at'):
            status_table.add_row("Started At", status['started_at'])
        if status.get('completed_at'):
            status_table.add_row("Completed At", status['completed_at'])
        
        self.console.print(status_table)
        
        if status.get('errors'):
            self.console.print("\n[bold red]Errors:[/bold red]")
            for error in status['errors'][:10]:
                self.console.print(f"  • {error}")
    
    def view_statistics(self):
        """View training statistics."""
        agent_id = self.select_agent()
        if not agent_id:
            return
        
        stats = get_training_statistics(agent_id)
        
        self.console.print(f"\n[bold]Training Statistics for {agent_id} agent:[/bold]")
        
        # Status table
        status = stats.get('status', {})
        status_table = Table(show_header=True, box=box.ROUNDED, title="Status")
        status_table.add_column("Property", style="cyan")
        status_table.add_column("Value", style="green")
        
        status_table.add_row("Mode", stats.get('mode', 'unknown'))
        status_table.add_row("Baseline Ready", str(status.get('baseline_ready', False)))
        status_table.add_row("Records Processed", str(status.get('records_processed', 0)))
        
        self.console.print(status_table)
        
        # Baseline stats
        baseline_stats = stats.get('baseline_stats', {})
        if baseline_stats:
            self.console.print("\n[bold]Baseline Statistics:[/bold]")
            
            numeric_baselines = baseline_stats.get('numeric_baselines', {})
            if numeric_baselines:
                numeric_table = Table(show_header=True, box=box.ROUNDED, title="Numeric Baselines")
                numeric_table.add_column("Baseline", style="cyan")
                numeric_table.add_column("Samples", style="green")
                numeric_table.add_column("Mean", style="yellow")
                numeric_table.add_column("Std Dev", style="yellow")
                numeric_table.add_column("Ready", style="green")
                
                for name, stats_data in numeric_baselines.items():
                    numeric_table.add_row(
                        name,
                        str(stats_data.get('sample_count', 0)),
                        f"{stats_data.get('mean', 0):.2f}",
                        f"{stats_data.get('std', 0):.2f}",
                        str(stats_data.get('is_ready', False))
                    )
                
                self.console.print(numeric_table)
            
            pattern_baselines = baseline_stats.get('pattern_baselines', {})
            if pattern_baselines:
                pattern_table = Table(show_header=True, box=box.ROUNDED, title="Pattern Baselines")
                pattern_table.add_column("Baseline", style="cyan")
                pattern_table.add_column("Total Observations", style="green")
                pattern_table.add_column("Unique Patterns", style="yellow")
                pattern_table.add_column("Known Patterns", style="green")
                
                for name, stats_data in pattern_baselines.items():
                    pattern_table.add_row(
                        name,
                        str(stats_data.get('total_observations', 0)),
                        str(stats_data.get('unique_patterns', 0)),
                        str(stats_data.get('known_patterns', 0))
                    )
                
                self.console.print(pattern_table)
    
    def switch_mode(self):
        """Switch agent mode."""
        agent_id = self.select_agent()
        if not agent_id:
            return
        
        self.console.print("\n[bold]Select Mode:[/bold]")
        mode_table = Table(show_header=False, box=box.SIMPLE)
        mode_table.add_row("1", "Training (only learning)")
        mode_table.add_row("2", "Inference (only detection)")
        mode_table.add_row("3", "Hybrid (continuous learning)")
        self.console.print(mode_table)
        
        choice = Prompt.ask("\nEnter choice", choices=["1", "2", "3"], default="1")
        
        mode_map = {
            "1": "training",
            "2": "inference",
            "3": "hybrid"
        }
        
        mode = mode_map.get(choice)
        if mode:
            success = switch_agent_mode(agent_id, mode)
            if success:
                self.console.print(f"\n[green]✓ Switched {agent_id} to {mode} mode[/green]")
            else:
                self.console.print(f"\n[red]✗ Failed to switch mode[/red]")
    
    def clear_baseline_ui(self):
        """Clear baseline UI."""
        agent_id = self.select_agent()
        if not agent_id:
            return
        
        if Confirm.ask(f"\n[bold red]Are you sure you want to clear baseline for {agent_id}?[/bold red]"):
            success = clear_baseline(agent_id)
            if success:
                self.console.print(f"\n[green]✓ Baseline cleared for {agent_id}[/green]")
            else:
                self.console.print(f"\n[red]✗ Failed to clear baseline[/red]")
    
    def run(self):
        """Run the training UI."""
        while True:
            try:
                self.show_main_menu()
                choice = Prompt.ask("Enter choice", choices=["1", "2", "3", "4", "5", "6"], default="6")
                
                if choice == "1":
                    self.upload_data()
                elif choice == "2":
                    self.view_status()
                elif choice == "3":
                    self.view_statistics()
                elif choice == "4":
                    self.switch_mode()
                elif choice == "5":
                    self.clear_baseline_ui()
                elif choice == "6":
                    self.console.print("\n[bold]Goodbye![/bold]\n")
                    break
                
                if choice != "6":
                    Prompt.ask("\nPress Enter to continue...", default="")
            
            except KeyboardInterrupt:
                self.console.print("\n\n[bold]Interrupted. Goodbye![/bold]\n")
                break
            except Exception as e:
                self.console.print(f"\n[red]Error: {e}[/red]")
                logger.exception("UI error")


def main():
    """Main entry point for training UI."""
    try:
        ui = TrainingUI()
        ui.run()
    except ImportError as e:
        print(f"Error: {e}")
        print("Please install rich library: pip install rich")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        logger.exception("UI startup error")
        sys.exit(1)


if __name__ == "__main__":
    main()





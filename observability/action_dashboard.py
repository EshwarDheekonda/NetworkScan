"""
Action Dashboard

User-facing dashboard that displays pending approvals, agent activity
in real-time, threat visualizations, and action history.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    from rich.layout import Layout
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None
    Table = None
    Panel = None
    Live = None
    Layout = None

from guardrails.action_guard import ActionGuard
from observability.agent_monitor import AgentMonitor


class ActionDashboard:
    """User-facing action dashboard."""
    
    def __init__(
        self,
        action_guard: ActionGuard,
        agent_monitor: AgentMonitor
    ):
        """
        Initialize the action dashboard.
        
        Args:
            action_guard: Action guard instance
            agent_monitor: Agent monitor instance
        """
        self.action_guard = action_guard
        self.agent_monitor = agent_monitor
        self.logger = logging.getLogger(__name__)
        self.console = Console() if RICH_AVAILABLE else None
    
    def display_pending_approvals(self):
        """Display pending approval requests."""
        pending = self.action_guard.get_pending_approvals()
        
        if not RICH_AVAILABLE:
            # Fallback to simple text output
            print(f"\n=== PENDING APPROVALS ({len(pending)}) ===")
            for approval in pending:
                action = approval.get('action', {})
                print(f"  [{approval['approval_id'][:8]}] {action.get('type', 'unknown')} from {action.get('agent_id', 'unknown')}")
            return
        
        if not pending:
            self.console.print("[green]No pending approvals[/green]")
            return
        
        table = Table(title="Pending Approvals")
        table.add_column("ID", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Agent", style="yellow")
        table.add_column("Timestamp", style="blue")
        
        for approval in pending[:20]:  # Show first 20
            action = approval.get('action', {})
            table.add_row(
                approval['approval_id'][:8],
                action.get('type', 'unknown'),
                action.get('agent_id', 'unknown'),
                approval.get('requested_at', '')[:19]
            )
        
        self.console.print(table)
    
    def display_agent_activity(self):
        """Display real-time agent activity."""
        summary = self.agent_monitor.get_system_summary()
        
        if not RICH_AVAILABLE:
            print(f"\n=== AGENT ACTIVITY ===")
            print(f"Running Agents: {summary['running_agents']}/{summary['total_agents']}")
            print(f"Total Observations: {summary['total_observations']}")
            print(f"Total Anomalies: {summary['total_anomalies']}")
            return
        
        table = Table(title="Agent Activity")
        table.add_column("Agent", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Observations", style="yellow")
        table.add_column("Anomalies", style="red")
        table.add_column("LLM Calls", style="magenta")
        
        for agent_id, status in summary['agents'].items():
            stats = status.get('stats', {})
            table.add_row(
                agent_id,
                "Running" if status.get('is_running') else "Stopped",
                str(stats.get('observation_count', 0)),
                str(stats.get('anomaly_count', 0)),
                str(stats.get('llm_calls', 0))
            )
        
        self.console.print(table)
    
    def display_dashboard(self, refresh_interval: float = 1.0):
        """Display full dashboard with auto-refresh."""
        if not RICH_AVAILABLE:
            # Simple text dashboard
            while True:
                import time
                import os
                os.system('cls' if os.name == 'nt' else 'clear')
                print("=" * 60)
                print("SECURITY AGENT DASHBOARD")
                print("=" * 60)
                self.display_pending_approvals()
                self.display_agent_activity()
                print("\nPress Ctrl+C to exit")
                time.sleep(refresh_interval)
            return
        
        # Rich dashboard
        def generate_layout():
            layout = Layout()
            layout.split_column(
                Layout(name="approvals", size=10),
                Layout(name="activity", size=15)
            )
            
            # Pending approvals
            pending = self.action_guard.get_pending_approvals()
            approvals_text = f"Pending Approvals: {len(pending)}"
            layout["approvals"].update(Panel(approvals_text, title="Approvals"))
            
            # Agent activity
            summary = self.agent_monitor.get_system_summary()
            activity_text = f"Running: {summary['running_agents']}/{summary['total_agents']}\n"
            activity_text += f"Observations: {summary['total_observations']}\n"
            activity_text += f"Anomalies: {summary['total_anomalies']}"
            layout["activity"].update(Panel(activity_text, title="Agent Activity"))
            
            return layout
        
        with Live(generate_layout(), refresh_per_second=1.0/refresh_interval) as live:
            try:
                while True:
                    live.update(generate_layout())
                    import time
                    time.sleep(refresh_interval)
            except KeyboardInterrupt:
                pass





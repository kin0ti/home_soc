from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

console.print(
    Panel.fit(
        "[bold cyan]HOME SOC v2.0[/bold cyan]\n"
        "[green]Python Security Dashboard[/green]"
    )
)

table = Table(title="Main Menu")

table.add_column("Option", style="cyan", justify="center")
table.add_column("Action", style="green")

table.add_row("1", "System Health")
table.add_row("2", "System Inventory")
table.add_row("3", "Network Scan")
table.add_row("4", "Log Analysis")
table.add_row("5", "Exit")

console.print(table)

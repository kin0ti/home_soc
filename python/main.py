from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from modules.health import get_system_health

console = Console()


def show_dashboard():
    """Display the Home SOC dashboard."""

    health = get_system_health()

    console.print(
        Panel.fit(
            "[bold cyan]HOME SOC v2.0[/bold cyan]\n"
            "[green]Python Security Dashboard[/green]"
        )
    )

    table = Table(title="System Health")

    table.add_column("Item", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Hostname", health["hostname"])
    table.add_row("Operating System", health["system"])
    table.add_row("Kernel", health["release"])
    table.add_row("CPU Usage", f"{health['cpu']}%")
    table.add_row("Memory Usage", f"{health['memory']}%")
    table.add_row("Disk Usage", f"{health['disk']}%")
    table.add_row("Boot Time", health["boot_time"])

    console.print(table)


if __name__ == "__main__":
    show_dashboard()

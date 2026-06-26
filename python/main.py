from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from modules.health import get_system_health
from modules.network import run_network_scan

console = Console()


def show_dashboard():
    """Display the system health dashboard."""

    health = get_system_health()

    console.clear()

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


def menu():
    while True:

        console.print()
        console.print("[bold yellow]========= MENU =========[/bold yellow]")
        console.print("1. Refresh System Health")
        console.print("2. Network Scanner")
        console.print("3. Log Analyzer")
        console.print("4. File Integrity Monitor")
        console.print("5. Generate Security Report")
        console.print("6. Exit")
        console.print()

        choice = input("Select an option: ")

        if choice == "1":
            show_dashboard()

        elif choice == "2":
            console.clear()
            show_dashboard()
            run_network_scan()

        elif choice == "3":
            console.print("[cyan]Log Analyzer module coming next...[/cyan]")

        elif choice == "4":
            console.print("[cyan]File Integrity module coming next...[/cyan]")

        elif choice == "5":
            console.print("[cyan]Security Report module coming next...[/cyan]")

        elif choice == "6":
            console.print()
            console.print("[bold green]Thank you for using Home SOC![/bold green]")
            break

        else:
            console.print("[bold red]Invalid option. Please try again.[/bold red]")


if __name__ == "__main__":
    show_dashboard()
    menu()

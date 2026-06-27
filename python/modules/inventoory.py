"""
Home SOC - Device Inventory
"""

from python.modules.database import get_connection
from rich.console import Console
from rich.table import Table

console = Console()


def show_inventory():
    """
    Display all known devices.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            ip,
            hostname,
            mac,
            vendor,
            status,
            risk,
            score
        FROM devices
        ORDER BY ip
    """)

    rows = cursor.fetchall()

    table = Table(title="Device Inventory", expand=True)

    table.add_column("IP", style="cyan")
    table.add_column("Hostname", style="green")
    table.add_column("MAC", style="magenta")
    table.add_column("Vendor", style="blue")
    table.add_column("Status", style="yellow")
    table.add_column("Risk", style="red")
    table.add_column("Score", justify="right")

    for row in rows:
        table.add_row(*[str(x) if x is not None else "-" for x in row])

    console.print(table)

    conn.close()


def main():
    show_inventory()


if __name__ == "__main__":
    main()

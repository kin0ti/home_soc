"""
Home SOC - Device Inventory
"""

import sqlite3
from pathlib import Path

from rich.console import Console
from rich.table import Table

DB_PATH = Path("data/home_soc.db")

console = Console()


def get_connection():
    return sqlite3.connect(DB_PATH)
def get_known_macs():
    """
    Return a set of all MAC addresses currently in the inventory.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT mac FROM devices")

    macs = {
        row[0]
        for row in cursor.fetchall()
        if row[0]
    }

    conn.close()

    return macs

def show_inventory():
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
            score,
            first_seen,
            last_seen
        FROM devices
        ORDER BY ip
    """)

    rows = cursor.fetchall()

    conn.close()

    table = Table(title="Device Inventory", expand=True)

    table.add_column("IP", style="cyan")
    table.add_column("Hostname", style="green")
    table.add_column("MAC", style="magenta")
    table.add_column("Vendor", style="blue")
    table.add_column("Status", style="yellow")
    table.add_column("Risk", style="red")
    table.add_column("Score", justify="right")
    table.add_column("First Seen")
    table.add_column("Last Seen")

    for row in rows:
        table.add_row(*[str(x) for x in row])

    console.print(table)

def get_online_devices():
    """
    Return all devices currently marked Online.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT mac, ip, hostname
        FROM devices
        WHERE status='Online'
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows

def main():
    show_inventory()

if __name__ == "__main__":
    main()

"""
Home SOC - Reporting Module

Generates reports from the Home SOC SQLite database.
"""

import sqlite3
from pathlib import Path

from rich.console import Console
from rich.table import Table

DB_PATH = Path("data/home_soc.db")

console = Console()


def get_connection():
    """
    Open a connection to the Home SOC database.
    """
    return sqlite3.connect(DB_PATH)


def show_latest_scan():
    """
    Display the latest network scan stored in the database.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, scan_time
        FROM scans
        ORDER BY id DESC
        LIMIT 1
    """)

    scan = cursor.fetchone()

    if not scan:
        console.print("[yellow]No scans found.[/yellow]")
        conn.close()
        return

    scan_id, scan_time = scan

    console.print(f"\n[bold cyan]Latest Scan[/bold cyan]")
    console.print(f"Scan ID: {scan_id}")
    console.print(f"Time: {scan_time}\n")

    cursor.execute("""
        SELECT
            ip,
            hostname,
            mac,
            vendor,
            ports,
            risk,
            score
        FROM scan_results
        WHERE scan_id = ?
        ORDER BY ip
    """, (scan_id,))

    rows = cursor.fetchall()

    table = Table(title="Scan Results", expand=True)

    table.add_column("IP", style="cyan")
    table.add_column("Hostname", style="green")
    table.add_column("MAC", style="magenta")
    table.add_column("Vendor", style="blue")
    table.add_column("Ports", style="yellow")
    table.add_column("Risk", style="red")
    table.add_column("Score", justify="right")

    for row in rows:
        table.add_row(*[str(x) for x in row])

    console.print(table)

    conn.close()

def show_scan_summary():
    """
    Display overall statistics for the Home SOC database.
    """
    conn = get_connection()
    cursor = conn.cursor()

    total_scans = cursor.execute(
        "SELECT COUNT(*) FROM scans"
    ).fetchone()[0]

    total_devices = cursor.execute(
        "SELECT COUNT(DISTINCT ip) FROM scan_results"
    ).fetchone()[0]

    high = cursor.execute(
        "SELECT COUNT(*) FROM scan_results WHERE risk='High'"
    ).fetchone()[0]

    medium = cursor.execute(
        "SELECT COUNT(*) FROM scan_results WHERE risk='Medium'"
    ).fetchone()[0]

    low = cursor.execute(
        "SELECT COUNT(*) FROM scan_results WHERE risk='Low'"
    ).fetchone()[0]

    console.print("\n[bold cyan]Home SOC Summary[/bold cyan]")
    console.print(f"Total scans      : {total_scans}")
    console.print(f"Devices observed : {total_devices}")
    console.print(f"[red]High Risk[/red]   : {high}")
    console.print(f"[yellow]Medium Risk[/yellow] : {medium}")
    console.print(f"[green]Low Risk[/green]    : {low}")

    conn.close()

def main():
    show_scan_summary()
    show_latest_scan()

if __name__ == "__main__":
    main()

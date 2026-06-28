"""
Home SOC v2.0
Device Inventory Management
"""

from __future__ import annotations

from typing import Any, Dict, List, Set

from rich.console import Console
from rich.table import Table

from python.core.database import (
    get_devices,
    get_device,
)

console = Console()


# ----------------------------------------------------------
# Inventory Queries
# ----------------------------------------------------------

def get_known_macs() -> Set[str]:
    """
    Return every MAC address currently stored
    in the Home SOC inventory.
    """

    return {
        device["mac"]
        for device in get_devices()
        if device.get("mac")
    }


def get_online_devices() -> List[Dict[str, Any]]:
    """
    Return devices currently marked Online.
    """

    return [
        device
        for device in get_devices()
        if device.get("status") == "Online"
    ]


def get_offline_devices() -> List[Dict[str, Any]]:
    """
    Return devices currently marked Offline.
    """

    return [
        device
        for device in get_devices()
        if device.get("status") == "Offline"
    ]


def find_device(mac: str) -> Dict[str, Any] | None:
    """
    Lookup a device by MAC address.
    """

    return get_device(mac)


# ----------------------------------------------------------
# Display Inventory
# ----------------------------------------------------------

def show_inventory() -> None:
    """
    Pretty-print the inventory.
    """

    devices = get_devices()

    table = Table(
        title="Home SOC Device Inventory",
        expand=True,
    )

    table.add_column("IP", style="cyan")
    table.add_column("Hostname", style="green")
    table.add_column("MAC", style="magenta")
    table.add_column("Vendor", style="blue")
    table.add_column("Status", style="yellow")
    table.add_column("Risk", style="red")
    table.add_column("Score", justify="right")
    table.add_column("First Seen")
    table.add_column("Last Seen")

    for device in devices:

        table.add_row(
            str(device.get("ip", "")),
            str(device.get("hostname", "")),
            str(device.get("mac", "")),
            str(device.get("vendor", "")),
            str(device.get("status", "")),
            str(device.get("risk", "")),
            str(device.get("score", "")),
            str(device.get("first_seen", "")),
            str(device.get("last_seen", "")),
        )

    console.print(table)


# ----------------------------------------------------------
# Statistics
# ----------------------------------------------------------

def inventory_summary() -> Dict[str, int]:
    """
    Return useful inventory statistics.
    """

    devices = get_devices()

    return {
        "total": len(devices),
        "online": sum(
            d.get("status") == "Online"
            for d in devices
        ),
        "offline": sum(
            d.get("status") == "Offline"
            for d in devices
        ),
        "high_risk": sum(
            d.get("risk") == "High"
            for d in devices
        ),
        "medium_risk": sum(
            d.get("risk") == "Medium"
            for d in devices
        ),
        "low_risk": sum(
            d.get("risk") == "Low"
            for d in devices
        ),
    }


# ----------------------------------------------------------
# CLI
# ----------------------------------------------------------

def main() -> None:

    show_inventory()

    stats = inventory_summary()

    console.print()

    console.print(
        f"[bold cyan]Total Devices:[/bold cyan] {stats['total']}"
    )

    console.print(
        f"[green]Online:[/green] {stats['online']}"
    )

    console.print(
        f"[yellow]Offline:[/yellow] {stats['offline']}"
    )

    console.print(
        f"[red]High Risk:[/red] {stats['high_risk']}"
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Home SOC v2.0
Advanced Network Scanner

Performs:
- Local network discovery
- ARP neighbour discovery
- Ping sweep
- TCP port scan
- MAC vendor lookup
- Risk scoring
- SQLite inventory integration
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import psutil
import requests

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.table import Table

from python.core.database import (
    initialize_database,
    save_scan,
)

from python.core.inventory import (
    get_known_macs,
)

from python.core.alerts import (
    new_device,
)

logger = logging.getLogger(__name__)

console = Console()

VENDOR_CACHE = Path("data/vendor_cache.json")

# ---------------------------------------------------------
# Vendor Cache
# ---------------------------------------------------------

def load_vendor_cache() -> dict[str, str]:
    """
    Load cached MAC vendor lookups.
    """

    if not VENDOR_CACHE.exists():
        return {}

    try:

        with VENDOR_CACHE.open(
            "r",
            encoding="utf-8",
        ) as fp:

            return json.load(fp)

    except Exception:

        logger.warning(
            "Unable to read vendor cache."
        )

        return {}


def save_vendor_cache(
    cache: dict[str, str],
) -> None:
    """
    Save vendor cache to disk.
    """

    VENDOR_CACHE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with VENDOR_CACHE.open(
        "w",
        encoding="utf-8",
    ) as fp:

        json.dump(
            cache,
            fp,
            indent=4,
            sort_keys=True,
        )


_VENDOR_CACHE = load_vendor_cache()

# -----------------------------
# Configuration
# -----------------------------

PING_TIMEOUT = 1
PORT_TIMEOUT = 0.20
MAX_THREADS = 100

COMMON_PORTS = [
    21,     # FTP
    22,     # SSH
    23,     # Telnet
    25,     # SMTP
    53,     # DNS
    80,     # HTTP
    110,    # POP3
    135,    # RPC
    139,    # NetBIOS
    143,    # IMAP
    443,    # HTTPS
    445,    # SMB
    3389    # RDP
]
# -----------------------------
# Local Network Discovery
# -----------------------------

def get_local_network():
    """
    Return the local IPv4 network.
    """
    for _, addresses in psutil.net_if_addrs().items():
        for addr in addresses:
            if addr.family != socket.AF_INET:
                continue

            if addr.address.startswith("127."):
                continue

            return ipaddress.ip_network(
                f"{addr.address}/{addr.netmask}",
                strict=False,
            )

    return ipaddress.ip_network("127.0.0.0/24")
# -----------------------------
# ARP / Neighbor Discovery
# -----------------------------

def get_neighbors():
    """
    Read IPv4 neighbors from the kernel ARP table.
    """

    neighbors = []

    try:

        output = subprocess.check_output(
            ["ip", "neigh"],
            text=True
        )

        for line in output.splitlines():

            parts = line.split()

            if len(parts) < 5:
                continue

            ip = parts[0]

            if ":" in ip:
                continue

            if "lladdr" not in parts:
                continue

            mac = parts[parts.index("lladdr") + 1]

            neighbors.append({
                "ip": ip,
                "mac": mac
            })

    except Exception:
        pass

    return neighbors


# -----------------------------
# Ping
# -----------------------------

def ping(ip):
    """
    Returns True if the host responds.
    """

    return subprocess.call(
        [
            "ping",
            "-c",
            "1",
            "-W",
            str(PING_TIMEOUT),
            str(ip)
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ) == 0


# -----------------------------
# Hostname Lookup
# -----------------------------

def get_hostname(ip):

    try:
        return socket.gethostbyaddr(str(ip))[0]

    except Exception:
        return "-"
# -----------------------------
# MAC Address Lookup
# -----------------------------

def get_mac(ip):
    """
    Get a MAC address from the local ARP cache.
    """

    try:
        output = subprocess.check_output(
            ["ip", "neigh", "show", str(ip)],
            text=True
        )

        parts = output.split()

        if "lladdr" in parts:
            return parts[parts.index("lladdr") + 1]

    except Exception:
        pass

    return "-"


# -----------------------------
# Vendor Lookup
# -----------------------------

def is_randomized_mac(mac):
    """
    Return True if the MAC address is locally administered
    (randomized/private MAC).
    """
    try:
        first_byte = int(mac.split(":")[0], 16)
        return (first_byte & 0x02) != 0
    except Exception:
        return False

def get_vendor(mac: str) -> str:
    """
    Resolve a MAC address to a vendor.
    Results are cached locally.
    """

    if not mac or mac == "-":
        return "Unknown"

    if is_randomized_mac(mac):
        return "Randomized MAC"

    prefix = mac.upper()[:8]

    if prefix in _VENDOR_CACHE:
        return _VENDOR_CACHE[prefix]

    try:

        response = requests.get(
            f"https://api.macvendors.com/{mac}",
            timeout=2,
        )

        if response.status_code == 200:

            vendor = response.text.strip()

            if vendor:

                _VENDOR_CACHE[prefix] = vendor

                save_vendor_cache(
                    _VENDOR_CACHE,
                )

                return vendor

    except Exception as exc:

        logger.debug(
            "Vendor lookup failed: %s",
            exc,
        )

    return "Unknown Vendor"

# -----------------------------
# TCP Port Scan
# -----------------------------


def scan_port(ip: str, port: int) -> int | None:
    """
    Scan a single TCP port.
    Returns the port number if it is open.
    """

    try:

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        ) as sock:

            sock.settimeout(PORT_TIMEOUT)

            if sock.connect_ex((str(ip), port)) == 0:
                return port

    except Exception as exc:

        logger.debug(
            "Port %s on %s failed: %s",
            port,
            ip,
            exc,
        )

    return None


def scan_ports(ip: str) -> list[int]:
    """
    Scan common TCP ports concurrently.
    """

    open_ports: list[int] = []

    with ThreadPoolExecutor(max_workers=32) as executor:

        futures = {
            executor.submit(scan_port, ip, port): port
            for port in COMMON_PORTS
        }

        for future in as_completed(futures):

            result = future.result()

            if result is not None:
                open_ports.append(result)

    return sorted(open_ports)

# -----------------------------
# Risk Scoring
# -----------------------------

def calculate_risk(open_ports):

    score = 0

    if 21 in open_ports:
        score += 3

    if 23 in open_ports:
        score += 5

    if 445 in open_ports:
        score += 3

    if 3389 in open_ports:
        score += 4

    if 22 in open_ports:
        score += 1

    if score >= 7:
        risk = "High"

    elif score >= 3:
        risk = "Medium"

    else:
        risk = "Low"

    return risk, score


# -----------------------------
# Host Scanner
# -----------------------------

def scan_host(ip: str) -> dict[str, Any] | None:
    """
    Scan a single host and return a normalized device record.
    """

    ip = str(ip)

    logger.debug("Scanning host %s", ip)

    alive = ping(ip)

    if not alive:
        return None

    hostname = get_hostname(ip)

    if not hostname or hostname == "-":
        hostname = "Unknown"

    mac = get_mac(ip).upper()

    if not mac:
        mac = "-"

    vendor = get_vendor(mac)

    open_ports = scan_ports(ip)

    risk, score = calculate_risk(open_ports)

    # Simple fingerprint
    if 22 in open_ports:
        device_type = "Linux/Unix"

    elif 3389 in open_ports:
        device_type = "Windows"

    elif 80 in open_ports or 443 in open_ports:
        device_type = "Web Device"

    elif 445 in open_ports:
        device_type = "File Server"

    else:
        device_type = "Unknown"

    return {

        "ip": ip,

        "hostname": hostname,

        "mac": mac,

        "vendor": vendor,

        "device_type": device_type,

        "ports": (
            ", ".join(
                map(str, open_ports)
            )
            if open_ports
            else "-"
        ),

        "open_ports": open_ports,

        "risk": risk,

        "score": score,

        "alive": True,

        "scan_time": time.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

    }

# -----------------------------
# Network Scan Engine
# -----------------------------
def run_network_scan() -> list[dict[str, Any]]:
    """
    Discover and scan devices on the local network.
    """

    network = get_local_network()

    console.print(
        f"\n[bold cyan]Scanning network[/bold cyan] {network}\n"
    )

    start_time = time.perf_counter()

    # ---------------------------------------------------------
    # Build host list
    # ---------------------------------------------------------

    hosts = {str(ip) for ip in network.hosts()}

    for neighbor in get_neighbors():
        hosts.add(neighbor["ip"])

    hosts = sorted(
        (
            ip
            for ip in hosts
            if ":" not in ip
        ),
        key=ipaddress.ip_address,
    )

    logger.info(
        "Scanning %s hosts",
        len(hosts),
    )

    discovered: list[dict[str, Any]] = []

    with Progress(

        SpinnerColumn(),

        TextColumn(
            "[progress.description]{task.description}"
        ),

        BarColumn(),

        TaskProgressColumn(),

    ) as progress:

        task = progress.add_task(
            "Scanning...",
            total=len(hosts),
        )

        with ThreadPoolExecutor(
            max_workers=MAX_THREADS,
        ) as executor:

            futures = {
                executor.submit(
                    scan_host,
                    ip,
                ): ip
                for ip in hosts
            }

            for future in as_completed(futures):

                ip = futures[future]

                try:

                    device = future.result()

                    if device:

                        discovered.append(
                            device
                        )

                except Exception as exc:

                    logger.exception(
                        "Host %s failed: %s",
                        ip,
                        exc,
                    )

                finally:

                    progress.update(
                        task,
                        advance=1,
                    )

    discovered.sort(
        key=lambda d: ipaddress.ip_address(
            d["ip"]
        )
    )

    duration = (
        time.perf_counter()
        - start_time
    )

    logger.info(
        "Finished scan in %.2f seconds",
        duration,
    )

    console.print(
        f"\n[green]Completed in "
        f"{duration:.2f} seconds[/green]\n"
    )

    table = Table(
        title="Discovered Devices",
        expand=True,
    )

    table.add_column(
        "IP",
        style="cyan",
        no_wrap=True,
    )

    table.add_column(
        "Hostname",
        style="green",
    )

    table.add_column(
        "MAC",
        style="magenta",
    )

    table.add_column(
        "Vendor",
        style="blue",
    )

    table.add_column(
        "Ports",
        style="yellow",
    )

    table.add_column(
        "Risk",
        style="red",
        justify="center",
    )

    table.add_column(
        "Score",
        justify="right",
    )

    for device in discovered:

        table.add_row(

            device["ip"],

            device["hostname"],

            device["mac"],

            device["vendor"],

            device["ports"],

            device["risk"],

            str(device["score"]),

        )

    console.print(table)

    logger.info(
        "%s devices discovered",
        len(discovered),
    )

    return discovered

# -----------------------------
# Security Summary
# -----------------------------

def print_security_summary(discovered):
    """
    Display a summary of the scan results.
    """

    high = sum(1 for d in discovered if d["risk"] == "High")
    medium = sum(1 for d in discovered if d["risk"] == "Medium")
    low = sum(1 for d in discovered if d["risk"] == "Low")

    console.print("\n[bold cyan]Security Summary[/bold cyan]")
    console.print(f"[green]Low Risk:[/green] {low}")
    console.print(f"[yellow]Medium Risk:[/yellow] {medium}")
    console.print(f"[red]High Risk:[/red] {high}")

    console.print(
        f"\n[green]Scan complete.[/green] "
        f"Found [bold]{len(discovered)}[/bold] active device(s).\n"
    )


# -----------------------------
# Main
# -----------------------------

def main():
    initialize_database()

    # Snapshot of devices already known before scanning
    known_macs = get_known_macs()

    discovered = run_network_scan()

    active_macs = {
        device["mac"]
        for device in discovered
        if device["mac"] and device["mac"] != "-"
    }

    print(f"\nDEBUG: Devices found = {len(discovered)}")

    # Alert on newly discovered devices
    for device in discovered:
        mac = device.get("mac")

        if mac and mac != "-" and mac not in known_macs:
            new_device(device)

    save_scan(discovered)
    mark_offline_devices(active_macs)
    print_security_summary(discovered)
if __name__ == "__main__":
    main()

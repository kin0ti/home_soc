#!/usr/bin/env python3
"""
Home SOC - Network Scanner

Performs:
- Local network discovery
- ARP neighbor discovery
- Ping sweep
- TCP port scan
- MAC vendor lookup
- Risk scoring
"""

import ipaddress
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil
import requests

from python.modules.database import (
    initialize_database,
    save_scan,
    mark_offline_devices,
)

from python.modules.inventory import get_known_macs
from python.modules.alerts import new_device

from rich.console import Console
from rich.progress import Progress
from rich.table import Table

console = Console()

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

def get_vendor(mac):
    """
    Lookup the vendor from a MAC address.
    """

    if mac == "-":
        return "-"

    try:

        response = requests.get(
            f"https://api.macvendors.com/{mac}",
            timeout=2
        )

        if response.status_code == 200:
            return response.text.strip()

    except Exception:
        pass

    return "-"


# -----------------------------
# TCP Port Scan
# -----------------------------

def scan_ports(ip):
    """
    Scan common TCP ports.
    """

    open_ports = []

    for port in COMMON_PORTS:

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(PORT_TIMEOUT)

            if sock.connect_ex((str(ip), port)) == 0:
                open_ports.append(port)

            sock.close()

        except Exception:
            pass

    return open_ports


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

def scan_host(ip):
    """
    Scan one host.
    """

    ip = str(ip)

    alive = ping(ip)

    hostname = get_hostname(ip)

    mac = get_mac(ip)

    vendor = get_vendor(mac)

    if alive:
        open_ports = scan_ports(ip)
    else:
        open_ports = []

    risk, score = calculate_risk(open_ports)

    # Ignore inactive hosts
    if not alive:
           return None

    return {
             "ip": ip,
             "hostname": hostname,
             "mac": mac,
             "vendor": vendor,
             "ports": ", ".join(map(str, open_ports)) if open_ports else "-",
             "risk": risk,
             "score": score,
    }
# -----------------------------
# Network Scan Engine
# -----------------------------

def run_network_scan():
    """
    Discover and scan devices on the local network.
    """

    network = get_local_network()
    

    console.print(f"\n[cyan]Scanning network {network}[/cyan]\n")

    # Hosts from subnet
    hosts = {str(ip) for ip in network.hosts()}

    # Add hosts already in ARP cache
    for neighbor in get_neighbors():
        hosts.add(neighbor["ip"])

    # Keep IPv4 only
    hosts = [
        ip for ip in hosts
        if ":" not in ip
    ]

    hosts = sorted(
        hosts,
        key=lambda ip: ipaddress.ip_address(ip)
    )

    discovered = []

    with Progress() as progress:

        task = progress.add_task(
            "[green]Scanning hosts...",
            total=len(hosts)
        )

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:

            futures = {
                executor.submit(scan_host, ip): ip
                for ip in hosts
            }

            for future in as_completed(futures):

                try:

                    device = future.result()

                    if device:
                        discovered.append(device)

                except Exception:
                    pass

                progress.update(task, advance=1)

    discovered.sort(
        key=lambda d: ipaddress.ip_address(d["ip"])
    )

    table = Table(
        title="Discovered Devices",
        expand=True
    )

    table.add_column(
        "IP Address",
        style="cyan",
        no_wrap=True
    )

    table.add_column(
        "Hostname",
        style="green"
    )

    table.add_column(
        "MAC Address",
        style="magenta",
        no_wrap=True
    )

    table.add_column(
        "Vendor",
        style="blue"
    )

    table.add_column(
        "Open Ports",
        style="yellow"
    )

    table.add_column(
        "Risk",
        style="red",
        justify="center"
    )

    table.add_column(
        "Score",
        justify="right"
    )

    for device in discovered:

        table.add_row(
            device["ip"],
            device["hostname"],
            device["mac"],
            device["vendor"],
            device["ports"],
            device["risk"],
            str(device["score"])
        )

    console.print(table)

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

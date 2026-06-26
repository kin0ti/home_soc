#!/usr/bin/env python3

"""
Home-SOC Network Scanner

Features
--------
- Automatic network detection
- Neighbor (ARP) discovery
- ICMP host discovery
- Hostname lookup
- MAC address lookup
- MAC vendor lookup
- Common TCP port scan
- Risk scoring
- Rich terminal output
"""

import ipaddress
import socket
import subprocess
import requests
import psutil

from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.progress import Progress
from rich.table import Table


console = Console()

PING_TIMEOUT = 1
PORT_TIMEOUT = 0.20
MAX_THREADS = 100


COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    3389,
]


def get_local_network():
    """
    Detect the currently active IPv4 network.
    """

    interfaces = psutil.net_if_addrs()

    for interface, addresses in interfaces.items():

        if interface == "lo":
            continue

        for addr in addresses:

            if addr.family != socket.AF_INET:
                continue

            ip = addr.address

            if ip.startswith("127."):
                continue

            octets = ip.split(".")
            network = ".".join(octets[:3]) + ".0/24"

            return ipaddress.ip_network(network, strict=False)

    return ipaddress.ip_network("127.0.0.0/24")


def ping(ip):
    """
    Return True if host responds to ICMP.
    """

    return (
        subprocess.call(
            ["ping", "-c", "1", "-W", str(PING_TIMEOUT), str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        == 0
    )


def get_hostname(ip):
    """
    Resolve hostname.
    """

    try:
        return socket.gethostbyaddr(str(ip))[0]
    except Exception:
        return "-"
def get_mac(ip):
    """
    Get the MAC address for an IP from the neighbor/ARP table.
    """

    try:
        output = subprocess.check_output(
            ["ip", "neigh", "show", str(ip)],
            text=True,
            stderr=subprocess.DEVNULL,
        )

        if "lladdr" in output:
            parts = output.split()

            if "lladdr" in parts:
                return parts[parts.index("lladdr") + 1]

    except Exception:
        pass

    return "-"


def get_vendor(mac):
    """
    Lookup the hardware vendor from a MAC address.
    """

    if mac == "-":
        return "-"

    try:
        response = requests.get(
            f"https://api.macvendors.com/{mac}",
            timeout=2,
        )

        if response.status_code == 200:
            return response.text.strip()

    except Exception:
        pass

    return "-"


def scan_ports(ip):
    """
    Scan common TCP ports.
    """

    open_ports = []

    for port in COMMON_PORTS:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PORT_TIMEOUT)

        try:
            if sock.connect_ex((str(ip), port)) == 0:
                open_ports.append(port)
        finally:
            sock.close()

    return open_ports


def get_neighbors():
    """
    Read reachable devices from the Linux neighbor table.
    """

    devices = []

    try:
        output = subprocess.check_output(
            ["ip", "neigh"],
            text=True,
        )

        for line in output.splitlines():

            parts = line.split()
  if len(parts) >= 5:

    ip = parts[0]

    # Skip IPv6 addresses
    if ":" in ip:
        continue

    # Skip incomplete entries
    if parts[4] == "FAILED":
        continue

    neighbors.append({
        "ip": ip,
        "mac": parts[4]
    })

    except Exception:
        pass

    return devices


def calculate_risk(open_ports):
    """
    Assign a simple security score based on open ports.
    """

    score = 0

    if 23 in open_ports:
        score += 40

    if 21 in open_ports:
        score += 25

    if 445 in open_ports:
        score += 25

    if 3389 in open_ports:
        score += 20

    if 22 in open_ports:
        score += 10

    if score >= 50:
        return "High", score

    if score >= 20:
        return "Medium", score

    return "Low", score
def scan_host(ip):
    """
    Scan one host.
    """

    ip = str(ip)

    alive = ping(ip)

    mac = get_mac(ip)

    # If the host did not respond but exists in the ARP cache,
    # still consider it discovered.
    if not alive and mac == "-":
        return None

    hostname = get_hostname(ip)
    vendor = get_vendor(mac)

    open_ports = scan_ports(ip)

    risk, score = calculate_risk(open_ports)

    return {
        "ip": ip,
        "hostname": hostname,
        "mac": mac,
        "vendor": vendor,
        "ports": ", ".join(map(str, open_ports)) if open_ports else "-",
        "risk": risk,
        "score": score,
    }


def run_network_scan():
    """
    Scan the local network.
    """

    network = get_local_network()

    console.print(
        f"\n[cyan]Scanning network {network}[/cyan]\n"
    )

    subnet_hosts = {
        str(ip)
        for ip in network.hosts()
    }

    neighbor_hosts = {
        entry["ip"]
        for entry in get_neighbors()
    }

    hosts = sorted(
        subnet_hosts | neighbor_hosts,
        key=ipaddress.ip_address,
    )

    discovered = []

    with Progress() as progress:

        task = progress.add_task(
            "[green]Scanning hosts...",
            total=len(hosts),
        )

        with ThreadPoolExecutor(
            max_workers=MAX_THREADS
        ) as executor:

            futures = {
                executor.submit(
                    scan_host,
                    ip,
                ): ip
                for ip in hosts
            }

            for future in as_completed(futures):

                try:

                    result = future.result()

                    if result:
                        discovered.append(result)

                except Exception:
                    pass

                progress.update(
                    task,
                    advance=1,
                )

    discovered.sort(
        key=lambda d: ipaddress.ip_address(d["ip"])
    )
    table = Table(
        title="Discovered Devices",
        expand=True,
        show_lines=False,
    )

    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("Hostname", style="green", no_wrap=True)
    table.add_column("MAC Address", style="magenta", no_wrap=True)
    table.add_column("Vendor", style="blue")
    table.add_column("Open Ports", style="yellow", no_wrap=True)
    table.add_column("Risk", style="red", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)

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

    return discovered


def print_security_summary(discovered):
    """
    Print a summary of the scan results.
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
# ----------------------------------------
# Main
# ----------------------------------------

def main():
    """
    Entry point.
    """
    discovered = run_network_scan()
    print_security_summary(discovered)


if __name__ == "__main__":
    main()

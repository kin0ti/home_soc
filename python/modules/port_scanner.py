import socket

from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()

COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP Alt"
}


def scan_port(ip, port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)

    result = sock.connect_ex((str(ip), port))

    sock.close()

    return result == 0


def run_port_scan(ip):

    console.print(f"\n[cyan]Scanning {ip}...[/cyan]\n")

    open_ports = []

    with Progress() as progress:

        task = progress.add_task(
            "[green]Checking Ports...",
            total=len(COMMON_PORTS)
        )

        with ThreadPoolExecutor(max_workers=50) as executor:

            futures = {
                executor.submit(scan_port, ip, port): port
                for port in COMMON_PORTS
            }

            for future in as_completed(futures):

                port = futures[future]

                try:

                    if future.result():
                        open_ports.append(port)

                except Exception:
                    pass

                progress.update(task, advance=1)

    table = Table(title=f"Open Ports on {ip}")

    table.add_column("Port", style="cyan")
    table.add_column("Service", style="green")

    for port in sorted(open_ports):

        table.add_row(
            str(port),
            COMMON_PORTS[port]
        )

    console.print(table)

    console.print(
        f"\n[green]Found {len(open_ports)} open port(s).[/green]"
    )


if __name__ == "__main__":

    target = input("Target IP: ")

    run_port_scan(target)

"""
Home SOC - Alert Engine
"""

from rich.console import Console

console = Console()


def new_device(device):
    console.print(
        f"[bold green][NEW DEVICE][/bold green] "
        f"{device['ip']} ({device['vendor']})"
    )


def device_offline(device):
    console.print(
        f"[bold red][OFFLINE][/bold red] "
        f"{device['hostname']} ({device['ip']})"
    )


def ip_changed(old_ip, new_ip, mac):
    console.print(
        f"[bold yellow][IP CHANGED][/bold yellow] "
        f"{mac}: {old_ip} → {new_ip}"
    )


def risk_changed(hostname, old_risk, new_risk):
    console.print(
        f"[bold magenta][RISK CHANGED][/bold magenta] "
        f"{hostname}: {old_risk} → {new_risk}"
    )

"""
Home SOC v2.0
Alert Engine
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import sqlite3

from rich.console import Console

console = Console()

LOG_DIR = Path("logs")
ALERT_LOG = LOG_DIR / "alerts.log"
DB_PATH = Path("data/home_soc.db")
LOG_DIR.mkdir(parents=True, exist_ok=True)


# ----------------------------------------------------------
# Internal Helpers
# ----------------------------------------------------------

def _timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _write(message: str) -> None:
    """
    Write alerts to disk for auditing.
    """

    with ALERT_LOG.open("a", encoding="utf-8") as logfile:
        logfile.write(f"[{_timestamp()}] {message}\n")
def _save_alert(
    severity: str,
    category: str,
    message: str,
    hostname: str = "",
    ip: str = "",
    mac: str = "",
) -> None:
    """
    Save an alert to the database.
    """

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO alerts
        (
            alert_time,
            severity,
            category,
            hostname,
            ip,
            mac,
            message
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _timestamp(),
            severity,
            category,
            hostname,
            ip,
            mac,
            message,
        ),
    )

    conn.commit()
    conn.close()

def _alert(
    style: str,
    title: str,
    message: str,
    hostname: str = "",
    ip: str = "",
    mac: str = "",
) -> None:
    """
    Display, log and save an alert.
    """

    console.print(f"[bold {style}][{title}][/bold {style}] {message}")

    _write(f"{title}: {message}")

    _save_alert(
        severity=style,
        category=title,
        message=message,
        hostname=hostname,
        ip=ip,
        mac=mac,
    )

# ----------------------------------------------------------
# Device Alerts
# ----------------------------------------------------------

def new_device(device: Dict[str, Any]) -> None:

    _alert(
        "green",
        "NEW DEVICE",
        (
            f"{device.get('hostname', 'Unknown')} "
            f"({device.get('ip', 'Unknown')}) "
            f"[{device.get('vendor', 'Unknown Vendor')}]"
        ),
        hostname=device.get("hostname", ""),
        ip=device.get("ip", ""),
        mac=device.get("mac", ""),
    )

def device_online(device: Dict[str, Any]) -> None:

    _alert(
        "cyan",
        "ONLINE",
        (
            f"{device.get('hostname', 'Unknown')} "
            f"({device.get('ip', 'Unknown')})"
        ),
    )


def device_offline(device: Dict[str, Any]) -> None:

    _alert(
        "red",
        "OFFLINE",
        (
            f"{device.get('hostname', 'Unknown')} "
            f"({device.get('ip', 'Unknown')})"
        ),
    )


# ----------------------------------------------------------
# Change Alerts
# ----------------------------------------------------------

def ip_changed(old_ip: str, new_ip: str, mac: str) -> None:

    _alert(
        "yellow",
        "IP CHANGED",
        f"{mac}: {old_ip} → {new_ip}",
    )


def hostname_changed(old: str, new: str, mac: str) -> None:

    _alert(
        "blue",
        "HOSTNAME CHANGED",
        f"{mac}: {old} → {new}",
    )


def vendor_changed(old: str, new: str, mac: str) -> None:

    _alert(
        "bright_blue",
        "VENDOR CHANGED",
        f"{mac}: {old} → {new}",
    )


def risk_changed(hostname: str, old_risk: str, new_risk: str) -> None:

    _alert(
        "magenta",
        "RISK CHANGED",
        f"{hostname}: {old_risk} → {new_risk}",
    )


# ----------------------------------------------------------
# Security Alerts
# ----------------------------------------------------------

def suspicious_ports(device: Dict[str, Any], ports: str) -> None:

    _alert(
        "bright_red",
        "SUSPICIOUS PORTS",
        (
            f"{device.get('hostname', 'Unknown')} "
            f"({device.get('ip', 'Unknown')}) "
            f"Ports: {ports}"
        ),
    )


def critical_risk(device: Dict[str, Any]) -> None:

    _alert(
        "red",
        "CRITICAL RISK",
        (
            f"{device.get('hostname', 'Unknown')} "
            f"({device.get('ip', 'Unknown')}) "
            f"Score={device.get('score', 0)}"
        ),
    )


def warning(message: str) -> None:

    _alert(
        "yellow",
        "WARNING",
        message,
    )


def info(message: str) -> None:

    _alert(
        "cyan",
        "INFO",
        message,
    )


def error(message: str) -> None:

    _alert(
        "red",
        "ERROR",
        message,
    )

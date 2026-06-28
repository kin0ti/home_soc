"""
Home SOC v2.0
Database Layer
"""

from __future__ import annotations

import logging
import sqlite3

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, List

logger = logging.getLogger(__name__)

DB_PATH = Path("data/home_soc.db")


# ----------------------------------------------------------
# Connection Management
# ----------------------------------------------------------

@contextmanager
def get_connection() -> Generator[sqlite3.Connection, None, None]:
    """
    Managed SQLite connection.

    Automatically:
      • creates the database directory
      • enables foreign keys
      • returns sqlite3.Row objects
      • commits on success
      • rolls back on failure
    """

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(
        DB_PATH,
        check_same_thread=False,
    )

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys = ON")

    try:
        yield conn
        conn.commit()

    except Exception:
        conn.rollback()
        logger.exception("Database transaction failed.")
        raise

    finally:
        conn.close()


# ----------------------------------------------------------
# Database Initialisation
# ----------------------------------------------------------

def initialize_database() -> None:
    """
    Create database tables and upgrade older databases.
    Safe to call every startup.
    """

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS devices
            (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                mac TEXT UNIQUE,
                ip TEXT,
                hostname TEXT,
                vendor TEXT,

                first_seen TEXT,
                last_seen TEXT,

                status TEXT,

                risk TEXT,
                score INTEGER,

                notes TEXT
                
               device_type TEXT,
               os_guess TEXT,
               last_ports TEXT
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans
            (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                scan_time TEXT NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_results
            (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                scan_id INTEGER NOT NULL,

                ip TEXT,
                hostname TEXT,
                mac TEXT,
                vendor TEXT,

                ports TEXT,
                
                device_type TEXT,

                os_guess TEXT,

                risk TEXT,

                score INTEGER,

                FOREIGN KEY(scan_id)
                    REFERENCES scans(id)
                    ON DELETE CASCADE
            )
            """
        )

        _run_migrations(cursor)
        _create_indexes(cursor)


def _run_migrations(cursor: sqlite3.Cursor) -> None:
    """
    Upgrade older databases without losing data.
    """

    cursor.execute("PRAGMA table_info(devices)")

    existing = {row["name"] for row in cursor.fetchall()}

    required_columns = {
        "ip": "TEXT",
        "status": "TEXT",
        "risk": "TEXT",
        "score": "INTEGER",
        "notes": "TEXT",
    }

    required_columns = {
        "ip": "TEXT",
        "status": "TEXT",
        "risk": "TEXT",
        "score": "INTEGER",
        "notes": "TEXT",

        "device_type": "TEXT",
        "os_guess": "TEXT",
        "last_ports": "TEXT",
    }

    for column, datatype in required_columns.items():

        if column not in existing:

            logger.info("Adding missing column %s", column)

            cursor.execute(
                f"ALTER TABLE devices ADD COLUMN {column} {datatype}"
            )


def _create_indexes(cursor: sqlite3.Cursor) -> None:
    """
    Speed up lookups.
    """

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac)"
    )

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip)"
    )

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen)"
    )

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_results_scan ON scan_results(scan_id)"
    )

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_results_mac ON scan_results(mac)"
    )


# ----------------------------------------------------------
# Scan Storage
# ----------------------------------------------------------

def save_scan(discovered: Iterable[Dict[str, Any]]) -> int:
    """
    Save a completed network scan.

    Returns
    -------
    int
        Scan ID.
    """

    scan_time = datetime.now().isoformat(timespec="seconds")

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO scans(scan_time) VALUES (?)",
            (scan_time,),
        )

        scan_id = cursor.lastrowid

        active_macs: List[str] = []

        for device in discovered:

            ip = device.get("ip", "")
            hostname = device.get("hostname", "")
            mac = device.get("mac", "")
            ports = device.get("ports", "")
            device_type = device.get(
                "device_type",
                "Unknown",
            )

            os_guess = device.get(
                "os_guess",
                "Unknown",
            )
            vendor = device.get("vendor", "")
            risk = device.get("risk", "Unknown")
            score = device.get("score", 0)
            cursor.execute(
                """
                INSERT INTO scan_results
                (
                    scan_id,
                    ip,
                    hostname,
                    mac,
                    vendor,
                    ports,
                    risk,
                    score
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    ip,
                    hostname,
                    mac,
                    vendor,
                    str(ports),
                    risk,
                    score,
                ),
            )

            if mac:
                active_macs.append(mac)

            cursor.execute(
                """
                SELECT id
                FROM devices
                WHERE mac = ?
                """,
                (mac,),
            )

            existing = cursor.fetchone()

            if existing:

                cursor.execute(
                    """
                    UPDATE devices
                    SET
                        ip = ?,
                        hostname = ?,
                        vendor = ?,
                        last_seen = ?,
                        status = ?,
                        risk = ?,
                        score = ?
                    WHERE mac = ?
                    """,
                    (
                        ip,
                        hostname,
                        vendor,
                        scan_time,
                        "Online",
                        risk,
                        score,
                        mac,
                    ),
                )

            else:

                cursor.execute(
                    """
                    INSERT INTO devices
                    (
                        mac,
                        ip,
                        hostname,
                        vendor,
                        first_seen,
                        last_seen,
                        status,
                        risk,
                        score
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        mac,
                        ip,
                        hostname,
                        vendor,
                        scan_time,
                        scan_time,
                        "Online",
                        risk,
                        score,
                    ),
                )

        if active_macs:

            placeholders = ",".join("?" * len(active_macs))

            cursor.execute(
                f"""
                UPDATE devices
                SET status='Offline'
                WHERE mac NOT IN ({placeholders})
                """,
                active_macs,
            )

        else:

            cursor.execute(
                """
                UPDATE devices
                SET status='Offline'
                """
            )

        return scan_id


# ----------------------------------------------------------
# Query Functions
# ----------------------------------------------------------

def get_devices() -> List[Dict[str, Any]]:
    """
    Return all known devices.
    """

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM devices
            ORDER BY last_seen DESC
            """
        )

        return [dict(row) for row in cursor.fetchall()]


def get_device(mac: str) -> Dict[str, Any] | None:
    """
    Return a single device by MAC address.
    """

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM devices
            WHERE mac = ?
            """,
            (mac,),
        )

        row = cursor.fetchone()

        return dict(row) if row else None


def get_scan_history(limit: int = 100) -> List[Dict[str, Any]]:
    """
    Return previous scans.
    """

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )

        return [dict(row) for row in cursor.fetchall()]


def get_scan_results(scan_id: int) -> List[Dict[str, Any]]:
    """
    Return all devices discovered during a scan.
    """

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM scan_results
            WHERE scan_id = ?
            ORDER BY hostname
            """,
            (scan_id,),
        )

        return [dict(row) for row in cursor.fetchall()]


def update_device_notes(mac: str, notes: str) -> None:
    """
    Update analyst notes.
    """

    with get_connection() as conn:

        conn.execute(
            """
            UPDATE devices
            SET notes = ?
            WHERE mac = ?
            """,
            (
                notes,
                mac,
            ),
        )


def delete_scan(scan_id: int) -> None:
    """
    Delete a stored scan.
    """

    with get_connection() as conn:

        conn.execute(
            """
            DELETE FROM scans
            WHERE id = ?
            """,
            (scan_id,),
        )


def vacuum_database() -> None:
    """
    Reclaim unused database space.
    """

    with get_connection() as conn:

        conn.execute("VACUUM")

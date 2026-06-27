import sqlite3
from pathlib import Path
from datetime import datetime

DB_PATH = Path("data/home_soc.db")


def get_connection():
    """
    Open a connection to the Home SOC database.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def initialize_database():
    """
    Create the database tables.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
       CREATE TABLE IF NOT EXISTS devices (
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
       )
   """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip TEXT,
            hostname TEXT,
            mac TEXT,
            vendor TEXT,
            ports TEXT,
            risk TEXT,
            score INTEGER
        )
    """)

    conn.commit()

    # Upgrade existing databases safely
    existing_columns = {
        row[1] for row in cursor.execute("PRAGMA table_info(devices)")
    }

    new_columns = {
        "ip": "TEXT",
        "status": "TEXT",
        "risk": "TEXT",
        "score": "INTEGER",
        "notes": "TEXT",
    }

    for column, datatype in new_columns.items():
        if column not in existing_columns:
            cursor.execute(
               f"ALTER TABLE devices ADD COLUMN {column} {datatype}"
           )

    conn.commit()
    conn.close()
def save_scan(discovered):
    """
    Save a completed network scan to the database.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Timestamp for this scan
    scan_time = datetime.now().isoformat(timespec="seconds")

    # Create a new scan record
    cursor.execute(
        "INSERT INTO scans (scan_time) VALUES (?)",
        (scan_time,)
    )

    scan_id = cursor.lastrowid

    for device in discovered:

        # Insert scan result
        cursor.execute("""
            INSERT INTO scan_results (
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
        """, (
            scan_id,
            device["ip"],
            device["hostname"],
            device["mac"],
            device["vendor"],
            device["ports"],
            device["risk"],
            device["score"],
        ))

        # Update device inventory
        if device["mac"] and device["mac"] != "-":

            cursor.execute("""
                SELECT id
                FROM devices
                WHERE mac = ?
            """, (device["mac"],))

            existing = cursor.fetchone()

            if existing:

                cursor.execute("""
                    UPDATE devices
                    SET ip = ?,
                        hostname = ?,
                        vendor = ?,
                        last_seen = ?,
                        status = ?,
                        risk = ?,
                        score = ?
                    WHERE mac = ?
                """, (
                    device["ip"],
                    device["hostname"],
                    device["vendor"],
                    scan_time,
                    "Online",
                    device["risk"],
                    device["score"],
                    device["mac"],
                ))

            else:

                cursor.execute("""
                    INSERT INTO devices (
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
                """, (
                    (
                     device["mac"],
                     device["ip"],
                     device["hostname"],
                     device["vendor"],
                     scan_time,
                     scan_time,
                     "Online",
                     device["risk"],
                     device["score"],
                    )
                ))

    conn.commit()
    conn.close()

if __name__ == "__main__":
    initialize_database()
    print("Database created.")

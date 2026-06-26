import sqlite3
from pathlib import Path

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
            hostname TEXT,
            vendor TEXT,
            first_seen TEXT,
            last_seen TEXT
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
    conn.close()


if __name__ == "__main__":
    initialize_database()
    print("Database created.")

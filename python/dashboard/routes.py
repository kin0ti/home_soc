from flask import Blueprint, render_template
import sqlite3

dashboard = Blueprint("dashboard", __name__)

DATABASE = "data/home_soc.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# ----------------------------------------------------
# Dashboard
# ----------------------------------------------------

@dashboard.route("/")
def home():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM devices")
    total_devices = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM devices WHERE status='Online'")
    online_devices = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM devices WHERE status='Offline'")
    offline_devices = cur.fetchone()[0]

    cur.execute("""
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT 10
    """)

    alerts = cur.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        total_devices=total_devices,
        online_devices=online_devices,
        offline_devices=offline_devices,
        alerts=alerts,
    )


# ----------------------------------------------------
# Devices
# ----------------------------------------------------

@dashboard.route("/devices")
def devices():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT *
        FROM devices
        ORDER BY last_seen DESC
    """)

    devices = cur.fetchall()

    conn.close()

    return render_template(
        "devices.html",
        devices=devices,
    )


# ----------------------------------------------------
# Alerts
# ----------------------------------------------------

@dashboard.route("/alerts")
def alerts():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT *
        FROM alerts
        ORDER BY id DESC
    """)

    alerts = cur.fetchall()

    conn.close()

    return render_template(
        "alerts.html",
        alerts=alerts,
    )


# ----------------------------------------------------
# Scan History
# ----------------------------------------------------

@dashboard.route("/history")
def history():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT *
        FROM scans
        ORDER BY id DESC
    """)

    scans = cur.fetchall()

    conn.close()

    return render_template(
        "history.html",
        scans=scans,
    )


# ----------------------------------------------------
# Manual Scan Page
# ----------------------------------------------------

@dashboard.route("/scan")
def scan():
    return render_template("scan.html")


# ----------------------------------------------------
# Reports
# ----------------------------------------------------

@dashboard.route("/reports")
def reports():

    conn = get_db()
    cur = conn.cursor()

    # --------------------------
    # Summary
    # --------------------------

    cur.execute("SELECT COUNT(*) FROM devices")
    total_devices = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM devices WHERE status='Online'")
    online_devices = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM devices WHERE status='Offline'")
    offline_devices = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM scans")
    total_scans = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM devices WHERE risk='High'")
    high_risk = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM devices WHERE risk='Medium'")
    medium_risk = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM devices WHERE risk='Low'")
    low_risk = cur.fetchone()[0]

    # --------------------------
    # Vendors
    # --------------------------

    cur.execute("""
        SELECT
            vendor,
            COUNT(*) AS total
        FROM devices
        GROUP BY vendor
        ORDER BY total DESC
    """)

    vendors = cur.fetchall()

    # --------------------------
    # Risk Distribution
    # --------------------------

    cur.execute("""
        SELECT
            risk,
            COUNT(*) AS total
        FROM devices
        GROUP BY risk
        ORDER BY total DESC
    """)

    risks = cur.fetchall()

    # --------------------------
    # Device Status
    # --------------------------

    cur.execute("""
        SELECT
            status,
            COUNT(*) AS total
        FROM devices
        GROUP BY status
    """)

    statuses = cur.fetchall()

    # --------------------------
    # Timeline
    # --------------------------

    cur.execute("""
        SELECT
            MIN(first_seen) AS first_seen,
            MAX(last_seen) AS last_seen
        FROM devices
    """)

    timeline = cur.fetchone()

    conn.close()

    return render_template(
        "reports.html",
        total_devices=total_devices,
        online_devices=online_devices,
        offline_devices=offline_devices,
        total_alerts=total_alerts,
        total_scans=total_scans,
        high_risk=high_risk,
        medium_risk=medium_risk,
        low_risk=low_risk,
        vendors=vendors,
        risks=risks,
        statuses=statuses,
        timeline=timeline,
    )


# ----------------------------------------------------
# Settings
# ----------------------------------------------------

@dashboard.route("/settings")
def settings():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM devices")
    total_devices = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM scans")
    total_scans = cur.fetchone()[0]

    conn.close()

    return render_template(
        "settings.html",
        total_devices=total_devices,
        total_alerts=total_alerts,
        total_scans=total_scans,
        database=DATABASE,
    )

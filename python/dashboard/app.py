from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

DB = "data/home_soc.db"


def get_connection():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def get_stats():
    conn = get_connection()
    cur = conn.cursor()

    stats = {
        "total": cur.execute(
            "SELECT COUNT(*) FROM devices"
        ).fetchone()[0],

        "online": cur.execute(
            "SELECT COUNT(*) FROM devices WHERE status='Online'"
        ).fetchone()[0],

        "offline": cur.execute(
            "SELECT COUNT(*) FROM devices WHERE status='Offline'"
        ).fetchone()[0],

        "high": cur.execute(
            "SELECT COUNT(*) FROM devices WHERE risk='High'"
        ).fetchone()[0],

        "medium": cur.execute(
            "SELECT COUNT(*) FROM devices WHERE risk='Medium'"
        ).fetchone()[0],

        "low": cur.execute(
            "SELECT COUNT(*) FROM devices WHERE risk='Low'"
        ).fetchone()[0],
    }

    conn.close()

    return stats


def get_devices():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            id,
            ip,
            hostname,
            mac,
            vendor,
            status,
            risk,
            score,
            first_seen,
            last_seen,
            notes
        FROM devices
        ORDER BY ip
    """)

    devices = cur.fetchall()

    conn.close()

    return devices

def get_alerts():

    conn = get_connection()
    cur = conn.cursor()

    alerts = []

    # High Risk Devices
    cur.execute("""
        SELECT hostname, ip, risk
        FROM devices
        WHERE risk='High'
        ORDER BY hostname
    """)

    for row in cur.fetchall():

        alerts.append({
            "type": "High Risk",
            "severity": "danger",
            "message": f"{row['hostname'] or row['ip']} is marked HIGH risk"
        })

    # Offline Devices
    cur.execute("""
        SELECT hostname, ip
        FROM devices
        WHERE status='Offline'
        ORDER BY hostname
    """)

    for row in cur.fetchall():

        alerts.append({
            "type": "Offline",
            "severity": "secondary",
            "message": f"{row['hostname'] or row['ip']} is offline"
        })

    # Medium Risk Devices
    cur.execute("""
        SELECT hostname, ip
        FROM devices
        WHERE risk='Medium'
        ORDER BY hostname
    """)

    for row in cur.fetchall():

        alerts.append({
            "type": "Medium Risk",
            "severity": "warning",
            "message": f"{row['hostname'] or row['ip']} requires attention"
        })

    conn.close()

    return alerts

def get_device(device_id):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            id,
            ip,
            hostname,
            mac,
            vendor,
            status,
            risk,
            score,
            first_seen,
            last_seen,
            notes
        FROM devices
        WHERE id = ?
    """, (device_id,))

    device = cur.fetchone()

    conn.close()

    return device


@app.route("/")
def dashboard():
    return render_template(
        "dashboard.html",
        stats=get_stats(),
        devices=get_devices()
    )


@app.route("/devices")
def devices():
    return render_template(
        "devices.html",
        devices=get_devices()
    )


@app.route("/device/<int:device_id>")
def device(device_id):
    return render_template(
        "device.html",
        device=get_device(device_id)
    )


@app.route("/alerts")
def alerts():

    return render_template(
        "alerts.html",
        alerts=get_alerts()
    )

@app.route("/reports")
def reports():

    conn = get_connection()
    cur = conn.cursor()

    # Dashboard statistics
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

    # Vendors
    cur.execute("""
        SELECT vendor,
               COUNT(*) AS total
        FROM devices
        GROUP BY vendor
        ORDER BY total DESC
    """)
    vendors = cur.fetchall()

    # Risk summary
    cur.execute("""
        SELECT risk,
               COUNT(*) AS total
        FROM devices
        GROUP BY risk
    """)
    risks = cur.fetchall()

    # Status summary
    cur.execute("""
        SELECT status,
               COUNT(*) AS total
        FROM devices
        GROUP BY status
    """)
    statuses = cur.fetchall()

    # Timeline
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
        vendors=vendors,
        risks=risks,
        statuses=statuses,
        timeline=timeline,
    )

@app.route("/settings")
def settings():
    return render_template("settings.html")


if __name__ == "__main__":
    app.run(debug=True)

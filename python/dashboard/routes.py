from flask import Blueprint, render_template
import sqlite3

dashboard = Blueprint("dashboard", __name__)

DATABASE = "data/home_soc.db"


@dashboard.route("/")
def home():

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM devices")
    total_devices = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM devices WHERE status='Online'")
    online_devices = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM devices WHERE status='Offline'")
    offline_devices = cur.fetchone()[0]

    cur.execute("""
        SELECT category, hostname, ip, created_at
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

from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

DB = "data/home_soc.db"


def get_stats():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    total = cur.execute(
        "SELECT COUNT(*) FROM devices"
    ).fetchone()[0]

    online = cur.execute(
        "SELECT COUNT(*) FROM devices WHERE status='Online'"
    ).fetchone()[0]

    offline = cur.execute(
        "SELECT COUNT(*) FROM devices WHERE status='Offline'"
    ).fetchone()[0]

    high = cur.execute(
        "SELECT COUNT(*) FROM devices WHERE risk='High'"
    ).fetchone()[0]

    medium = cur.execute(
        "SELECT COUNT(*) FROM devices WHERE risk='Medium'"
    ).fetchone()[0]

    low = cur.execute(
        "SELECT COUNT(*) FROM devices WHERE risk='Low'"
    ).fetchone()[0]

    conn.close()

    return {
        "total": total,
        "online": online,
        "offline": offline,
        "high": high,
        "medium": medium,
        "low": low,
    }


def get_devices():

    conn = sqlite3.connect(DB)

    cur = conn.cursor()

    cur.execute("""
        SELECT
            ip,
            hostname,
            vendor,
            status,
            risk
        FROM devices
        ORDER BY ip
    """)

    devices = cur.fetchall()

    conn.close()

    return devices


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


@app.route("/alerts")
def alerts():

    return "<h1>🚨 Alerts Page (Coming Soon)</h1>"


@app.route("/reports")
def reports():

    return "<h1>📈 Reports Page (Coming Soon)</h1>"


@app.route("/settings")
def settings():

    return "<h1>⚙️ Settings Page (Coming Soon)</h1>"


if __name__ == "__main__":
    app.run(debug=True)

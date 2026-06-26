import platform
from datetime import datetime

import psutil


def get_system_health():
    return {
        "hostname": platform.node(),
        "system": platform.system(),
        "release": platform.release(),
        "cpu": psutil.cpu_percent(interval=1),
        "memory": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage("/").percent,
        "boot_time": datetime.fromtimestamp(
            psutil.boot_time()
        ).strftime("%Y-%m-%d %H:%M:%S"),
    }

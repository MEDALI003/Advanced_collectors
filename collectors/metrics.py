from __future__ import annotations

import os
from datetime import datetime, timezone

import psutil


def collect_metrics() -> dict:
    root_path = os.path.abspath(os.sep)
    data = {
        "cpu": psutil.cpu_percent(interval=0.2),
        "memory": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage(root_path).percent,
        "boot_time": datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc).isoformat(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        load1, _, _ = os.getloadavg()
        data["load_1m"] = round(load1, 2)
    except (AttributeError, OSError):
        data["load_1m"] = None
    return data

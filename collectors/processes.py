from __future__ import annotations

import psutil

from .common import now_iso


def collect_top_processes(limit: int = 10) -> list[dict]:
    timestamp = now_iso()
    processes = []
    try:
        for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
            info = proc.info
            processes.append(
                {
                    "pid": info.get("pid"),
                    "name": info.get("name") or "unknown",
                    "username": info.get("username"),
                    "cpu_percent": float(info.get("cpu_percent") or 0),
                    "memory_percent": round(float(info.get("memory_percent") or 0), 2),
                    "timestamp": timestamp,
                }
            )
    except Exception:
        return []

    processes.sort(key=lambda x: (x["cpu_percent"], x["memory_percent"]), reverse=True)
    return processes[:limit]

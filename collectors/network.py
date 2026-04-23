from __future__ import annotations

import psutil

from .common import now_iso


def _addr(value) -> str:
    if not value:
        return "-"
    host = getattr(value, "ip", None) or value[0]
    port = getattr(value, "port", None) or value[1]
    return f"{host}:{port}"


def collect_network_connections(limit: int = 100) -> list[dict]:
    timestamp = now_iso()
    rows: list[dict] = []
    try:
        connections = psutil.net_connections(kind="inet")
    except Exception:
        return rows

    for conn in connections:
        try:
            pname = None
            if conn.pid:
                try:
                    pname = psutil.Process(conn.pid).name()
                except Exception:
                    pname = None
            rows.append(
                {
                    "protocol": "tcp" if conn.type == 1 else "udp",
                    "local_address": _addr(conn.laddr),
                    "remote_address": _addr(conn.raddr),
                    "status": conn.status or "NONE",
                    "pid": conn.pid,
                    "process_name": pname,
                    "timestamp": timestamp,
                }
            )
        except Exception:
            continue
    rows.sort(key=lambda x: (x["status"] != "LISTEN", x["local_address"]))
    return rows[:limit]

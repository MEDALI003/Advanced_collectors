from __future__ import annotations

from .common import get_platform, now_iso, run_command


def _linux_service(name: str) -> dict:
    timestamp = now_iso()
    rc1, out1, err1 = run_command(["systemctl", "is-active", name], timeout=5)
    rc2, out2, err2 = run_command(["systemctl", "show", name, "--property=SubState", "--value"], timeout=5)
    return {
        "service_name": name,
        "active_state": out1 if rc1 == 0 else (out1 or err1 or "unknown"),
        "sub_state": out2 if rc2 == 0 else (out2 or err2 or "unknown"),
        "timestamp": timestamp,
    }


def _windows_service(name: str) -> dict:
    timestamp = now_iso()
    query = f"Get-Service -Name '{name}' | Select-Object Status, Name | ConvertTo-Json -Compress"
    rc, out, err = run_command(["powershell", "-NoProfile", "-Command", query], timeout=10)
    if rc != 0 or not out:
        return {"service_name": name, "active_state": "error", "sub_state": err or "not_found", "timestamp": timestamp}
    try:
        import json
        data = json.loads(out)
        return {
            "service_name": data.get("Name", name),
            "active_state": str(data.get("Status", "unknown")).lower(),
            "sub_state": "windows-service",
            "timestamp": timestamp,
        }
    except Exception as exc:
        return {"service_name": name, "active_state": "error", "sub_state": str(exc), "timestamp": timestamp}


def _mac_service(name: str) -> dict:
    timestamp = now_iso()
    rc, out, err = run_command(["launchctl", "print", f"system/{name}"], timeout=10)
    if rc == 0 and out:
        active = "running" if "state = running" in out.lower() else "loaded"
        return {"service_name": name, "active_state": active, "sub_state": "launchctl", "timestamp": timestamp}
    return {"service_name": name, "active_state": "unknown", "sub_state": err or "not_found", "timestamp": timestamp}


def collect_services(names: list[str]) -> list[dict]:
    platform_name = get_platform()
    rows = []
    for name in names:
        if platform_name == "linux":
            rows.append(_linux_service(name))
        elif platform_name == "windows":
            rows.append(_windows_service(name))
        elif platform_name == "darwin":
            rows.append(_mac_service(name))
    return rows

from __future__ import annotations

from pathlib import Path

from .common import get_platform, load_state, now_iso, run_command, save_state

STATE_FILE = "logs_state.json"


def _linux_logs(targets: list[str], interval_seconds: int) -> list[dict]:
    timestamp = now_iso()
    state = load_state(STATE_FILE)
    rows: list[dict] = []

    for target in targets:
        since = state.get(target) or f"{interval_seconds + 5} seconds ago"
        rc, out, err = run_command(["journalctl", "-u", target, "--since", since, "--no-pager", "-o", "short-iso"], timeout=10)
        if rc == 0 and out:
            for line in out.splitlines()[:100]:
                rows.append({"source": "journalctl", "service": target, "level": "info", "message": line.strip(), "timestamp": timestamp})
        elif err:
            fallback = Path(f"/var/log/{target}.log")
            if fallback.exists():
                try:
                    tail = fallback.read_text(errors="ignore").splitlines()[-50:]
                    for line in tail:
                        rows.append({"source": str(fallback), "service": target, "level": "info", "message": line.strip(), "timestamp": timestamp})
                except Exception:
                    pass
        state[target] = timestamp
    save_state(STATE_FILE, state)
    return rows[:200]


def _windows_logs(targets: list[str]) -> list[dict]:
    timestamp = now_iso()
    rows: list[dict] = []
    source_map = {
        "security": "Security",
        "system": "System",
        "application": "Application",
    }
    for target in targets:
        log_name = source_map.get(target.lower(), target)
        query = f"Get-WinEvent -LogName '{log_name}' -MaxEvents 30 | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | ConvertTo-Json -Compress"
        rc, out, err = run_command(["powershell", "-NoProfile", "-Command", query], timeout=15)
        if rc != 0 or not out:
            if err:
                rows.append({"source": log_name, "service": log_name, "level": "error", "message": err[:500], "timestamp": timestamp})
            continue
        try:
            import json
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            for entry in data[:30]:
                rows.append({
                    "source": log_name,
                    "service": entry.get("ProviderName") or log_name,
                    "level": (entry.get("LevelDisplayName") or "info").lower(),
                    "message": (entry.get("Message") or "").replace("\r", " ").replace("\n", " ")[:2000],
                    "timestamp": timestamp,
                })
        except Exception as exc:
            rows.append({"source": log_name, "service": log_name, "level": "error", "message": str(exc), "timestamp": timestamp})
    return rows[:200]


def _mac_logs(targets: list[str], interval_seconds: int) -> list[dict]:
    timestamp = now_iso()
    rows: list[dict] = []
    minutes = max(1, round((interval_seconds + 30) / 60))
    for target in targets:
        query = f"log show --style compact --last {minutes}m --predicate 'eventMessage CONTAINS[c] \"{target}\"'"
        rc, out, err = run_command(["sh", "-lc", query], timeout=15)
        if rc == 0 and out:
            for line in out.splitlines()[-50:]:
                rows.append({"source": "log show", "service": target, "level": "info", "message": line.strip(), "timestamp": timestamp})
        elif err:
            rows.append({"source": "log show", "service": target, "level": "error", "message": err[:500], "timestamp": timestamp})
    return rows[:200]


def collect_logs(targets: list[str], interval_seconds: int) -> list[dict]:
    platform_name = get_platform()
    if platform_name == "linux":
        return _linux_logs(targets, interval_seconds)
    if platform_name == "windows":
        return _windows_logs(targets)
    if platform_name == "darwin":
        return _mac_logs(targets, interval_seconds)
    return []

from __future__ import annotations

import json
import platform
import time
from pathlib import Path

import requests

from collectors.common import get_hostname
from collectors.files import collect_file_events
from collectors.logs import collect_logs
from collectors.metrics import collect_metrics
from collectors.network import collect_network_connections
from collectors.processes import collect_top_processes
from collectors.services import collect_services

APP_VERSION = "2.0.0"
CONFIG_FILE = Path(__file__).resolve().parent / "config.json"


NOISE_MESSAGES = [
    "-- No entries --",
]

NOISE_CONTAINS = [
    "debian-sa1 1 1",
    "cron.service: Referenced but unset environment variable",
]


def load_config() -> dict:
    return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))


def _os_key() -> str:
    system = platform.system().lower()
    return "darwin" if system == "darwin" else system


def _get_targets(config: dict, key: str) -> list[str]:
    return config.get(key, {}).get(_os_key(), [])


def is_noise_log(log: dict) -> bool:
    msg = str(log.get("message", "")).strip()

    if not msg:
        return True

    if msg in NOISE_MESSAGES:
        return True

    for noise in NOISE_CONTAINS:
        if noise in msg:
            return True

    return False


def build_payload(config: dict) -> dict:
    interval_seconds = int(config.get("interval_seconds", 30))
    watch_directory = config.get("watch_directory", ".")
    limits = config.get("limits", {})
    os_name = platform.system()

    logs = collect_logs(_get_targets(config, "log_targets"), interval_seconds)

    clean_logs = []
    for log in logs:
        if is_noise_log(log):
            continue

        msg = str(log.get("message", "")).strip()
        log["message"] = msg
        log["source"] = str(log.get("source", "unknown")).strip() or "unknown"
        log["level"] = str(log.get("level", "info")).strip() or "info"
        clean_logs.append(log)

    payload = {
        "agent": {
            "hostname": get_hostname(),
            "os_name": os_name,
            "os_version": platform.version(),
            "agent_version": APP_VERSION,
        },
        "metrics": collect_metrics(),
        "logs": clean_logs,
        "services": collect_services(_get_targets(config, "watch_services")),
        "file_events": collect_file_events(
            watch_directory,
            max_files=int(limits.get("max_file_scan", 5000)),
        ),
        "network_connections": collect_network_connections(
            limit=int(limits.get("max_network_connections", 100)),
        ),
        "top_processes": collect_top_processes(
            limit=int(limits.get("top_processes", 10)),
        ),
    }

    return payload


def _canonical_json(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_signature(secret: str, payload: dict) -> str:
    import hashlib
    import hmac

    return hmac.new(
        secret.encode("utf-8"),
        _canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()


def send_payload(config: dict, payload: dict):
    headers = {
        "X-API-KEY": config["api_key"],
        "X-Signature": build_signature(config["hmac_secret"], payload),
    }

    response = requests.post(
        config["manager_url"],
        json=payload,
        headers=headers,
        timeout=15,
        verify=bool(config.get("tls_verify", True)),
    )

    if not response.ok:
        print("[!] Manager response:", response.status_code, response.text)

    response.raise_for_status()
    return response


def main() -> None:
    config = load_config()
    interval_seconds = int(config.get("interval_seconds", 30))

    print(f"[*] Cross-OS SIEM Agent {APP_VERSION}")
    print(f"[*] Host: {get_hostname()}")
    print(f"[*] Platform: {platform.system()} {platform.version()}")
    print(f"[*] Manager: {config['manager_url']}")
    print(f"[*] Interval: {interval_seconds}s")

    while True:
        try:
            payload = build_payload(config)
            response = send_payload(config, payload)
            data = response.json()

            print(
                f"[+] Sent successfully: {response.status_code} | "
                f"logs={len(payload.get('logs', []))} | "
                f"file_events={len(payload.get('file_events', []))} | "
                f"alerts={len(data.get('alerts', []))}"
            )

            for alert in data.get("alerts", []):
                print(f"    [ALERT] {alert}")

        except Exception as exc:
            print(f"[!] Send failed: {exc}")

        time.sleep(interval_seconds)


if __name__ == "__main__":
    main()
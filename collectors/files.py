from __future__ import annotations

from pathlib import Path

from .common import load_state, now_iso, save_state

STATE_FILE = "file_state.json"


def _snapshot_directory(directory: str, max_files: int = 5000) -> dict:
    root = Path(directory)
    snapshot = {}
    if not root.exists():
        return snapshot

    count = 0
    for path in root.rglob("*"):
        if count >= max_files:
            break
        if path.is_file():
            try:
                stat = path.stat()
                snapshot[str(path)] = {"mtime": stat.st_mtime, "size": stat.st_size}
                count += 1
            except Exception:
                continue
    return snapshot


def collect_file_events(directory: str, max_files: int = 5000) -> list[dict]:
    previous = load_state(STATE_FILE)
    current = _snapshot_directory(directory, max_files=max_files)
    timestamp = now_iso()
    events: list[dict] = []

    old_paths = set(previous.keys())
    new_paths = set(current.keys())

    for path in sorted(new_paths - old_paths):
        events.append({"path": path, "action": "created", "timestamp": timestamp})
    for path in sorted(old_paths - new_paths):
        events.append({"path": path, "action": "deleted", "timestamp": timestamp})
    for path in sorted(new_paths & old_paths):
        if previous.get(path) != current.get(path):
            events.append({"path": path, "action": "modified", "timestamp": timestamp})

    save_state(STATE_FILE, current)
    return events[:500]

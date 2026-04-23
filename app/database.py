from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "siem.db"


@contextmanager
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                ip TEXT NOT NULL,
                os_name TEXT NOT NULL,
                os_version TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(hostname, ip)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                ip TEXT NOT NULL,
                cpu REAL,
                memory REAL,
                disk REAL,
                load_1m REAL,
                boot_time TEXT,
                timestamp TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                ip TEXT NOT NULL,
                source TEXT NOT NULL,
                service TEXT,
                level TEXT,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                ip TEXT NOT NULL,
                service_name TEXT NOT NULL,
                active_state TEXT,
                sub_state TEXT,
                timestamp TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS file_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                ip TEXT NOT NULL,
                path TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                local_address TEXT NOT NULL,
                remote_address TEXT NOT NULL,
                status TEXT NOT NULL,
                pid INTEGER,
                process_name TEXT,
                timestamp TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS top_processes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                ip TEXT NOT NULL,
                pid INTEGER NOT NULL,
                name TEXT NOT NULL,
                username TEXT,
                cpu_percent REAL,
                memory_percent REAL,
                timestamp TEXT NOT NULL
            )
            """
        )
        conn.commit()


def upsert_agent(agent: dict, ip: str, seen_at: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO agents (hostname, ip, os_name, os_version, agent_version, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(hostname, ip) DO UPDATE SET
                os_name = excluded.os_name,
                os_version = excluded.os_version,
                agent_version = excluded.agent_version,
                last_seen = excluded.last_seen
            """,
            (
                agent["hostname"],
                ip,
                agent["os_name"],
                agent.get("os_version", "unknown"),
                agent.get("agent_version", "2.0.0"),
                seen_at,
            ),
        )
        conn.commit()


def _bulk_insert(table_sql: str, rows: Iterable[tuple]) -> None:
    rows = list(rows)
    if not rows:
        return
    with get_connection() as conn:
        conn.executemany(table_sql, rows)
        conn.commit()


def insert_metrics(hostname: str, ip: str, metrics: dict) -> None:
    _bulk_insert(
        """
        INSERT INTO metrics (hostname, ip, cpu, memory, disk, load_1m, boot_time, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [(
            hostname,
            ip,
            metrics.get("cpu"),
            metrics.get("memory"),
            metrics.get("disk"),
            metrics.get("load_1m"),
            metrics.get("boot_time"),
            metrics.get("timestamp"),
        )],
    )


def insert_logs(hostname: str, ip: str, logs: list[dict]) -> None:
    _bulk_insert(
        """
        INSERT INTO logs (hostname, ip, source, service, level, message, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [(
            hostname,
            ip,
            entry.get("source", "unknown"),
            entry.get("service"),
            entry.get("level", "info"),
            entry.get("message", ""),
            entry.get("timestamp"),
        ) for entry in logs],
    )


def insert_services(hostname: str, ip: str, services: list[dict]) -> None:
    _bulk_insert(
        """
        INSERT INTO services (hostname, ip, service_name, active_state, sub_state, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [(
            hostname,
            ip,
            entry.get("service_name"),
            entry.get("active_state"),
            entry.get("sub_state"),
            entry.get("timestamp"),
        ) for entry in services],
    )


def insert_file_events(hostname: str, ip: str, events: list[dict]) -> None:
    _bulk_insert(
        """
        INSERT INTO file_events (hostname, ip, path, action, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        [(
            hostname,
            ip,
            entry.get("path"),
            entry.get("action"),
            entry.get("timestamp"),
        ) for entry in events],
    )


def insert_network_connections(hostname: str, ip: str, rows: list[dict]) -> None:
    _bulk_insert(
        """
        INSERT INTO network_connections (hostname, ip, protocol, local_address, remote_address, status, pid, process_name, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [(
            hostname,
            ip,
            entry.get("protocol"),
            entry.get("local_address"),
            entry.get("remote_address"),
            entry.get("status"),
            entry.get("pid"),
            entry.get("process_name"),
            entry.get("timestamp"),
        ) for entry in rows],
    )


def insert_top_processes(hostname: str, ip: str, rows: list[dict]) -> None:
    _bulk_insert(
        """
        INSERT INTO top_processes (hostname, ip, pid, name, username, cpu_percent, memory_percent, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [(
            hostname,
            ip,
            entry.get("pid"),
            entry.get("name"),
            entry.get("username"),
            entry.get("cpu_percent"),
            entry.get("memory_percent"),
            entry.get("timestamp"),
        ) for entry in rows],
    )


def fetch_recent(table: str, limit: int = 100):
    allow = {
        "agents", "metrics", "logs", "services", "file_events", "network_connections", "top_processes"
    }
    if table not in allow:
        raise ValueError("Invalid table")
    with get_connection() as conn:
        rows = conn.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

from __future__ import annotations

import os
from contextlib import contextmanager

import mysql.connector
from mysql.connector import pooling


DB_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "database": os.getenv("MYSQL_DATABASE", "siem"),
    "user": os.getenv("MYSQL_USER", "siem_user"),
    "password": os.getenv("MYSQL_PASSWORD", "strong_password"),
    "autocommit": True,
}

POOL = pooling.MySQLConnectionPool(
    pool_name="siem_pool",
    pool_size=5,
    **DB_CONFIG,
)
def fetch_recent(table: str, limit: int = 100) -> list[dict]:
    allowed_tables = {
        "agents",
        "metrics",
        "logs",
        "services",
        "file_events",
        "network_connections",
        "top_processes",
    }

    if table not in allowed_tables:
        raise ValueError(f"Invalid table name: {table}")

    limit = max(1, min(int(limit), 1000))

    with get_conn() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
        cur.close()
        return rows

@contextmanager
def get_conn():
    conn = POOL.get_connection()
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        cur = conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hostname VARCHAR(255) NOT NULL,
            ip VARCHAR(64) NOT NULL,
            os_name VARCHAR(128),
            os_version VARCHAR(255),
            agent_version VARCHAR(64),
            last_seen DATETIME(6) NOT NULL,
            UNIQUE KEY uniq_agent (hostname, ip)
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS metrics (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hostname VARCHAR(255) NOT NULL,
            ip VARCHAR(64) NOT NULL,
            cpu DOUBLE,
            memory DOUBLE,
            disk DOUBLE,
            load_1m DOUBLE NULL,
            boot_time VARCHAR(64) NULL,
            timestamp DATETIME(6) NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hostname VARCHAR(255) NOT NULL,
            ip VARCHAR(64) NOT NULL,
            source VARCHAR(255),
            service VARCHAR(255),
            level VARCHAR(64),
            message TEXT NOT NULL,
            timestamp DATETIME(6) NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS services (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hostname VARCHAR(255) NOT NULL,
            ip VARCHAR(64) NOT NULL,
            service_name VARCHAR(255) NOT NULL,
            active_state VARCHAR(128),
            sub_state VARCHAR(128),
            timestamp DATETIME(6) NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS file_events (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hostname VARCHAR(255) NOT NULL,
            ip VARCHAR(64) NOT NULL,
            path TEXT NOT NULL,
            action VARCHAR(64) NOT NULL,
            timestamp DATETIME(6) NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS network_connections (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hostname VARCHAR(255) NOT NULL,
            ip VARCHAR(64) NOT NULL,
            protocol VARCHAR(32),
            local_address VARCHAR(255),
            remote_address VARCHAR(255),
            status VARCHAR(64),
            pid INT NULL,
            process_name VARCHAR(255) NULL,
            timestamp DATETIME(6) NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS top_processes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hostname VARCHAR(255) NOT NULL,
            ip VARCHAR(64) NOT NULL,
            pid INT NULL,
            name VARCHAR(255),
            username VARCHAR(255),
            cpu_percent DOUBLE,
            memory_percent DOUBLE,
            timestamp DATETIME(6) NOT NULL
        )
        """)

        cur.close()


def upsert_agent(agent: dict, ip: str, ts: str) -> None:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO agents (hostname, ip, os_name, os_version, agent_version, last_seen)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                os_name = VALUES(os_name),
                os_version = VALUES(os_version),
                agent_version = VALUES(agent_version),
                last_seen = VALUES(last_seen)
        """, (
            agent["hostname"],
            ip,
            agent.get("os_name"),
            agent.get("os_version"),
            agent.get("agent_version"),
            ts,
        ))
        cur.close()


def insert_metrics(agent: dict, ip: str, metrics: dict, ts: str) -> None:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO metrics (hostname, ip, cpu, memory, disk, load_1m, boot_time, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            agent["hostname"],
            ip,
            metrics.get("cpu"),
            metrics.get("memory"),
            metrics.get("disk"),
            metrics.get("load_1m"),
            metrics.get("boot_time"),
            ts,
        ))
        cur.close()


def insert_logs(agent: dict, ip: str, logs: list[dict]) -> None:
    if not logs:
        return
    with get_conn() as conn:
        cur = conn.cursor()
        rows = [
            (
                agent["hostname"],
                ip,
                item.get("source"),
                item.get("service"),
                item.get("level"),
                item["message"],
                item["timestamp"],
            )
            for item in logs
        ]
        cur.executemany("""
            INSERT INTO logs (hostname, ip, source, service, level, message, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, rows)
        cur.close()


def insert_services(agent: dict, ip: str, services: list[dict]) -> None:
    if not services:
        return
    with get_conn() as conn:
        cur = conn.cursor()
        rows = [
            (
                agent["hostname"],
                ip,
                item["service_name"],
                item.get("active_state"),
                item.get("sub_state"),
                item["timestamp"],
            )
            for item in services
        ]
        cur.executemany("""
            INSERT INTO services (hostname, ip, service_name, active_state, sub_state, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, rows)
        cur.close()


def insert_file_events(agent: dict, ip: str, events: list[dict]) -> None:
    if not events:
        return
    with get_conn() as conn:
        cur = conn.cursor()
        rows = [
            (
                agent["hostname"],
                ip,
                item["path"],
                item["action"],
                item["timestamp"],
            )
            for item in events
        ]
        cur.executemany("""
            INSERT INTO file_events (hostname, ip, path, action, timestamp)
            VALUES (%s, %s, %s, %s, %s)
        """, rows)
        cur.close()


def insert_network_connections(agent: dict, ip: str, items: list[dict]) -> None:
    if not items:
        return
    with get_conn() as conn:
        cur = conn.cursor()
        rows = [
            (
                agent["hostname"],
                ip,
                item.get("protocol"),
                item.get("local_address"),
                item.get("remote_address"),
                item.get("status"),
                item.get("pid"),
                item.get("process_name"),
                item["timestamp"],
            )
            for item in items
        ]
        cur.executemany("""
            INSERT INTO network_connections
            (hostname, ip, protocol, local_address, remote_address, status, pid, process_name, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, rows)
        cur.close()


def insert_top_processes(agent: dict, ip: str, items: list[dict]) -> None:
    if not items:
        return
    with get_conn() as conn:
        cur = conn.cursor()
        rows = [
            (
                agent["hostname"],
                ip,
                item.get("pid"),
                item.get("name"),
                item.get("username"),
                item.get("cpu_percent"),
                item.get("memory_percent"),
                item["timestamp"],
            )
            for item in items
        ]
        cur.executemany("""
            INSERT INTO top_processes
            (hostname, ip, pid, name, username, cpu_percent, memory_percent, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, rows)
        cur.close()
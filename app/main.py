from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request

from .database import (
    fetch_recent,
    init_db,
    insert_file_events,
    insert_logs,
    insert_metrics,
    insert_network_connections,
    insert_services,
    insert_top_processes,
    upsert_agent,
)
from .models import IngestPayload
from .security import verify_hmac

API_KEY = os.getenv("SIEM_API_KEY", "change-me")
HMAC_SECRET = os.getenv("SIEM_HMAC_SECRET", "change-me-too")
MAX_LOGS = int(os.getenv("SIEM_MAX_LOGS", "500"))
MAX_ITEMS = int(os.getenv("SIEM_MAX_ITEMS", "250"))

app = FastAPI(title="Cross-OS SIEM Manager", version="2.0.0")
init_db()


def _build_alerts(payload: IngestPayload) -> list[str]:
    alerts: list[str] = []
    hostname = payload.agent.hostname
    if payload.metrics.cpu >= 85:
        alerts.append(f"HIGH_CPU on {hostname}: {payload.metrics.cpu}%")
    if payload.metrics.memory >= 90:
        alerts.append(f"HIGH_MEMORY on {hostname}: {payload.metrics.memory}%")
    if payload.metrics.disk >= 90:
        alerts.append(f"HIGH_DISK on {hostname}: {payload.metrics.disk}%")

    suspicious = ("failed password", "authentication failure", "denied", "error", "audit fail")
    for entry in payload.logs:
        msg = entry.message.lower()
        if any(token in msg for token in suspicious):
            alerts.append(f"SUSPICIOUS_LOG on {hostname}: {entry.source} / {entry.service or '-'}")
            break

    for svc in payload.services:
        if svc.active_state.lower() in {"failed", "inactive", "stopped", "stop_pending"}:
            alerts.append(f"SERVICE_ISSUE on {hostname}: {svc.service_name}={svc.active_state}")

    listening_external = [
        c for c in payload.network_connections
        if c.status.upper() == "LISTEN" and not c.local_address.startswith(("127.", "::1", "localhost"))
    ]
    if len(listening_external) >= 5:
        alerts.append(f"EXCESSIVE_LISTENING_PORTS on {hostname}: {len(listening_external)} exposed listeners")
    return alerts[:20]


@app.get("/")
def home() -> dict[str, str]:
    return {"status": "manager running", "version": app.version}


@app.post("/ingest")
async def ingest(
    request: Request,
    x_api_key: str | None = Header(default=None),
    x_signature: str | None = Header(default=None),
) -> dict[str, Any]:
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")

    raw_payload = await request.json()
    if not isinstance(raw_payload, dict):
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    if not x_signature or not verify_hmac(HMAC_SECRET, raw_payload, x_signature):
        raise HTTPException(status_code=403, detail="Invalid signature")

    try:
        payload = IngestPayload.model_validate(raw_payload)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Payload validation failed: {exc}") from exc

    if len(payload.logs) > MAX_LOGS:
        raise HTTPException(status_code=413, detail="Too many logs")

    lists = [payload.services, payload.file_events, payload.network_connections, payload.top_processes]
    if any(len(items) > MAX_ITEMS for items in lists):
        raise HTTPException(status_code=413, detail="Too many items in payload")

    seen_at = datetime.now(timezone.utc).isoformat()
    client_ip = request.client.host if request.client else "unknown"
    payload.agent.ip = client_ip

    upsert_agent(payload.agent.model_dump(), client_ip, seen_at)
    insert_metrics(payload.agent.hostname, client_ip, payload.metrics.model_dump())
    insert_logs(payload.agent.hostname, client_ip, [x.model_dump() for x in payload.logs])
    insert_services(payload.agent.hostname, client_ip, [x.model_dump() for x in payload.services])
    insert_file_events(payload.agent.hostname, client_ip, [x.model_dump() for x in payload.file_events])
    insert_network_connections(payload.agent.hostname, client_ip, [x.model_dump() for x in payload.network_connections])
    insert_top_processes(payload.agent.hostname, client_ip, [x.model_dump() for x in payload.top_processes])

    alerts = _build_alerts(payload)
    return {"status": "stored", "alerts": alerts, "agent": payload.agent.hostname}


@app.get("/agents")
def get_agents(limit: int = 100):
    return {"agents": fetch_recent("agents", limit)}


@app.get("/metrics")
def get_metrics(limit: int = 100):
    return {"metrics": fetch_recent("metrics", limit)}


@app.get("/logs")
def get_logs(limit: int = 100):
    return {"logs": fetch_recent("logs", limit)}


@app.get("/services")
def get_services(limit: int = 100):
    return {"services": fetch_recent("services", limit)}


@app.get("/file-events")
def get_file_events(limit: int = 100):
    return {"file_events": fetch_recent("file_events", limit)}


@app.get("/network-connections")
def get_network_connections(limit: int = 100):
    return {"network_connections": fetch_recent("network_connections", limit)}


@app.get("/top-processes")
def get_top_processes(limit: int = 100):
    return {"top_processes": fetch_recent("top_processes", limit)}

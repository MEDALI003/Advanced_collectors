from __future__ import annotations

from typing import List, Optional, Literal
from pydantic import BaseModel, Field


class AgentInfo(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    os_name: str = Field(min_length=1, max_length=64)
    os_version: str = Field(default="unknown", max_length=128)
    ip: Optional[str] = None
    agent_version: str = Field(default="2.0.0", max_length=32)


class MetricRecord(BaseModel):
    cpu: float = Field(ge=0, le=100)
    memory: float = Field(ge=0, le=100)
    disk: float = Field(ge=0, le=100)
    load_1m: Optional[float] = None
    boot_time: Optional[str] = None
    timestamp: str


class LogRecord(BaseModel):
    source: str = Field(min_length=1, max_length=64)
    service: Optional[str] = Field(default=None, max_length=128)
    level: str = Field(default="info", max_length=32)
    message: str = Field(min_length=1, max_length=5000)
    timestamp: str


class ServiceRecord(BaseModel):
    service_name: str = Field(min_length=1, max_length=128)
    active_state: str = Field(min_length=1, max_length=64)
    sub_state: str = Field(default="unknown", max_length=128)
    timestamp: str


class FileEventRecord(BaseModel):
    path: str = Field(min_length=1, max_length=2000)
    action: Literal["created", "deleted", "modified"]
    timestamp: str


class NetworkRecord(BaseModel):
    protocol: str = Field(min_length=1, max_length=16)
    local_address: str = Field(min_length=1, max_length=128)
    remote_address: str = Field(min_length=1, max_length=128)
    status: str = Field(min_length=1, max_length=64)
    pid: Optional[int] = None
    process_name: Optional[str] = Field(default=None, max_length=255)
    timestamp: str


class ProcessRecord(BaseModel):
    pid: int
    name: str = Field(min_length=1, max_length=255)
    username: Optional[str] = Field(default=None, max_length=255)
    cpu_percent: float = Field(ge=0)
    memory_percent: float = Field(ge=0)
    timestamp: str


class IngestPayload(BaseModel):
    agent: AgentInfo
    metrics: MetricRecord
    logs: List[LogRecord] = []
    services: List[ServiceRecord] = []
    file_events: List[FileEventRecord] = []
    network_connections: List[NetworkRecord] = []
    top_processes: List[ProcessRecord] = []

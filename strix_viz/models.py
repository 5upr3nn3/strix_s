"""Data models shared by the strix_viz backend."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional, TypedDict

from pydantic import BaseModel, Field


class EventDict(TypedDict, total=False):
    ts: str
    type: str
    agent_id: str
    target: str
    action: str
    tool: str
    status: str
    meta: Dict[str, Any]
    args: Dict[str, Any]
    result_summary: str
    vuln_id: str
    severity: str
    category: str
    description: str


class RunMetadata(BaseModel):
    id: str
    created_at: Optional[datetime]
    event_count: int


class Agent(BaseModel):
    id: str
    label: str
    first_seen: datetime
    last_seen: datetime
    meta: Dict[str, Any] = Field(default_factory=dict)


class Asset(BaseModel):
    id: str
    label: str
    url: str
    first_seen: datetime
    last_seen: datetime
    meta: Dict[str, Any] = Field(default_factory=dict)


class Vulnerability(BaseModel):
    id: str
    agent_id: Optional[str]
    asset_id: Optional[str]
    severity: Optional[str]
    category: Optional[str]
    description: Optional[str]
    ts: datetime


class Edge(BaseModel):
    id: str
    source: str
    target: str
    relation: str
    label: Optional[str]


class ToolCall(BaseModel):
    id: str
    ts: datetime
    agent_id: Optional[str]
    tool: Optional[str]
    target: Optional[str]
    status: Optional[str]
    summary: Optional[str]
    args: Dict[str, Any] = Field(default_factory=dict)
    result_summary: Optional[str] = None


class Snapshot(BaseModel):
    run_id: str
    agents: list[Agent]
    assets: list[Asset]
    vulnerabilities: list[Vulnerability]
    edges: list[Edge]
    tool_calls: list[ToolCall]
    last_event_ts: Optional[datetime]


class PaginatedEvents(BaseModel):
    run_id: str
    events: list[EventDict]
    offset: int
    limit: int
    total: int

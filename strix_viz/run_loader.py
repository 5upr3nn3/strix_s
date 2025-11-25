"""Helpers for discovering runs and building viz-friendly snapshots."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Optional, Tuple

from fastapi import HTTPException, status

from .config import EVENTS_FILE_NAME, get_events_path, get_run_dir, get_runs_dir
from .models import Agent, Asset, Edge, EventDict, PaginatedEvents, RunMetadata, Snapshot, ToolCall, Vulnerability

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ParsedEvent:
    raw: EventDict
    ts: datetime


# ---------------------------------------------------------------------------
# Event helpers
# ---------------------------------------------------------------------------

def parse_timestamp(raw: Optional[str]) -> datetime:
    if raw is None:
        return datetime.now(tz=timezone.utc)
    candidate = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        LOGGER.warning("Invalid timestamp '%s', defaulting to now", raw)
        return datetime.now(tz=timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def read_events_file(path: Path) -> list[ParsedEvent]:
    events: list[ParsedEvent] = []
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="events.jsonl missing for run")
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                LOGGER.warning("Skipping malformed JSON line: %s", line)
                continue
            if not isinstance(payload, dict):
                continue
            payload.setdefault("type", "event")
            ts = parse_timestamp(payload.get("ts"))
            events.append(ParsedEvent(raw=payload, ts=ts))
    return events


# ---------------------------------------------------------------------------
# Run discovery
# ---------------------------------------------------------------------------

def list_runs() -> list[RunMetadata]:
    runs_dir = get_runs_dir()
    if not runs_dir.exists():
        return []
    runs: list[RunMetadata] = []
    for child in runs_dir.iterdir():
        if not child.is_dir():
            continue
        events_path = child / EVENTS_FILE_NAME
        if not events_path.exists():
            continue
        created_at = datetime.fromtimestamp(child.stat().st_mtime, tz=timezone.utc)
        event_count = count_file_lines(events_path)
        runs.append(RunMetadata(id=child.name, created_at=created_at, event_count=event_count))
    runs.sort(key=lambda meta: meta.created_at or datetime.fromtimestamp(0, tz=timezone.utc), reverse=True)
    return runs


def count_file_lines(path: Path) -> int:
    count = 0
    with path.open("r", encoding="utf-8") as handle:
        for _ in handle:
            count += 1
    return count


def load_snapshot(run_id: str) -> Snapshot:
    parsed_events = read_events_file(get_events_path(run_id))
    builder = SnapshotBuilder(run_id)
    for event in parsed_events:
        builder.apply_event(event)
    return builder.build()


def load_events_page(run_id: str, offset: int, limit: int) -> PaginatedEvents:
    parsed_events = read_events_file(get_events_path(run_id))
    total = len(parsed_events)
    slice_start = max(offset, 0)
    slice_end = min(slice_start + limit, total)
    raw_events: list[EventDict] = [parsed_events[idx].raw for idx in range(slice_start, slice_end)]
    return PaginatedEvents(run_id=run_id, events=raw_events, offset=slice_start, limit=limit, total=total)


# ---------------------------------------------------------------------------
# Snapshot builder
# ---------------------------------------------------------------------------

class SnapshotBuilder:
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.agents: Dict[str, Dict[str, Any]] = {}
        self.assets: Dict[str, Dict[str, Any]] = {}
        self.vulns: Dict[str, Vulnerability] = {}
        self.edges: Dict[Tuple[str, str, str], Edge] = {}
        self.tool_calls: list[ToolCall] = []
        self.last_event_ts: Optional[datetime] = None
        self.tool_counter = 0

    def apply_event(self, event: ParsedEvent) -> None:
        self.last_event_ts = event.ts
        payload = event.raw
        event_type = payload.get("type", "event")
        agent_id = payload.get("agent_id")
        target = payload.get("target")
        self._touch_agent(agent_id, event.ts)
        if target:
            self._touch_asset(target, event.ts)

        if event_type == "agent_step":
            self._handle_agent_step(agent_id, target, payload)
        elif event_type == "vuln_found":
            self._handle_vuln_found(agent_id, target, payload, event.ts)
        elif event_type == "mcp_tool_call":
            self._handle_tool_call(agent_id, target, payload, event.ts)
        else:
            # default handling: only maintain nodes
            if agent_id and target:
                self._add_edge(agent_id, target, relation=event_type, label=payload.get("action"))

    def build(self) -> Snapshot:
        agents = [
            Agent(
                id=agent_id,
                label=data.get("label", agent_id),
                first_seen=data["first_seen"],
                last_seen=data["last_seen"],
                meta=data.get("meta", {}),
            )
            for agent_id, data in self.agents.items()
        ]
        assets = [
            Asset(
                id=asset_id,
                label=data.get("label", asset_id),
                url=data.get("url", asset_id),
                first_seen=data["first_seen"],
                last_seen=data["last_seen"],
                meta=data.get("meta", {}),
            )
            for asset_id, data in self.assets.items()
        ]
        vulns = list(self.vulns.values())
        edges = list(self.edges.values())
        return Snapshot(
            run_id=self.run_id,
            agents=sorted(agents, key=lambda agent: agent.id),
            assets=sorted(assets, key=lambda asset: asset.id),
            vulnerabilities=sorted(vulns, key=lambda vuln: vuln.ts),
            edges=edges,
            tool_calls=self.tool_calls,
            last_event_ts=self.last_event_ts,
        )

    def _touch_agent(self, agent_id: Optional[str], ts: datetime) -> None:
        if not agent_id:
            return
        agent = self.agents.setdefault(agent_id, {"id": agent_id, "label": agent_id, "first_seen": ts, "last_seen": ts, "meta": {}})
        agent["first_seen"] = min(agent["first_seen"], ts)
        agent["last_seen"] = max(agent["last_seen"], ts)

    def _touch_asset(self, asset_id: Optional[str], ts: datetime) -> None:
        if not asset_id:
            return
        asset = self.assets.setdefault(asset_id, {"id": asset_id, "label": asset_id, "url": asset_id, "first_seen": ts, "last_seen": ts, "meta": {}})
        asset["first_seen"] = min(asset["first_seen"], ts)
        asset["last_seen"] = max(asset["last_seen"], ts)

    def _handle_agent_step(self, agent_id: Optional[str], target: Optional[str], payload: EventDict) -> None:
        if agent_id and target:
            relation = payload.get("action") or payload.get("tool") or "agent_step"
            self._add_edge(agent_id, target, relation=relation, label=payload.get("status"))

    def _handle_vuln_found(self, agent_id: Optional[str], target: Optional[str], payload: EventDict, ts: datetime) -> None:
        vuln_id = payload.get("vuln_id") or f"vuln-{len(self.vulns) + 1}"
        vuln = Vulnerability(
            id=vuln_id,
            agent_id=agent_id,
            asset_id=target,
            severity=payload.get("severity"),
            category=payload.get("category"),
            description=payload.get("description"),
            ts=ts,
        )
        self.vulns[vuln_id] = vuln
        if agent_id:
            self._add_edge(agent_id, vuln_id, relation="reported", label=vuln.severity)
        if target:
            self._touch_asset(target, ts)
            self._add_edge(vuln_id, target, relation="affects", label=vuln.category)

    def _handle_tool_call(self, agent_id: Optional[str], target: Optional[str], payload: EventDict, ts: datetime) -> None:
        self.tool_counter += 1
        args = payload.get("args") or {}
        inferred_target = target or _extract_tool_target(args)
        if inferred_target:
            self._touch_asset(inferred_target, ts)
            if agent_id:
                self._add_edge(agent_id, inferred_target, relation=payload.get("tool", "tool_call"), label=payload.get("status"))
        tool_call = ToolCall(
            id=f"tool-{self.tool_counter}",
            ts=ts,
            agent_id=agent_id,
            tool=payload.get("tool"),
            target=inferred_target,
            status=payload.get("status"),
            summary=payload.get("meta", {}).get("summary") if isinstance(payload.get("meta"), dict) else payload.get("result_summary"),
            args=args if isinstance(args, dict) else {},
            result_summary=payload.get("result_summary"),
        )
        self.tool_calls.append(tool_call)

    def _add_edge(self, source: str, target: str, relation: str, label: Optional[str]) -> None:
        key = (source, target, relation)
        if key in self.edges:
            return
        edge = Edge(id=f"edge-{len(self.edges) + 1}", source=source, target=target, relation=relation, label=label)
        self.edges[key] = edge


def _extract_tool_target(args: Dict[str, Any]) -> Optional[str]:
    url = args.get("url") if isinstance(args, dict) else None
    if isinstance(url, str):
        return url
    target = args.get("target") if isinstance(args, dict) else None
    if isinstance(target, str):
        return target
    return None


# ---------------------------------------------------------------------------
# Event streaming
# ---------------------------------------------------------------------------

async def stream_new_events(run_id: str, start_at_end: bool = True) -> AsyncIterator[EventDict]:
    path = get_events_path(run_id)
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    with path.open("r", encoding="utf-8") as handle:
        if start_at_end:
            handle.seek(0, 2)
        while True:
            position = handle.tell()
            line = handle.readline()
            if not line:
                await asyncio.sleep(0.5)
                handle.seek(position)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                LOGGER.warning("Skipping malformed JSON during stream: %s", line)
                continue
            if isinstance(payload, dict):
                yield payload

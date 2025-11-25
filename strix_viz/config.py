"""Configuration helpers for the strix_viz service."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

EVENTS_FILE_NAME = "events.jsonl"


@lru_cache(maxsize=1)
def get_runs_dir() -> Path:
    """Return the directory that holds Strix run folders."""
    configured = os.environ.get("STRIX_RUNS_DIR")
    candidate = Path(configured) if configured else Path("./strix_runs")
    return candidate.expanduser().resolve()


def get_run_dir(run_id: str) -> Path:
    """Return the path to a specific run directory."""
    return get_runs_dir() / run_id


def get_events_path(run_id: str) -> Path:
    """Return the path to the events log for a run."""
    return get_run_dir(run_id) / EVENTS_FILE_NAME

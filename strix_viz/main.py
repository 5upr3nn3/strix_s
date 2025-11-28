"""FastAPI entrypoint for the strix-viz service."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .run_loader import list_runs, load_events_page, load_snapshot, stream_new_events, load_vulnerabilities

LOGGER = logging.getLogger(__name__)

app = FastAPI(title="Strix Visualization Service", version=__version__)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/runs")
def api_list_runs():
    return [meta.model_dump() for meta in list_runs()]


@app.get("/api/runs/{run_id}/snapshot")
def api_snapshot(run_id: str):
    snapshot = load_snapshot(run_id)
    return snapshot.model_dump()


@app.get("/api/runs/{run_id}/events")
def api_events(run_id: str, offset: int = 0, limit: int = 200):
    limit = max(1, min(limit, 1000))
    page = load_events_page(run_id, offset=offset, limit=limit)
    return page.model_dump()


@app.get("/api/runs/{run_id}/vulnerabilities")
def api_vulnerabilities(run_id: str):
    """Load vulnerabilities from agent_runs directory."""
    vulnerabilities = load_vulnerabilities(run_id)
    return vulnerabilities


@app.websocket("/ws/runs/{run_id}")
async def websocket_events(websocket: WebSocket, run_id: str) -> None:
    await websocket.accept()
    try:
        async for event in stream_new_events(run_id):
            await websocket.send_json(event)
    except WebSocketDisconnect:
        LOGGER.info("Websocket disconnected for run %s", run_id)
    except HTTPException as exc:  # bubble up missing runs to the client
        await websocket.send_json({"error": exc.detail})
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
    except Exception:  # pragma: no cover - defensive logging
        LOGGER.exception("Unexpected error while streaming events for run %s", run_id)
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------

FRONTEND_DIST = Path(__file__).resolve().parent / "frontend" / "dist"


if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="strix-viz-ui")
else:
    @app.get("/")
    def _frontend_placeholder():
        return JSONResponse(
            {
                "message": "Frontend build not found. Run 'npm install && npm run build' inside strix_viz/frontend.'",
            }
        )


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------


def main(host: str = "0.0.0.0", port: int = 8000) -> None:  # noqa: S104
    import uvicorn

    uvicorn.run("strix_viz.main:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()

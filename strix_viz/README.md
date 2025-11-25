# Strix Viz

A lightweight visualization service for Strix runs. It exposes a FastAPI backend that watches Strix run folders and a React (Vite) frontend that renders a graph/terminal dashboard with live updates.

## Backend

### Requirements
- Python 3.12+
- Project dependencies installed via `poetry install`

### Configuration
- `STRIX_RUNS_DIR`: optional path to a directory containing Strix run folders. Defaults to `./strix_runs` (relative to the current working directory).

Each run folder should contain an `events.jsonl` with Strix event records.

### Run the API server
```bash
poetry run python -m strix_viz.main
```
This starts FastAPI on `http://localhost:8000` with:
- `GET /api/runs` – discover available runs.
- `GET /api/runs/{run_id}/snapshot` – normalized snapshot (agents, assets, vulnerabilities, tool calls, edges).
- `GET /api/runs/{run_id}/events` – paginated raw JSON events.
- `WS /ws/runs/{run_id}` – JSON stream of new log entries appended to the run's `events.jsonl`.

The backend automatically serves the built frontend bundle from `strix_viz/frontend/dist` if present.

## Frontend

Located under `strix_viz/frontend` (Vite + React + TypeScript).

### Install dependencies
```bash
cd strix_viz/frontend
npm install
```

### Development server
```bash
npm run dev
```
This proxies API/WebSocket traffic to `http://localhost:8000`.

### Production build
```bash
npm run build
```
The build artifacts land in `strix_viz/frontend/dist`. The FastAPI app serves these files automatically, so restarting `python -m strix_viz.main` will expose the UI at `http://localhost:8000`.

## Pointing to Strix runs
Ensure the backend can read run folders that look like:
```
strix_runs/my-run-123/
  events.jsonl
  ...other artifacts...
```
Set `STRIX_RUNS_DIR` if your runs live elsewhere:
```bash
export STRIX_RUNS_DIR=/path/to/custom/runs
```
Start the backend. The UI will list `my-run-123` and stream new events in real time.

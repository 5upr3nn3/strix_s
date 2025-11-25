import { useCallback, useEffect, useMemo, useState } from "react";
import GraphView, { GraphSelection } from "./components/GraphView";
import NodeDetailsPanel from "./components/NodeDetailsPanel";
import TerminalView, { TerminalFilters } from "./components/TerminalView";
import type { LiveEvent, RunMetadata, Snapshot, ToolCall } from "./types";

const defaultTerminalFilters: TerminalFilters = {
  agentId: "all",
  tool: "all",
  onlyErrors: false,
  onlySuccess: false
};

const TIME_RANGES = [
  { value: "all", label: "All time" },
  { value: "5m", label: "Last 5 min" },
  { value: "15m", label: "Last 15 min" },
  { value: "1h", label: "Last hour" }
];

const App = () => {
  const [runs, setRuns] = useState<RunMetadata[]>([]);
  const [selectedRun, setSelectedRun] = useState<string>("");
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [toolCalls, setToolCalls] = useState<ToolCall[]>([]);
  const [terminalFilters, setTerminalFilters] = useState<TerminalFilters>(defaultTerminalFilters);
  const [agentFilter, setAgentFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [timeRange, setTimeRange] = useState("all");
  const [selectedNode, setSelectedNode] = useState<GraphSelection | null>(null);
  const [highlightedNodeId, setHighlightedNodeId] = useState<string | null>(null);
  const [assetTerminalFilter, setAssetTerminalFilter] = useState<string | null>(null);

  const fetchRuns = useCallback(async () => {
    const response = await fetch("/api/runs");
    if (!response.ok) {
      throw new Error("Unable to fetch runs");
    }
    const data: RunMetadata[] = await response.json();
    setRuns(data);
    if (!data.length) {
      setSelectedRun("");
      return;
    }
    const currentExists = data.some((run) => run.id === selectedRun);
    if (!selectedRun || !currentExists) {
      setSelectedRun(data[0].id);
    }
  }, [selectedRun]);

  const loadSnapshot = useCallback(
    async (runId: string) => {
      setLoading(true);
      setError(null);
      try {
        const response = await fetch(`/api/runs/${runId}/snapshot`);
        if (!response.ok) {
          throw new Error(`${response.status} ${response.statusText}`);
        }
        const data: Snapshot = await response.json();
        setSnapshot(data);
        setToolCalls(data.tool_calls ?? []);
      } catch (loadError) {
        setError(loadError instanceof Error ? loadError.message : "Failed to load snapshot");
      } finally {
        setLoading(false);
      }
    },
    []
  );

  useEffect(() => {
    fetchRuns().catch((err) => setError(err.message));
  }, [fetchRuns]);

  useEffect(() => {
    if (selectedRun) {
      loadSnapshot(selectedRun).catch((err) => setError(err.message));
    }
  }, [selectedRun, loadSnapshot]);

  useEffect(() => {
    if (!selectedRun) {
      return undefined;
    }
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const socket = new WebSocket(`${protocol}://${window.location.host}/ws/runs/${selectedRun}`);
    let refreshHandle: number | undefined;

    const scheduleRefresh = () => {
      if (refreshHandle) {
        return;
      }
      refreshHandle = window.setTimeout(() => {
        refreshHandle = undefined;
        loadSnapshot(selectedRun).catch((err) => setError(err.message));
      }, 750);
    };

    socket.onmessage = (event) => {
      try {
        const payload: LiveEvent = JSON.parse(event.data);
        if (payload.type === "mcp_tool_call") {
          const call = mapEventToToolCall(payload);
          setToolCalls((current) => (current.some((existing) => isSameToolCall(existing, call)) ? current : [...current, call]));
        }
      } catch (parseError) {
        console.warn("Failed to parse live event", parseError);
      } finally {
        scheduleRefresh();
      }
    };

    socket.onerror = () => {
      setError("WebSocket connection lost");
    };

    return () => {
      socket.close();
      if (refreshHandle) {
        window.clearTimeout(refreshHandle);
      }
    };
  }, [selectedRun, loadSnapshot]);

  const timeFilteredCalls = useMemo(() => {
    if (timeRange === "all") {
      return toolCalls;
    }
    const threshold = computeThreshold(timeRange);
    return toolCalls.filter((call) => new Date(call.ts).getTime() >= threshold);
  }, [toolCalls, timeRange]);

  const assetFilteredCalls = useMemo(() => {
    if (!assetTerminalFilter) {
      return timeFilteredCalls;
    }
    return timeFilteredCalls.filter((call) => call.target === assetTerminalFilter || call.args?.url === assetTerminalFilter);
  }, [timeFilteredCalls, assetTerminalFilter]);

  const severityOptions = useMemo(() => {
    if (!snapshot) {
      return [];
    }
    const unique = new Set(
      snapshot.vulnerabilities
        .map((vuln) => vuln.severity?.toLowerCase())
        .filter((value): value is string => Boolean(value))
    );
    return Array.from(unique);
  }, [snapshot]);

  const agentOptions = snapshot?.agents ?? [];

  const handleNodeSelect = (selection: GraphSelection | null) => {
    setSelectedNode(selection);
    if (!selection) {
      setHighlightedNodeId(null);
      setAssetTerminalFilter(null);
      return;
    }
    setHighlightedNodeId(selection.id);
    if (selection.entityType === "agent") {
      const [, rawId] = selection.id.split(":", 2);
      setAgentFilter(rawId ?? "all");
      setTerminalFilters((current) => ({ ...current, agentId: rawId ?? "all" }));
      setAssetTerminalFilter(null);
    } else if (selection.entityType === "asset") {
      const [, rawId] = selection.id.split(":", 2);
      setAssetTerminalFilter(rawId ?? null);
    } else if (selection.entityType === "vuln") {
      const [, rawId] = selection.id.split(":", 2);
      const vuln = snapshot?.vulnerabilities.find((candidate) => candidate.id === (rawId ?? ""));
      if (vuln?.asset_id) {
        setAssetTerminalFilter(vuln.asset_id);
      }
      if (vuln?.agent_id) {
        setTerminalFilters((current) => ({ ...current, agentId: vuln.agent_id ?? "all" }));
      }
    }
  };

  const handleTerminalSelect = (call: ToolCall) => {
    if (call.target) {
      setHighlightedNodeId(`asset:${call.target}`);
    } else if (call.agent_id) {
      setHighlightedNodeId(`agent:${call.agent_id}`);
    }
  };

  const handleRunChange = (event: React.ChangeEvent<HTMLSelectElement>) => {
    setSelectedRun(event.target.value);
    setTerminalFilters(defaultTerminalFilters);
    setAgentFilter("all");
    setSeverityFilter("all");
    setAssetTerminalFilter(null);
  };

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="title-group">
          <h1>Strix Viz</h1>
          {loading && <span className="badge">Loading…</span>}
        </div>
        <div className="toolbar">
          <label>
            Run
            <select value={selectedRun} onChange={handleRunChange} disabled={!runs.length}>
              {!runs.length && <option value="">No runs found</option>}
              {runs.map((run) => (
                <option key={run.id} value={run.id}>
                  {run.id} ({run.event_count} events)
                </option>
              ))}
            </select>
          </label>
          <label>
            Agent filter
            <select value={agentFilter} onChange={(event) => setAgentFilter(event.target.value)}>
              <option value="all">All</option>
              {agentOptions.map((agent) => (
                <option key={agent.id} value={agent.id}>
                  {agent.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            Severity
            <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
              <option value="all">All</option>
              {severityOptions.map((severity) => (
                <option key={severity} value={severity}>
                  {severity}
                </option>
              ))}
            </select>
          </label>
          <label>
            Time range
            <select value={timeRange} onChange={(event) => setTimeRange(event.target.value)}>
              {TIME_RANGES.map((range) => (
                <option key={range.value} value={range.value}>
                  {range.label}
                </option>
              ))}
            </select>
          </label>
        </div>
      </header>
      {error && <div className="error-banner">{error}</div>}
      <div className="main-grid">
        <div className="graph-section">
          <GraphView
            snapshot={snapshot}
            agentFilter={agentFilter}
            severityFilter={severityFilter}
            highlightedNodeId={highlightedNodeId}
            onNodeSelect={handleNodeSelect}
          />
          <NodeDetailsPanel selection={selectedNode} snapshot={snapshot} onClear={() => handleNodeSelect(null)} />
        </div>
        <div className="terminal-section">
          <TerminalView
            toolCalls={assetFilteredCalls}
            filters={terminalFilters}
            onFiltersChange={setTerminalFilters}
            onSelectCall={handleTerminalSelect}
          />
        </div>
      </div>
    </div>
  );
};

const mapEventToToolCall = (event: LiveEvent): ToolCall => {
  const now = event.ts ?? new Date().toISOString();
  return {
    id: `live-${Math.random().toString(36).slice(2)}`,
    ts: now,
    agent_id: typeof event.agent_id === "string" ? event.agent_id : undefined,
    tool: typeof event.tool === "string" ? event.tool : undefined,
    target: typeof event.target === "string" ? event.target : undefined,
    status: typeof event.status === "string" ? event.status : undefined,
    summary: typeof event.result_summary === "string" ? event.result_summary : undefined,
    args: (event.args && typeof event.args === "object" ? (event.args as Record<string, unknown>) : {}),
    result_summary: typeof event.result_summary === "string" ? event.result_summary : undefined
  };
};

const isSameToolCall = (a: ToolCall, b: ToolCall) =>
  a.ts === b.ts && a.agent_id === b.agent_id && a.tool === b.tool && a.target === b.target && a.result_summary === b.result_summary;

const computeThreshold = (range: string) => {
  const now = Date.now();
  switch (range) {
    case "5m":
      return now - 5 * 60 * 1000;
    case "15m":
      return now - 15 * 60 * 1000;
    case "1h":
      return now - 60 * 60 * 1000;
    default:
      return 0;
  }
};

export default App;

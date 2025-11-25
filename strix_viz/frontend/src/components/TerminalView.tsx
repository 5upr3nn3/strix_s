import { useMemo, useState } from "react";
import type { ToolCall } from "../types";

export interface TerminalFilters {
  agentId: string;
  tool: string;
  onlyErrors: boolean;
  onlySuccess: boolean;
}

interface TerminalViewProps {
  toolCalls: ToolCall[];
  filters: TerminalFilters;
  onFiltersChange: (filters: TerminalFilters) => void;
  onSelectCall?: (call: ToolCall) => void;
}

const TerminalView = ({ toolCalls, filters, onFiltersChange, onSelectCall }: TerminalViewProps) => {
  const [expandedCallId, setExpandedCallId] = useState<string | null>(null);

  const agents = useMemo(
    () =>
      Array.from(
        new Set(
          toolCalls
            .map((call) => call.agent_id)
            .filter((id): id is string => Boolean(id))
        )
      ),
    [toolCalls]
  );
  const tools = useMemo(
    () =>
      Array.from(
        new Set(
          toolCalls
            .map((call) => call.tool)
            .filter((tool): tool is string => Boolean(tool))
        )
      ),
    [toolCalls]
  );

  const filteredCalls = useMemo(() => {
    return toolCalls.filter((call) => {
      const normalizedStatus = (call.status ?? "").toLowerCase();
      const isError = normalizedStatus !== "" && normalizedStatus !== "ok" && normalizedStatus !== "success";
      const isSuccess = normalizedStatus === "ok" || normalizedStatus === "success";

      if (filters.agentId !== "all" && call.agent_id !== filters.agentId) {
        return false;
      }
      if (filters.tool !== "all" && call.tool !== filters.tool) {
        return false;
      }
      if (filters.onlyErrors && !isError) {
        return false;
      }
      if (filters.onlySuccess && !isSuccess) {
        return false;
      }
      return true;
    });
  }, [toolCalls, filters]);

  const toggleExpand = (call: ToolCall) => {
    setExpandedCallId((current) => (current === call.id ? null : call.id));
    onSelectCall?.(call);
  };

  const renderFilters = () => (
    <div className="terminal-filters">
      <label>
        Agent
        <select value={filters.agentId} onChange={(event) => onFiltersChange({ ...filters, agentId: event.target.value })}>
          <option value="all">All</option>
          {agents.map((agentId) => (
            <option key={agentId} value={agentId}>
              {agentId}
            </option>
          ))}
        </select>
      </label>
      <label>
        Tool
        <select value={filters.tool} onChange={(event) => onFiltersChange({ ...filters, tool: event.target.value })}>
          <option value="all">All</option>
          {tools.map((tool) => (
            <option key={tool} value={tool}>
              {tool}
            </option>
          ))}
        </select>
      </label>
      <label className="terminal-toggle">
        <input
          type="checkbox"
          checked={filters.onlyErrors}
          onChange={(event) => onFiltersChange({ ...filters, onlyErrors: event.target.checked })}
        />
        Only errors
      </label>
      <label className="terminal-toggle">
        <input
          type="checkbox"
          checked={filters.onlySuccess}
          onChange={(event) => onFiltersChange({ ...filters, onlySuccess: event.target.checked })}
        />
        Only successful exploits
      </label>
    </div>
  );

  const renderCall = (call: ToolCall) => {
    const timestamp = new Date(call.ts).toLocaleTimeString();
    const status = call.status ?? "";
    const statusClass = status ? status.toLowerCase().replace(/[^a-z0-9]+/g, "-") : "";
    const summary = call.result_summary || call.summary || "";
    const isExpanded = expandedCallId === call.id;
    const target = call.target ?? call.args?.url ?? "(n/a)";

    return (
      <div key={call.id} className={`terminal-entry${isExpanded ? " expanded" : ""}`}>
        <button type="button" className="terminal-line" onClick={() => toggleExpand(call)}>
          <span className="terminal-ts">[{timestamp}]</span>
          <span className="terminal-agent">({call.agent_id ?? "system"})</span>
          <span className="terminal-tool">&gt; {call.tool ?? "tool.call"}</span>
          <span className="terminal-target">{target}</span>
          {status && <span className={`terminal-status status-${statusClass}`}>{status}</span>}
        </button>
        {summary && <div className="terminal-summary">→ {summary}</div>}
        {isExpanded && (
          <div className="terminal-details">
            <div>
              <strong>Args:</strong>
              <pre>{JSON.stringify(call.args, null, 2)}</pre>
            </div>
            {call.result_summary && (
              <div>
                <strong>Result:</strong>
                <p>{call.result_summary}</p>
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="terminal-view">
      {renderFilters()}
      <div className="terminal-window">
        {filteredCalls.length === 0 && <div className="terminal-placeholder">No tool calls yet.</div>}
        {filteredCalls.map(renderCall)}
      </div>
    </div>
  );
};

export default TerminalView;

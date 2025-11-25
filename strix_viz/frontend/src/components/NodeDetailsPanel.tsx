import type { Snapshot } from "../types";
import type { GraphSelection } from "./GraphView";

interface NodeDetailsPanelProps {
  selection: GraphSelection | null;
  snapshot: Snapshot | null;
  onClear?: () => void;
}

const formatDate = (value?: string) => {
  if (!value) {
    return "";
  }
  return new Date(value).toLocaleString();
};

const NodeDetailsPanel = ({ selection, snapshot, onClear }: NodeDetailsPanelProps) => {
  if (!selection || !snapshot) {
    return (
      <div className="node-details empty">
        <p>Select a node to see details.</p>
      </div>
    );
  }

  const [entityType, rawId] = selection.id.includes(":") ? selection.id.split(":", 2) : [selection.entityType, selection.id];

  if (entityType === "agent") {
    const agent = snapshot.agents.find((candidate) => candidate.id === rawId);
    if (!agent) {
      return null;
    }
    const associatedAssets = snapshot.edges
      .filter((edge) => edge.source === agent.id)
      .map((edge) => edge.target);

    return (
      <div className="node-details">
        <header>
          <h3>Agent {agent.label}</h3>
          <button type="button" onClick={onClear}>
            Clear
          </button>
        </header>
        <p>ID: {agent.id}</p>
        <p>First seen: {formatDate(agent.first_seen)}</p>
        <p>Last seen: {formatDate(agent.last_seen)}</p>
        <h4>Assets touched</h4>
        <ul>
          {associatedAssets.length ? associatedAssets.map((assetId) => <li key={assetId}>{assetId}</li>) : <li>No assets recorded.</li>}
        </ul>
      </div>
    );
  }

  if (entityType === "asset") {
    const asset = snapshot.assets.find((candidate) => candidate.id === rawId);
    if (!asset) {
      return null;
    }
    const agentIds = new Set(snapshot.agents.map((agent) => agent.id));
    const incomingAgents = snapshot.edges.filter((edge) => edge.target === asset.id && agentIds.has(edge.source));
    const relatedVulns = snapshot.vulnerabilities.filter((vuln) => vuln.asset_id === asset.id);

    return (
      <div className="node-details">
        <header>
          <h3>Asset</h3>
          <button type="button" onClick={onClear}>
            Clear
          </button>
        </header>
        <p>URL: {asset.url}</p>
        <p>First seen: {formatDate(asset.first_seen)}</p>
        <p>Last seen: {formatDate(asset.last_seen)}</p>
        <h4>Agents</h4>
        <ul>
          {incomingAgents.length ? incomingAgents.map((edge) => <li key={edge.id}>{edge.source}</li>) : <li>No agents yet.</li>}
        </ul>
        <h4>Vulnerabilities</h4>
        <ul>
          {relatedVulns.length
            ? relatedVulns.map((vuln) => (
                <li key={vuln.id}>
                  {vuln.id} ({vuln.severity ?? "unknown"}) - {vuln.category ?? ""}
                </li>
              ))
            : <li>No findings.</li>}
        </ul>
      </div>
    );
  }

  const vuln = snapshot.vulnerabilities.find((candidate) => candidate.id === rawId);
  if (!vuln) {
    return null;
  }
  return (
    <div className="node-details">
      <header>
        <h3>Vulnerability {vuln.id}</h3>
        <button type="button" onClick={onClear}>
          Clear
        </button>
      </header>
      <p>Severity: {vuln.severity ?? "unknown"}</p>
      <p>Category: {vuln.category ?? "n/a"}</p>
      <p>Detected: {formatDate(vuln.ts)}</p>
      {vuln.asset_id && <p>Asset: {vuln.asset_id}</p>}
      {vuln.agent_id && <p>Agent: {vuln.agent_id}</p>}
      {vuln.description && (
        <div>
          <h4>Description</h4>
          <p>{vuln.description}</p>
        </div>
      )}
    </div>
  );
};

export default NodeDetailsPanel;

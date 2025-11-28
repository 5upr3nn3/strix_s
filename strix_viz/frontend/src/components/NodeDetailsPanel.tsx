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
        <p>Выберите узел для просмотра деталей.</p>
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
          <h3>Агент {agent.label}</h3>
          <button type="button" onClick={onClear}>
            Очистить
          </button>
        </header>
        <p>ID: {agent.id}</p>
        <p>Первый раз: {formatDate(agent.first_seen)}</p>
        <p>Последний раз: {formatDate(agent.last_seen)}</p>
        <h4>Затронутые ресурсы</h4>
        <ul>
          {associatedAssets.length ? associatedAssets.map((assetId) => <li key={assetId}>{assetId}</li>) : <li>Ресурсы не зафиксированы.</li>}
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
          <h3>Ресурс</h3>
          <button type="button" onClick={onClear}>
            Очистить
          </button>
        </header>
        <p>URL: {asset.url}</p>
        <p>Первый раз: {formatDate(asset.first_seen)}</p>
        <p>Последний раз: {formatDate(asset.last_seen)}</p>
        <h4>Агенты</h4>
        <ul>
          {incomingAgents.length ? incomingAgents.map((edge) => <li key={edge.id}>{edge.source}</li>) : <li>Агенты отсутствуют.</li>}
        </ul>
        <h4>Уязвимости</h4>
        <ul>
          {relatedVulns.length
            ? relatedVulns.map((vuln) => (
                <li key={vuln.id}>
                  {vuln.id} ({vuln.severity ?? "неизвестно"}) - {vuln.category ?? ""}
                </li>
              ))
            : <li>Находки отсутствуют.</li>}
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
        <h3>Уязвимость {vuln.id}</h3>
        <button type="button" onClick={onClear}>
          Очистить
        </button>
      </header>
      <p>Критичность: {vuln.severity ?? "неизвестно"}</p>
      <p>Категория: {vuln.category ?? "н/д"}</p>
      <p>Обнаружена: {formatDate(vuln.ts)}</p>
      {vuln.asset_id && <p>Ресурс: {vuln.asset_id}</p>}
      {vuln.agent_id && <p>Агент: {vuln.agent_id}</p>}
      {vuln.description && (
        <div>
          <h4>Описание</h4>
          <p>{vuln.description}</p>
        </div>
      )}
    </div>
  );
};

export default NodeDetailsPanel;

import { useEffect, useState } from "react";

interface Vulnerability {
  id: string;
  title: string;
  severity: string;
  timestamp: string;
  file: string;
}

interface VulnerabilitiesPanelProps {
  runId: string;
}

const severityColors: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
  INFO: "#3b82f6",
};

const VulnerabilitiesPanel = ({ runId }: VulnerabilitiesPanelProps) => {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!runId) {
      return;
    }
    setLoading(true);
    setError(null);
    fetch(`/api/runs/${runId}/vulnerabilities`)
      .then((res) => {
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`);
        }
        return res.json();
      })
      .then((data: Vulnerability[]) => {
        setVulnerabilities(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, [runId]);

  if (loading) {
    return (
      <div className="vulnerabilities-panel">
        <h3>Уязвимости</h3>
        <div className="vulnerabilities-loading">Загрузка...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="vulnerabilities-panel">
        <h3>Уязвимости</h3>
        <div className="vulnerabilities-error">Ошибка: {error}</div>
      </div>
    );
  }

  if (vulnerabilities.length === 0) {
    return (
      <div className="vulnerabilities-panel">
        <h3>Уязвимости</h3>
        <div className="vulnerabilities-empty">Уязвимости не найдены</div>
      </div>
    );
  }

  return (
    <div className="vulnerabilities-panel">
      <h3>Найденные уязвимости ({vulnerabilities.length})</h3>
      <div className="vulnerabilities-list">
        {vulnerabilities.map((vuln) => {
          const severity = vuln.severity?.toUpperCase() || "UNKNOWN";
          const color = severityColors[severity] || "#6b7280";
          return (
            <div key={vuln.id} className="vulnerability-item">
              <div className="vulnerability-header">
                <span className="vulnerability-id">{vuln.id}</span>
                <span className="vulnerability-severity" style={{ backgroundColor: color }}>
                  {severity}
                </span>
              </div>
              <div className="vulnerability-title">{vuln.title}</div>
              <div className="vulnerability-timestamp">{vuln.timestamp}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default VulnerabilitiesPanel;


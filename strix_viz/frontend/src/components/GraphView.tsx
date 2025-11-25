import CytoscapeComponent from "react-cytoscapejs";
import type { Core, ElementDefinition } from "cytoscape";
import { useEffect, useMemo, useRef } from "react";
import { Snapshot } from "../types";

const stylesheet = [
  {
    selector: "node",
    style: {
      label: "data(label)",
      color: "#e5e7eb",
      "font-size": "12px",
      "text-valign": "center",
      "text-outline-width": 2,
      "text-outline-color": "#1f2937",
      "background-color": "#4b5563",
      "border-width": 1,
      "border-color": "#111827"
    }
  },
  {
    selector: "node.agent",
    style: {
      "background-color": "#2563eb",
      shape: "round-rectangle",
      width: "label",
      padding: "8px"
    }
  },
  {
    selector: "node.asset",
    style: {
      "background-color": "#10b981",
      shape: "rectangle",
      width: "label",
      padding: "6px"
    }
  },
  {
    selector: "node.vuln",
    style: {
      shape: "diamond",
      width: 32,
      height: 32,
      "background-color": "mapData(severityScore, 0, 3, #22c55e, #ef4444)"
    }
  },
  {
    selector: "node.faded",
    style: {
      opacity: 0.3
    }
  },
  {
    selector: "node.highlighted",
    style: {
      "border-width": 4,
      "border-color": "#fbbf24"
    }
  },
  {
    selector: "edge",
    style: {
      width: 2,
      "line-color": "#6b7280",
      "target-arrow-color": "#6b7280",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      label: "data(label)",
      "font-size": "10px",
      color: "#9ca3af",
      "text-background-color": "#111827",
      "text-background-opacity": 0.7,
      "text-background-padding": "2px"
    }
  }
];

const severityScores: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3
};

export interface GraphSelection {
  id: string;
  entityType: "agent" | "asset" | "vuln";
}

interface GraphViewProps {
  snapshot: Snapshot | null;
  agentFilter: string;
  severityFilter: string;
  highlightedNodeId?: string | null;
  onNodeSelect?: (selection: GraphSelection | null) => void;
}

const GraphView = ({ snapshot, agentFilter, severityFilter, highlightedNodeId, onNodeSelect }: GraphViewProps) => {
  const cyRef = useRef<Core | null>(null);

  const { elements } = useMemo(() => {
    if (!snapshot) {
      return { elements: [] as ElementDefinition[] };
    }
    const agents = new Map(snapshot.agents.map((agent) => [agent.id, agent]));
    const assets = new Map(snapshot.assets.map((asset) => [asset.id, asset]));
    const vulns = new Map(snapshot.vulnerabilities.map((vuln) => [vuln.id, vuln]));

    const nodes: ElementDefinition[] = [];

    const shouldFadeAgent = (id: string) => agentFilter !== "all" && id !== agentFilter;
    const shouldFadeVuln = (severity?: string | null) => {
      if (severityFilter === "all") {
        return false;
      }
      const normalized = severity?.toLowerCase() ?? "unknown";
      return normalized !== severityFilter;
    };

    agents.forEach((agent) => {
      nodes.push({
        data: {
          id: `agent:${agent.id}`,
          label: agent.label,
          entityType: "agent"
        },
        classes: `agent${shouldFadeAgent(agent.id) ? " faded" : ""}`
      });
    });

    assets.forEach((asset) => {
      nodes.push({
        data: {
          id: `asset:${asset.id}`,
          label: asset.label,
          entityType: "asset"
        },
        classes: "asset"
      });
    });

    vulns.forEach((vuln) => {
      const severity = vuln.severity?.toLowerCase() ?? "low";
      nodes.push({
        data: {
          id: `vuln:${vuln.id}`,
          label: vuln.id,
          entityType: "vuln",
          severity,
          severityScore: severityScores[severity] ?? 1
        },
        classes: `vuln${shouldFadeVuln(severity) ? " faded" : ""}`
      });
    });

    const prefix = (id: string) => {
      if (agents.has(id)) {
        return `agent:${id}`;
      }
      if (vulns.has(id)) {
        return `vuln:${id}`;
      }
      if (assets.has(id)) {
        return `asset:${id}`;
      }
      return id;
    };

    const edges = snapshot.edges
      .map((edge) => ({
        data: {
          id: edge.id,
          source: prefix(edge.source),
          target: prefix(edge.target),
          label: edge.label ?? edge.relation
        }
      }))
      .filter((edge) => edge.data.source && edge.data.target);

    return { elements: [...nodes, ...edges] };
  }, [snapshot, agentFilter, severityFilter]);

  useEffect(() => {
    if (!cyRef.current) {
      return;
    }
    const cy = cyRef.current;
    cy.nodes().removeClass("highlighted");
    if (highlightedNodeId) {
      const node = cy.$(`node[id = "${highlightedNodeId}"]`);
      if (node && node.length > 0) {
        node.addClass("highlighted");
        cy.center(node);
      }
    }
  }, [highlightedNodeId]);

  const handleCyInit = (cy: Core) => {
    cyRef.current = cy;
    cy.off("tap");
    cy.on("tap", "node", (event) => {
      const node = event.target;
      const entityType = (node.data("entityType") ?? "asset") as GraphSelection["entityType"];
      onNodeSelect?.({ id: node.id(), entityType });
    });
    cy.on("tap", (event) => {
      if (event.target === cy) {
        onNodeSelect?.(null);
      }
    });
  };

  useEffect(() => {
    if (!cyRef.current) {
      return;
    }
    const layout = cyRef.current.layout({ name: "breadthfirst", directed: true, padding: 20, spacingFactor: 0.8 });
    layout.run();
  }, [elements]);

  return (
    <CytoscapeComponent
      elements={elements}
      stylesheet={stylesheet}
      cy={handleCyInit}
      className="graph-canvas"
      style={{ width: "100%", height: "100%" }}
    />
  );
};

export default GraphView;

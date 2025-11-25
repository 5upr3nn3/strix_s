export interface RunMetadata {
  id: string;
  created_at?: string;
  event_count: number;
}

export interface Agent {
  id: string;
  label: string;
  first_seen: string;
  last_seen: string;
}

export interface Asset {
  id: string;
  label: string;
  url: string;
  first_seen: string;
  last_seen: string;
}

export interface Vulnerability {
  id: string;
  agent_id?: string | null;
  asset_id?: string | null;
  severity?: string | null;
  category?: string | null;
  description?: string | null;
  ts: string;
}

export interface Edge {
  id: string;
  source: string;
  target: string;
  relation: string;
  label?: string | null;
}

export interface ToolCall {
  id: string;
  ts: string;
  agent_id?: string | null;
  tool?: string | null;
  target?: string | null;
  status?: string | null;
  summary?: string | null;
  args: Record<string, unknown>;
  result_summary?: string | null;
}

export interface Snapshot {
  run_id: string;
  agents: Agent[];
  assets: Asset[];
  vulnerabilities: Vulnerability[];
  edges: Edge[];
  tool_calls: ToolCall[];
  last_event_ts?: string | null;
}

export type LiveEvent = Record<string, unknown> & {
  type?: string;
  ts?: string;
};

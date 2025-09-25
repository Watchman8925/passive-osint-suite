export interface Capability {
  id: string;
  name: string;
  description: string;
  category: string;
  version: string;
  inputs: Record<string, string>;
  produces: string[];
  dependencies: string[];
  cost_weight: number;
  risk_level: string;
  enabled: boolean;
}

export interface PlannedTask {
  id: string;                // plan-<capability_id>
  capability_id: string;
  inputs: Record<string,string>;
  depends_on: string[];
  status: string;            // planned|running|completed|failed
}

export interface Plan {
  investigation_id: string;
  tasks: PlannedTask[];
}

export interface ExecutionResult {
  task_id: string;
  success: boolean;
  error?: string | null;
  produced_entities: any[];
  produced_relationships: any[];
  evidence_ids: string[];
}

export interface ProvenanceSummary {
  investigation_id: string;
  leaf_count: number;
  merkle_root: string | null;
  leaves: string[]; // SHA-256 hashes
}

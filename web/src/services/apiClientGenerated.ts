// Lightweight wrapper around generated OpenAPI types.
// Uses existing axios instance pattern but typed via openapi-typescript output.
import axios from 'axios';
import type { paths } from '../types/openapi-types';
import type { Capability, Plan, ExecutionResult, ProvenanceSummary } from '../types/autonomy';

// Helper to extract response body type from a path+method
export type OperationResponse<P extends keyof paths, M extends keyof paths[P]> =
  paths[P][M] extends { responses: infer R }
    ? R extends { 200: infer OK }
      ? OK extends { content: { 'application/json': infer B } } ? B : unknown
      : unknown
    : unknown;

const baseURL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export const http = axios.create({ baseURL, timeout: 30000 });

// Example typed operations (incremental adoption)
export async function getHealth() {
  const res = await http.get('/api/health');
  return res.data as OperationResponse<'/api/health','get'>;
}

export async function listInvestigations(params?: { skip?: number; limit?: number; status?: string; include_archived?: boolean; include_meta?: boolean }) {
  const res = await http.get('/api/investigations', { params });
  return res.data as OperationResponse<'/api/investigations','get'>;
}

export async function createInvestigation(body: any) {
  const res = await http.post('/api/investigations', body);
  return res.data as OperationResponse<'/api/investigations','post'>;
}

// --- Autonomy endpoints ---
export async function listCapabilities() {
  const res = await http.get('/api/capabilities');
  return res.data as Capability[];
}

export async function getPlan(investigationId: string) {
  const res = await http.get(`/api/investigations/${investigationId}/plan`);
  return res.data as Plan;
}

export async function executeNext(investigationId: string) {
  const res = await http.post(`/api/investigations/${investigationId}/execute/next`);
  return res.data as ExecutionResult | { message: string };
}

export async function executeAll(investigationId: string) {
  const res = await http.post(`/api/investigations/${investigationId}/execute/all`);
  return res.data as { message: string };
}

export async function getProvenance(investigationId: string) {
  const res = await http.get(`/api/investigations/${investigationId}/evidence/provenance`);
  return res.data as ProvenanceSummary;
}

export const generatedClient = {
  getHealth,
  listInvestigations,
  createInvestigation,
  listCapabilities,
  getPlan,
  executeNext,
  executeAll,
  getProvenance,
};

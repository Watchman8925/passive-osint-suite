import { useCallback, useEffect, useMemo, useState } from 'react';
import { generatedClient } from '../services/apiClientGenerated';
import type { Capability, Plan, PlannedTask, ProvenanceSummary, ExecutionResult } from '../types/autonomy';
import { useInvestigationWebSocket } from './useWebSocket';

export function useCapabilities() {
  const [data, setData] = useState<Capability[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    generatedClient.listCapabilities()
      .then(d => { if (!cancelled) { setData(d); setLoading(false); } })
      .catch(e => { if (!cancelled) { setError(e.message || 'Failed'); setLoading(false); } });
    return () => { cancelled = true; };
  }, []);

  return { data, loading, error };
}

export function usePlan(investigationId?: string) {
  const [plan, setPlan] = useState<Plan | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { planTasks } = useInvestigationWebSocket();

  const refresh = useCallback(() => {
    if (!investigationId) return;
    setLoading(true); setError(null);
    generatedClient.getPlan(investigationId)
      .then(p => { setPlan(p); setLoading(false); })
      .catch(e => { setError(e.message || 'Failed to load plan'); setLoading(false); });
  }, [investigationId]);

  useEffect(() => { refresh(); }, [refresh]);

  // Merge live task status updates from ws with static plan
  const merged = useMemo(() => {
    if (!plan) return null;
    const taskMap: Record<string, PlannedTask> = {};
    for (const t of plan.tasks) taskMap[t.id] = t;
    for (const [tid, t] of Object.entries(planTasks)) {
      if (taskMap[tid]) {
        taskMap[tid] = { ...taskMap[tid], status: t.status };
      } else {
        taskMap[tid] = t; // newly appeared (unlikely but safe)
      }
    }
    return { ...plan, tasks: Object.values(taskMap) } as Plan;
  }, [plan, planTasks]);

  return { plan: merged, loading, error, refresh };
}

export function useExecution(investigationId?: string) {
  const [executing, setExecuting] = useState(false);
  const [lastResult, setLastResult] = useState<ExecutionResult | { message: string } | null>(null);
  const runNext = useCallback(async () => {
    if (!investigationId) return;
    setExecuting(true); try { const r = await generatedClient.executeNext(investigationId); setLastResult(r as any); } finally { setExecuting(false); }
  }, [investigationId]);
  const runAll = useCallback(async () => {
    if (!investigationId) return;
    setExecuting(true); try { const r = await generatedClient.executeAll(investigationId); setLastResult(r as any); } finally { setExecuting(false); }
  }, [investigationId]);
  return { executing, lastResult, runNext, runAll };
}

export function useProvenance(investigationId?: string) {
  const [data, setData] = useState<ProvenanceSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const refresh = useCallback(() => {
    if (!investigationId) return;
    setLoading(true); setError(null);
    generatedClient.getProvenance(investigationId)
      .then(d => { setData(d); setLoading(false); })
      .catch(e => { setError(e.message || 'Failed'); setLoading(false); });
  }, [investigationId]);
  useEffect(() => { refresh(); }, [refresh]);
  return { data, loading, error, refresh };
}

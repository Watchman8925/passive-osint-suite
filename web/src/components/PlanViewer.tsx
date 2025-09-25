import React, { useMemo, useState } from 'react';
import { usePlan, useExecution } from '../hooks/useAutonomy';
import { generatedClient } from '../services/apiClientGenerated';

interface Props { investigationId?: string }

export const PlanViewer: React.FC<Props> = ({ investigationId }) => {
  const { plan, loading, error, refresh } = usePlan(investigationId);
  const { runNext, runAll, executing, lastResult } = useExecution(investigationId);
  const [generating, setGenerating] = useState(false);
  const [genError, setGenError] = useState<string | null>(null);

  const orderedTasks = useMemo(() => (plan?.tasks || []).slice().sort((a,b)=>a.id.localeCompare(b.id)), [plan]);

  if (!investigationId) return <div>Select an investigation...</div>;
  if (loading) return <div>Loading plan...</div>;
  if (error) return <div className="text-red-600">{error}</div>;
  if (!plan) {
    return (
      <div className="space-y-3">
        <h3 className="font-semibold text-lg">No Plan Built</h3>
        <p className="text-sm text-gray-600">Generate a dependency-aware capability plan for this investigation.</p>
        {genError && <div className="text-sm text-red-600">{genError}</div>}
        <button
          disabled={generating || !investigationId}
          onClick={async () => {
            if (!investigationId) return;
            setGenError(null);
            setGenerating(true);
            try {
              await generatedClient.getPlan(investigationId); // triggers planner server-side if lazy
              refresh();
            } catch (e:any) {
              setGenError(e.message || 'Failed to generate plan');
            } finally {
              setGenerating(false);
            }
          }}
          className="px-3 py-1.5 bg-blue-600 text-white text-sm rounded disabled:opacity-50"
        >{generating ? 'Generating...' : 'Generate Plan'}</button>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <h3 className="font-semibold text-lg">Plan Tasks ({orderedTasks.length})</h3>
        <button disabled={executing} onClick={runNext} className="px-2 py-1 bg-blue-600 text-white text-sm rounded disabled:opacity-50 flex items-center gap-1">{executing && <span className="animate-spin h-3 w-3 border-2 border-white border-t-transparent rounded-full"/>}Run Next</button>
        <button disabled={executing} onClick={runAll} className="px-2 py-1 bg-indigo-600 text-white text-sm rounded disabled:opacity-50 flex items-center gap-1">{executing && <span className="animate-spin h-3 w-3 border-2 border-white border-t-transparent rounded-full"/>}Run All</button>
        <button onClick={refresh} className="px-2 py-1 bg-gray-200 text-sm rounded">Refresh</button>
        <button disabled className="px-2 py-1 bg-gray-300 text-gray-600 text-sm rounded" title="Cancellation not yet implemented">Cancel (soon)</button>
      </div>
      {executing && <div className="text-xs text-blue-600">Executing... waiting for task completion events.</div>}
      {lastResult && 'task_id' in lastResult && (
        <div className="text-xs text-gray-600">Last: {('success' in lastResult && (lastResult as any).success) ? 'Success' : 'Message'} {(lastResult as any).task_id || (lastResult as any).message}</div>
      )}
      {plan && plan.tasks && (
        <div className="text-xs text-gray-500">Next runnable (no unmet deps): {orderedTasks.filter(t => t.status==='pending' && t.depends_on.every(d => orderedTasks.find(x=>x.id===d)?.status==='completed')).slice(0,3).map(t=>t.id).join(', ') || '—'}</div>
      )}
      <table className="min-w-full text-sm border">
        <thead className="bg-gray-100">
          <tr>
            <th className="p-1 text-left">Task</th>
            <th className="p-1 text-left">Capability</th>
            <th className="p-1 text-left">Status</th>
            <th className="p-1 text-left">Depends On</th>
          </tr>
        </thead>
        <tbody>
          {orderedTasks.map(t => (
            <tr key={t.id} className="border-t hover:bg-gray-50">
              <td className="p-1 font-mono">{t.id}</td>
              <td className="p-1">{t.capability_id}</td>
              <td className="p-1"><span className={`px-1 rounded text-white ${t.status==='completed'?'bg-green-600':t.status==='running'?'bg-blue-600':t.status==='failed'?'bg-red-600':'bg-gray-500'}`}>{t.status}</span></td>
              <td className="p-1 text-xs">{t.depends_on.join(', ') || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

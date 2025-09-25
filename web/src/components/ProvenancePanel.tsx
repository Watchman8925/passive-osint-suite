import React from 'react';
import { useProvenance } from '../hooks/useAutonomy';

interface Props { investigationId?: string }

export const ProvenancePanel: React.FC<Props> = ({ investigationId }) => {
  const { data, loading, error, refresh } = useProvenance(investigationId);
  if (!investigationId) return <div>Select an investigation...</div>;
  if (loading) return <div>Loading provenance...</div>;
  if (error) return <div className="text-red-600">{error}</div>;
  if (!data) return <div>No provenance yet.</div>;
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <h3 className="font-semibold text-lg">Evidence Provenance</h3>
        <button onClick={refresh} className="px-2 py-1 bg-gray-200 text-sm rounded">Refresh</button>
      </div>
      <div className="text-xs font-mono break-all">
        Root: {data.merkle_root || '— none —'} (leaves: {data.leaf_count})
      </div>
      {data.leaves.length > 0 && (
        <details className="text-xs">
          <summary className="cursor-pointer">Show Leaves</summary>
          <ul className="max-h-48 overflow-auto space-y-0.5 mt-1">
            {data.leaves.map(h => <li key={h} className="font-mono">{h}</li>)}
          </ul>
        </details>
      )}
    </div>
  );
};

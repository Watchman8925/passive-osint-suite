import React from 'react';
import { useCapabilities } from '../hooks/useAutonomy';

export const CapabilityCatalog: React.FC = () => {
  const { data, loading, error } = useCapabilities();
  if (loading) return <div>Loading capabilities...</div>;
  if (error) return <div className="text-red-600">{error}</div>;
  if (!data) return null;
  return (
    <div className="space-y-2">
      <h3 className="font-semibold text-lg">Capabilities</h3>
  <table className="min-w-full text-sm border">
        <thead className="bg-gray-100">
          <tr>
            <th className="p-1 text-left">ID</th>
            <th className="p-1 text-left">Category</th>
            <th className="p-1 text-left">Risk</th>
            <th className="p-1 text-left">Cost</th>
            <th className="p-1 text-left">Produces</th>
            <th className="p-1 text-left">Deps</th>
          </tr>
        </thead>
        <tbody>
          {data.map(c => {
            const riskColor = c.risk_level === 'high' ? 'bg-red-600' : c.risk_level === 'medium' ? 'bg-yellow-600' : 'bg-green-600';
            const costColor = c.cost_weight >= 5 ? 'bg-purple-600' : c.cost_weight >=3 ? 'bg-blue-600' : 'bg-gray-600';
            return (
              <tr key={c.id} className="border-t hover:bg-gray-50">
                <td className="p-1 font-mono">{c.id}</td>
                <td className="p-1">{c.category}</td>
                <td className="p-1"><span className={`px-1 rounded text-white ${riskColor}`}>{c.risk_level}</span></td>
                <td className="p-1"><span className={`px-1 rounded text-white ${costColor}`}>{c.cost_weight}</span></td>
                <td className="p-1">{c.produces.join(', ')}</td>
                <td className="p-1 text-xs">{c.dependencies.join(', ') || '-'}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

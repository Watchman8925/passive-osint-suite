import React from 'react';
import { useInvestigations } from '../../hooks/useInvestigations';
import { useSelectedInvestigation } from '../../contexts/SelectedInvestigationContext';

interface InvestigationSelectorProps {
  className?: string;
  placeholder?: string;
  autoSelectFirst?: boolean;
}

export const InvestigationSelector: React.FC<InvestigationSelectorProps> = ({ className = '', placeholder = 'Select Investigation', autoSelectFirst = false }) => {
  const { data: investigations } = useInvestigations();
  const { selectedId, setSelectedId } = useSelectedInvestigation();

  React.useEffect(() => {
    if (autoSelectFirst && !selectedId && investigations && investigations.length > 0) {
      setSelectedId(investigations[0].investigation_id);
    }
  }, [autoSelectFirst, selectedId, investigations, setSelectedId]);

  return (
    <select
      className={`text-xs border rounded px-2 py-1 bg-white focus:outline-none focus:ring ${className}`}
      value={selectedId || ''}
      onChange={e => setSelectedId(e.target.value || null)}
    >
      <option value="">{placeholder}</option>
      {(investigations || []).map(inv => (
        <option key={inv.investigation_id} value={inv.investigation_id}>{inv.name || inv.investigation_id}</option>
      ))}
    </select>
  );
};

export default InvestigationSelector;

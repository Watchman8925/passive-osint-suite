import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';

interface SelectedInvestigationContextValue {
  selectedId: string | null;
  setSelectedId: (id: string | null) => void;
  clear: () => void;
}

const SelectedInvestigationContext = createContext<SelectedInvestigationContextValue | undefined>(undefined);

const STORAGE_KEY = 'osint.selectedInvestigationId';

export const SelectedInvestigationProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
  const [selectedId, setSelectedIdState] = useState<string | null>(null);

  // Load from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) setSelectedIdState(stored);
    } catch (_) { /* ignore */ }
  }, []);

  const setSelectedId = useCallback((id: string | null) => {
    setSelectedIdState(id);
    try {
      if (id) localStorage.setItem(STORAGE_KEY, id); else localStorage.removeItem(STORAGE_KEY);
    } catch (_) { /* ignore */ }
  }, []);

  const clear = useCallback(() => setSelectedId(null), [setSelectedId]);

  return (
    <SelectedInvestigationContext.Provider value={{ selectedId, setSelectedId, clear }}>
      {children}
    </SelectedInvestigationContext.Provider>
  );
};

export function useSelectedInvestigation() {
  const ctx = useContext(SelectedInvestigationContext);
  if (!ctx) throw new Error('useSelectedInvestigation must be used within SelectedInvestigationProvider');
  return ctx;
}

import { useEffect, useState, useCallback } from 'react';
import { generatedClient } from '../services/apiClientGenerated';

export interface InvestigationRecord {
  investigation_id: string;
  name: string;
  targets: string[];
  investigation_type: string;
  priority: string;
  status: string;
  created_at?: string;
  progress?: number;
}

interface UseInvestigationsState {
  data: InvestigationRecord[] | null;
  loading: boolean;
  error: string | null;
  refresh: () => void;
}

export function useInvestigations(authToken?: string): UseInvestigationsState {
  const [data, setData] = useState<InvestigationRecord[] | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);

  const refresh = useCallback(() => setNonce(n => n + 1), []);

  useEffect(() => {
    let cancelled = false;
    async function run() {
      setLoading(true);
      setError(null);
      try {
        const json = await generatedClient.listInvestigations();
        if (!cancelled) {
          setData(Array.isArray(json) ? json : (json as any)?.items || []);
          setLoading(false);
        }
      } catch (e:any) {
        if (!cancelled) {
          setError(e?.message || 'Failed to load investigations');
          setLoading(false);
        }
      }
    }
    run();
    return () => { cancelled = true; };
  }, [authToken, nonce]);

  return { data, loading, error, refresh };
}

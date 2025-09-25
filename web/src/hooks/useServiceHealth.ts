import { useEffect, useState } from 'react';

interface HealthData {
  status?: string;
  services?: Record<string, any>;
  [k: string]: any;
}

interface TorStatusData {
  proxy_reachable?: boolean;
  [k: string]: any;
}

export interface ServiceHealthState {
  loading: boolean;
  backend: 'ok' | 'error' | 'unknown';
  tor: 'ok' | 'warn' | 'error' | 'unknown';
  errors: string[];
  raw: { health?: HealthData | null; tor?: TorStatusData | null };
  refresh: () => void;
}

export function useServiceHealth(pollMs = 5000): ServiceHealthState {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [tor, setTor] = useState<TorStatusData | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);
  const [errors, setErrors] = useState<string[]>([]);

  useEffect(() => {
    let cancelled = false;
    async function fetchAll() {
      setLoading(true);
      const bases = ['http://127.0.0.1:8000', 'http://localhost:8000'];
      async function first(pathVariants: string[], label?: string): Promise<any | null> {
        for (const base of bases) {
          for (const p of pathVariants) {
            try {
              const r = await fetch(base + p, { cache: 'no-store' });
              if (r.ok) return await r.json();
            } catch {
              if (label) {
                setErrors(prev => prev.slice(-30).concat(`${new Date().toLocaleTimeString()} ${label} fetch failed`));
              }
            }
          }
        }
        return null;
      }
      const h = await first(['/api/health', '/health'], 'health');
      const t = await first(['/tor/status'], 'tor');
      if (!cancelled) {
        setHealth(h);
        setTor(t);
        setLoading(false);
      }
    }
    fetchAll();
    const id = setInterval(fetchAll, pollMs);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [pollMs, nonce]);

  const backend: ServiceHealthState['backend'] = health ? 'ok' : loading ? 'unknown' : 'error';
  let torState: ServiceHealthState['tor'] = 'unknown';
  if (tor) {
    if (tor.proxy_reachable === false) torState = 'warn';
    else torState = 'ok';
  } else if (!loading && !tor) torState = 'error';

  return {
    loading,
    backend,
    tor: torState,
    errors,
    raw: { health, tor },
    refresh: () => setNonce(n => n + 1)
  };
}

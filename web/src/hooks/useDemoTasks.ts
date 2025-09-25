import { useCallback, useEffect, useState } from 'react';

interface DemoTask {
  id: string;
  name: string;
  type: string;
  status: string;
  progress: number;
  created_at?: string;
  started_at?: string | null;
  completed_at?: string | null;
}

interface UseDemoTasksOptions {
  investigationId?: string;
  token?: string;
  auto?: boolean;
}

export function useDemoTasks({ investigationId, token, auto = false }: UseDemoTasksOptions) {
  const [tasks, setTasks] = useState<DemoTask[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [seeded, setSeeded] = useState<boolean>(false);

  const seed = useCallback(async () => {
    if (!investigationId || !token) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/api/investigations/${investigationId}/demo/seed-tasks`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      if (!res.ok) throw new Error(`Seed failed: ${res.status}`);
      const json = await res.json();
      if (json.tasks) {
        setTasks(json.tasks);
        setSeeded(true);
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [investigationId, token]);

  useEffect(() => {
    if (auto && investigationId && token) {
      seed();
    }
  }, [auto, investigationId, token, seed]);

  return { tasks, loading, error, seeded, seed };
}

import React, { useEffect, useMemo, useState } from 'react';
import { TaskStatus } from '../../types/investigation';
import { useWebSocketContext } from '../../contexts/WebSocketContext';
import { investigationApi } from '../../services/api';
import { motion, AnimatePresence } from 'framer-motion';
import { useSelectedInvestigation } from '../../contexts/SelectedInvestigationContext';
import InvestigationSelector from '../investigations/InvestigationSelector';

interface LiveTasksPanelProps {
  className?: string;
  limit?: number;
  showPicker?: boolean; // allow parent to hide picker if rendering elsewhere
}

interface LiveTaskEntry {
  id: string;
  name: string;
  status: TaskStatus | string;
  progress: number;
  started_at?: string;
  completed_at?: string;
  updated_at: string;
  raw?: any;
}

const statusColors: Record<string, string> = {
  pending: 'bg-gray-200 text-gray-800',
  running: 'bg-blue-100 text-blue-800',
  completed: 'bg-green-100 text-green-800',
  failed: 'bg-red-100 text-red-800',
  skipped: 'bg-yellow-100 text-yellow-800',
  retry: 'bg-purple-100 text-purple-800'
};

export const LiveTasksPanel: React.FC<LiveTasksPanelProps> = ({ className = '', limit = 50, showPicker = true }) => {
  const { lastMessage } = useWebSocketContext();
  const { selectedId } = useSelectedInvestigation();
  const [tasks, setTasks] = useState<Record<string, LiveTaskEntry>>({});
  const [initialLoaded, setInitialLoaded] = useState(false);

  // Load initial tasks when investigationId changes
  useEffect(() => {
    if (!selectedId) return;
    let cancelled = false;
    (async () => {
      try {
        const inv = await investigationApi.getInvestigation(selectedId);
        if (cancelled) return;
        const mapped: Record<string, LiveTaskEntry> = {};
        Object.values(inv.tasks || {}).forEach((t: any) => {
          mapped[t.id] = {
            id: t.id,
            name: t.name || t.task_type,
            status: t.status,
            progress: t.progress ?? 0,
            started_at: t.started_at,
            completed_at: t.completed_at,
            updated_at: t.completed_at || t.started_at || t.created_at,
            raw: t
          };
        });
        setTasks(mapped);
        setInitialLoaded(true);
      } catch (e) {
        console.warn('Failed to load initial tasks', e);
      }
    })();
    return () => { cancelled = true; };
  }, [selectedId]);

  // Process incoming websocket messages
  useEffect(() => {
  if (!lastMessage || !selectedId) return;
    const msg = lastMessage; // already parsed in context
  if (msg.investigation_id !== selectedId) return;

    if (msg.type === 'task_update' || msg.type === 'task_completed' || msg.type === 'task_failed') {
      const t = msg.data?.task || msg.data; // flexible shape
      if (t?.id) {
        setTasks(prev => ({
          ...prev,
            [t.id]: {
              id: t.id,
              name: t.name || t.task_type,
              status: t.status,
              progress: t.progress ?? 0,
              started_at: t.started_at || prev[t.id]?.started_at,
              completed_at: t.completed_at || prev[t.id]?.completed_at,
              updated_at: new Date().toISOString(),
              raw: t
            }
        }));
      }
    } else if (msg.type === 'investigation_update') {
      // Potential bulk refresh if tasks included
      if (msg.data?.tasks) {
        const newEntries: Record<string, LiveTaskEntry> = { ...tasks };
        Object.values(msg.data.tasks).forEach((t: any) => {
          newEntries[t.id] = {
            id: t.id,
            name: t.name || t.task_type,
            status: t.status,
            progress: t.progress ?? 0,
            started_at: t.started_at || newEntries[t.id]?.started_at,
            completed_at: t.completed_at || newEntries[t.id]?.completed_at,
            updated_at: new Date().toISOString(),
            raw: t
          };
        });
        setTasks(newEntries);
      }
    }
  }, [lastMessage, selectedId, tasks]);

  const ordered = useMemo(() => {
    return Object.values(tasks)
      .sort((a, b) => (b.updated_at.localeCompare(a.updated_at)))
      .slice(0, limit);
  }, [tasks, limit]);

  return (
    <div className={`bg-white rounded-lg shadow flex flex-col ${className}`}>      
      <div className="px-4 py-3 border-b flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 flex-1 min-w-0">
          <h3 className="text-sm font-semibold text-gray-800 truncate">Live Tasks</h3>
          {showPicker && <InvestigationSelector />}
        </div>
        <span className="text-xs text-gray-500 whitespace-nowrap">{ordered.length} shown</span>
      </div>
      <div className="flex-1 overflow-y-auto max-h-96 divide-y">
        {ordered.length === 0 && initialLoaded && selectedId && (
          <div className="p-4 text-sm text-gray-500 flex items-center justify-between">
            <span>No tasks yet</span>
            <button
              onClick={async () => {
                try {
                  await investigationApi.seedDemoTasks(selectedId);
                  // re-fetch tasks
                  const inv = await investigationApi.getInvestigation(selectedId);
                  const mapped: Record<string, LiveTaskEntry> = {};
                  Object.values(inv.tasks || {}).forEach((t: any) => {
                    mapped[t.id] = {
                      id: t.id,
                      name: t.name || t.task_type,
                      status: t.status,
                      progress: t.progress ?? 0,
                      started_at: t.started_at,
                      completed_at: t.completed_at,
                      updated_at: t.completed_at || t.started_at || t.created_at,
                      raw: t
                    };
                  });
                  setTasks(mapped);
                } catch (e) {
                  console.warn('Seeding demo tasks failed', e);
                }
              }}
              className="text-xs px-2 py-1 bg-blue-600 text-white rounded hover:bg-blue-700"
            >Seed Demo Tasks</button>
          </div>
        )}
        {!selectedId && (
          <div className="p-4 text-sm text-gray-500">Select an investigation to view tasks.</div>
        )}
        <AnimatePresence initial={false}>
          {ordered.map(task => (
            <motion.div
              key={task.id}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.15 }}
              className="p-3 text-sm hover:bg-gray-50"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="font-medium text-gray-800 truncate">{task.name}</div>
                  <div className="text-xs text-gray-500 space-x-2 mt-0.5">
                    {task.started_at && <span>Started: {new Date(task.started_at).toLocaleTimeString()}</span>}
                    {task.completed_at && <span>Done: {new Date(task.completed_at).toLocaleTimeString()}</span>}
                  </div>
                  {task.raw?.error && (
                    <div className="text-xs text-red-600 mt-1 truncate">Err: {task.raw.error}</div>
                  )}
                </div>
                <div className="flex flex-col items-end ml-3">
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${statusColors[task.status] || 'bg-gray-100 text-gray-700'}`}>{task.status}</span>
                  <div className="mt-1 h-2 w-20 bg-gray-100 rounded overflow-hidden">
                    <div
                      className="h-full bg-blue-500"
                      style={{ width: `${Math.min(100, Math.max(0, task.progress))}%` }}
                    />
                  </div>
                </div>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
};

export default LiveTasksPanel;

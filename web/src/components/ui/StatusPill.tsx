import React from 'react';
import { clsx } from 'clsx';

interface StatusPillProps {
  status: 'ok' | 'warn' | 'error' | 'unknown';
  label: string;
  pulse?: boolean;
}

const colorMap: Record<StatusPillProps['status'], string> = {
  ok: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30',
  warn: 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/30',
  error: 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/30',
  unknown: 'bg-slate-400/15 text-slate-600 dark:text-slate-300 border border-slate-400/30'
};

export const StatusPill: React.FC<StatusPillProps> = ({ status, label, pulse }) => (
  <div
    className={clsx(
      'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium tracking-wide backdrop-blur-sm',
      'shadow-sm select-none',
      colorMap[status]
    )}
  >
    {pulse && <span className={clsx('w-1.5 h-1.5 rounded-full bg-current', 'animate-ping-short')} />}
    <span>{label}</span>
  </div>
);

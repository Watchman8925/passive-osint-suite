import React from 'react';
import { clsx } from 'clsx';

interface MetricTileProps {
  label: string;
  value: React.ReactNode;
  icon?: React.ReactNode;
  accent?: 'default' | 'emerald' | 'rose' | 'blue' | 'amber';
}

const accentClasses: Record<NonNullable<MetricTileProps['accent']>, string> = {
  default: 'text-slate-600 dark:text-slate-300',
  emerald: 'text-emerald-600 dark:text-emerald-400',
  rose: 'text-rose-600 dark:text-rose-400',
  blue: 'text-blue-600 dark:text-blue-400',
  amber: 'text-amber-600 dark:text-amber-400'
};

export const MetricTile: React.FC<MetricTileProps> = ({ label, value, icon, accent = 'default' }) => {
  return (
    <div className="p-5 rounded-xl border border-black/5 dark:border-white/10 bg-white/70 dark:bg-slate-800/60 backdrop-blur-sm shadow-sm hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</p>
          <div className={clsx('mt-1 text-3xl font-semibold', accentClasses[accent])}>{value}</div>
        </div>
        {icon && <div className="opacity-70">{icon}</div>}
      </div>
    </div>
  );
};

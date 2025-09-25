import React from 'react';
import { clsx } from 'clsx';

interface SkeletonProps {
  className?: string;
  lines?: number;
}

export const Skeleton: React.FC<SkeletonProps> = ({ className = '', lines = 1 }) => {
  if (lines <= 1) {
    return <div className={clsx('animate-pulse rounded bg-slate-200 dark:bg-slate-700 h-4', className)} />;
  }
  return (
    <div className={clsx('space-y-2', className)}>
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} className="animate-pulse rounded bg-slate-200 dark:bg-slate-700 h-4 w-full" />
      ))}
    </div>
  );
};

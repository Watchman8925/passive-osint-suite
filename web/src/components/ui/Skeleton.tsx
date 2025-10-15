import React from 'react';
import { clsx } from 'clsx';

interface SkeletonProps {
  className?: string;
  lines?: number;
  rounded?: 'sm' | 'md' | 'lg' | 'xl' | 'full';
}

const radius = {
  sm: 'rounded-sm',
  md: 'rounded-md',
  lg: 'rounded-lg',
  xl: 'rounded-xl',
  full: 'rounded-full',
};

export const Skeleton: React.FC<SkeletonProps> = ({ className = '', lines = 1, rounded = 'md' }) => {
  if (lines <= 1) {
    return (
      <div className={clsx('relative overflow-hidden bg-[rgba(255,77,0,0.08)] border border-[rgba(255,77,0,0.15)] h-4', radius[rounded], className)}>
        <div className="absolute inset-0 -translate-x-full animate-[shimmer_1.6s_infinite] bg-gradient-to-r from-transparent via-[rgba(255,77,0,0.15)] to-transparent" />
      </div>
    );
  }
  return (
    <div className={clsx('space-y-2', className)}>
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} className={clsx('relative overflow-hidden bg-[rgba(255,77,0,0.08)] border border-[rgba(255,77,0,0.15)] h-4', radius[rounded])}>
          <div className="absolute inset-0 -translate-x-full animate-[shimmer_1.6s_infinite] bg-gradient-to-r from-transparent via-[rgba(255,77,0,0.15)] to-transparent" />
        </div>
      ))}
      <style>{`
        @keyframes shimmer { 
          100% { transform: translateX(100%); }
        }
      `}</style>
    </div>
  );
};

import React from 'react';
import { clsx } from 'clsx';

interface CardProps {
  title?: string;
  actions?: React.ReactNode;
  children?: React.ReactNode;
  className?: string;
  padded?: boolean;
}

export const Card: React.FC<CardProps> = ({ title, actions, children, className = '', padded = true }) => {
  return (
    <div
      className={clsx(
        'rounded-xl border border-black/5 dark:border-white/10 shadow-sm bg-white/70 dark:bg-slate-800/60 backdrop-blur-sm transition-colors',
        'hover:shadow-md hover:border-black/10 dark:hover:border-white/20',
        className
      )}
    >
      {(title || actions) && (
        <div className="flex items-center justify-between px-4 py-3 border-b border-black/5 dark:border-white/10">
          {title && <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{title}</h3>}
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </div>
      )}
      <div className={padded ? 'p-4' : ''}>{children}</div>
    </div>
  );
};

import React from 'react';
import { clsx } from 'clsx';

type CardElevation = 'flat' | 'base' | 'hover' | 'modal';

interface CardProps {
  title?: string;
  actions?: React.ReactNode;
  children?: React.ReactNode;
  className?: string;
  padded?: boolean;
  elevation?: CardElevation;
  interactive?: boolean;
}

const elevationStyles: Record<CardElevation, string> = {
  flat: 'shadow-none',
  base: 'shadow-[0_8px_24px_rgba(0,0,0,0.6),0_0_18px_rgba(255,77,0,0.08)]',
  hover: 'shadow-[0_12px_40px_rgba(0,0,0,0.7),0_0_24px_rgba(255,77,0,0.15)]',
  modal: 'shadow-[0_20px_60px_rgba(0,0,0,0.85),0_0_40px_rgba(255,77,0,0.2)]'
};

export const Card: React.FC<CardProps> = ({ 
  title, 
  actions, 
  children, 
  className = '', 
  padded = true,
  elevation = 'base',
  interactive = false
}) => {
  return (
    <div
      className={clsx(
        'rounded-xl border backdrop-blur-sm transition-all duration-200 ease-out',
        'bg-white/70 dark:bg-slate-800/60 border-black/5 dark:border-white/10',
        elevationStyles[elevation],
        interactive && 'hover:scale-[1.01] hover:-translate-y-[1px] cursor-pointer',
        interactive && 'hover:shadow-[0_12px_40px_rgba(0,0,0,0.5),0_0_24px_rgba(255,77,0,0.15)]',
        interactive && 'hover:border-[rgba(255,77,0,0.3)]',
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

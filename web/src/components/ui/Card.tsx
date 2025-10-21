import React from 'react';
import { clsx } from 'clsx';
import { colors } from '../../design/tokens';

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

const hoverShadow = colors.shadow.hover;

export const Card: React.FC<CardProps> = ({
  title,
  actions,
  children,
  className = '',
  padded = true,
  elevation = 'base',
  interactive = false
}) => {
  const surfaceStyle: React.CSSProperties & { '--hover-shadow'?: string } = {
    boxShadow: colors.shadow[elevation]
  };

  if (interactive) {
    surfaceStyle['--hover-shadow'] = hoverShadow;
  }

  return (
    <div
      className={clsx(
        'glass rounded-2xl border backdrop-blur-xl transition-all duration-200 ease-out',
        'bg-[var(--glass-surface)] border-[var(--glass-border)] text-[var(--text-primary)]',
        interactive && 'hover:-translate-y-[2px] cursor-pointer hover:shadow-[var(--hover-shadow)]',
        interactive && 'hover:bg-[var(--glass-hover)]',
        className
      )}
      style={surfaceStyle}
    >
      {(title || actions) && (
        <div className="flex items-center justify-between px-4 py-3 border-b border-[color:var(--glass-border)]/70">
          {title && <h3 className="text-sm font-semibold text-[var(--text-secondary)]">{title}</h3>}
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </div>
      )}
      <div className={padded ? 'p-4' : ''}>{children}</div>
    </div>
  );
};

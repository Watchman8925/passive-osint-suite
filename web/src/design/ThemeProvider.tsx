import React, { createContext, useContext, useEffect, useState } from 'react';
import { colors, spacing, typography } from './tokens';

interface ThemeContextValue {
  mode: 'light' | 'dark';
  toggle: () => void;
  tokens: typeof colors & { spacing: typeof spacing; typography: typeof typography };
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export const useTheme = () => {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useTheme must be used within ThemeProvider');
  return ctx;
};

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [mode, setMode] = useState<'light' | 'dark'>(() => {
    if (typeof window !== 'undefined') {
      const stored = window.localStorage.getItem('osint-theme');
      if (stored === 'light' || stored === 'dark') return stored;
    }
    return 'dark';
  });

  useEffect(() => {
    const root = document.documentElement;
    const palette = mode === 'light'
      ? {
          '--bg-base': '#f8fafc',
          '--bg-subtle': 'rgba(248, 250, 252, 0.92)',
          '--bg-muted': 'rgba(226, 232, 240, 0.85)',
          '--bg-gradient': 'linear-gradient(135deg, #e0f2fe 0%, #e6fffa 100%)',
          '--text-primary': '#020617',
          '--text-secondary': '#1e293b',
          '--text-muted': '#475569',
          '--text-inverse': '#f8fafc',
          '--glass-surface': 'rgba(255, 255, 255, 0.65)',
          '--glass-elevated': 'rgba(255, 255, 255, 0.8)',
          '--glass-hover': 'rgba(255, 255, 255, 0.9)',
          '--glass-border': 'rgba(15, 23, 42, 0.1)',
          '--glass-highlight': 'rgba(148, 163, 184, 0.25)',
          '--accent-blue': '#2563eb',
          '--accent-seafoam': '#0ea5e9',
          '--accent-silver': '#94a3b8',
          '--accent-gold': '#f59e0b',
          '--accent-magenta': '#db2777',
          '--status-success': '#16a34a',
          '--status-warning': '#d97706',
          '--status-danger': '#dc2626',
          '--status-info': '#0ea5e9'
        }
      : {
          '--bg-base': colors.background.base,
          '--bg-subtle': colors.background.subtle,
          '--bg-muted': colors.background.muted,
          '--bg-gradient': colors.background.gradient,
          '--text-primary': colors.text.primary,
          '--text-secondary': colors.text.secondary,
          '--text-muted': colors.text.muted,
          '--text-inverse': colors.text.inverse,
          '--glass-surface': colors.glass.surface,
          '--glass-elevated': colors.glass.elevated,
          '--glass-hover': colors.glass.hover,
          '--glass-border': colors.glass.border,
          '--glass-highlight': colors.glass.highlight,
          '--accent-blue': colors.accent.blue,
          '--accent-seafoam': colors.accent.seafoam,
          '--accent-silver': colors.accent.silver,
          '--accent-gold': colors.accent.gold,
          '--accent-magenta': colors.accent.magenta,
          '--status-success': colors.status.success,
          '--status-warning': colors.status.warning,
          '--status-danger': colors.status.danger,
          '--status-info': colors.status.info
        };

    Object.entries(palette).forEach(([key, value]) => {
      root.style.setProperty(key, value);
    });
    root.dataset.theme = mode;
    try {
      window.localStorage.setItem('osint-theme', mode);
    } catch {}
  }, [mode]);

  const value: ThemeContextValue = {
    mode,
    toggle: () => setMode(m => (m === 'light' ? 'dark' : 'light')),
    tokens: { ...colors, spacing, typography }
  };

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
};

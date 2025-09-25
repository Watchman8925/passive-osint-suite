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
    return 'light';
  });

  useEffect(() => {
    const root = document.documentElement;
    root.style.setProperty('--bg-base', mode === 'light' ? '#ffffff' : '#0f172a');
    root.style.setProperty('--bg-subtle', mode === 'light' ? '#f5f7fa' : '#1e293b');
    root.style.setProperty('--bg-muted', mode === 'light' ? '#eef2f6' : '#334155');
    root.style.setProperty('--text-primary', mode === 'light' ? '#0f172a' : '#f1f5f9');
    root.style.setProperty('--text-secondary', mode === 'light' ? '#334155' : '#cbd5e1');
    root.style.setProperty('--text-muted', mode === 'light' ? '#64748b' : '#94a3b8');
    root.style.setProperty('--surface-elevated', mode === 'light' ? 'rgba(255,255,255,0.7)' : 'rgba(30,41,59,0.7)');
    root.style.setProperty('--surface-hover', mode === 'light' ? 'rgba(255,255,255,0.85)' : 'rgba(30,41,59,0.9)');
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

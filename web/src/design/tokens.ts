// Central design tokens (source of truth)
// These tokens can later be exported to CSS variables via a build step if desired.

export const colors = {
  background: {
    base: '#ffffff',
    subtle: '#f5f7fa',
    muted: '#eef2f6',
    accent: 'linear-gradient(to right, #7e22ce, #2563eb)'
  },
  surface: {
    base: '#ffffff',
    elevated: 'rgba(255,255,255,0.7)',
    hover: 'rgba(255,255,255,0.85)',
    border: 'rgba(0,0,0,0.08)'
  },
  text: {
    primary: '#0f172a',
    secondary: '#334155',
    muted: '#64748b',
    inverse: '#ffffff'
  },
  brand: {
    purple: '#7e22ce',
    blue: '#2563eb',
    gradientFrom: '#7e22ce',
    gradientTo: '#2563eb'
  },
  status: {
    success: '#10b981',
    warning: '#f59e0b',
    danger: '#ef4444',
    info: '#3b82f6'
  },
  borderRadius: {
    xs: '3px',
    sm: '6px',
    md: '10px',
    lg: '16px',
    xl: '24px'
  },
  shadow: {
    sm: '0 1px 2px rgba(0,0,0,0.08)',
    md: '0 4px 12px -2px rgba(0,0,0,0.12)',
    lg: '0 8px 28px -6px rgba(0,0,0,0.18)'
  }
};

export const spacing = {
  xs: 4,
  sm: 8,
  md: 12,
  lg: 20,
  xl: 32
};

export const typography = {
  fontFamily: "'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen",
  sizes: {
    xs: '11px',
    sm: '13px',
    md: '15px',
    lg: '17px',
    xl: '21px'
  },
  weights: {
    regular: 400,
    medium: 500,
    semibold: 600,
    bold: 700
  }
};

export type ThemeTokens = typeof colors & typeof spacing & typeof typography;

// Central design tokens (source of truth)
// These tokens can later be exported to CSS variables via a build step if desired.

export const colors = {
  background: {
    base: '#020617',
    subtle: 'rgba(2, 6, 23, 0.92)',
    muted: 'rgba(8, 15, 40, 0.78)',
    gradient: 'linear-gradient(135deg, #010409 0%, #031633 45%, #020617 100%)'
  },
  glass: {
    surface: 'rgba(15, 23, 42, 0.68)',
    elevated: 'rgba(15, 23, 42, 0.8)',
    hover: 'rgba(24, 35, 65, 0.88)',
    border: 'rgba(148, 163, 184, 0.4)',
    highlight: 'rgba(255, 255, 255, 0.16)'
  },
  text: {
    primary: '#f8fafc',
    secondary: '#cbd5f5',
    muted: '#94a3b8',
    inverse: '#f8fafc'
  },
  accent: {
    blue: '#38bdf8',
    seafoam: '#2dd4bf',
    silver: '#d1d5db',
    gold: '#facc15',
    magenta: '#f472b6'
  },
  status: {
    success: '#34d399',
    warning: '#fbbf24',
    danger: '#f87171',
    info: '#38bdf8'
  },
  borderRadius: {
    xs: '4px',
    sm: '8px',
    md: '14px',
    lg: '20px',
    xl: '28px'
  },
  shadow: {
    flat: 'none',
    base: '0 18px 38px -20px rgba(8, 47, 73, 0.85), 0 0 40px -24px rgba(45, 212, 191, 0.45)',
    hover: '0 24px 50px -20px rgba(2, 132, 199, 0.7), 0 0 60px -30px rgba(250, 204, 21, 0.55)',
    modal: '0 40px 90px -30px rgba(15, 23, 42, 0.95)'
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

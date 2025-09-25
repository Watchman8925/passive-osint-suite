# OSINT Suite Design System (Foundations)

This document describes the emerging in-repo design system that unifies styling across the VS Code-embedded dashboard.

## Goals
- Consistent spacing, color, elevation, motion
- Light/Dark toggle capability (progressive)
- Reusable primitives (Card, StatusPill, Skeleton, Button, Badge, etc.)
- Minimize ad-hoc Tailwind class duplication

## Tokens
Defined in `src/design/tokens.ts` (not yet auto-exported to Tailwind config). Categories:
- Colors: background, surface, text, brand, status
- Radii: xs → xl for consistent rounding
- Shadows: sm / md / lg
- Spacing: numeric scale (xs..xl)
- Typography: base families, sizes, weights

## Theme Provider
`ThemeProvider` sets CSS variables for a subset of tokens and provides a `toggle()` to switch modes. Dark mode tokens are applied via runtime variable overrides (no build-time split needed yet).

Usage example:
```tsx
import { useTheme } from '@/design/ThemeProvider';
const { mode, toggle } = useTheme();
```

## Primitives
| Component | File | Purpose |
|-----------|------|---------|
| Card | `components/ui/Card.tsx` | Elevated surface wrapper with optional header/actions |
| StatusPill | `components/ui/StatusPill.tsx` | Uniform status labeling (ok/warn/error/unknown) |
| Skeleton | `components/ui/Skeleton.tsx` | Loading placeholder lines/blocks |

## Roadmap
1. Replace inline gradient/stat blocks in dashboard with `<Card>` usage.
2. Convert backend/Tor ribbon injection to native React status bar using `StatusPill` + live polling hook.
3. Abstract animation timings & easing constants.
4. Introduce `DataTable` and `MetricTile` primitives for reusable analytics visuals.
5. Provide story-based visual regression test harness (future: Chromatic / Storybook optional).

## Migration Guidelines
- New feature surfaces should compose primitives first; only add bespoke styling when layout demands it.
- Avoid re-encoding brand gradients; use tokens.
- When adding new semantic colors (e.g., "neutral", "info-soft"), extend tokens before usage.

## Contributing
1. Add token to `tokens.ts`.
2. If dynamic (themeable), map it inside `ThemeProvider` to a CSS variable.
3. Build or extend a primitive under `components/ui/`.
4. Update this document if it changes semantic guidance.

---
This is an incremental system; expect iterative refinement rather than a one-off finalization.

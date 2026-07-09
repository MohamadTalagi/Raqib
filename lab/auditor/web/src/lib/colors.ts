// Mirrors the CSS custom properties in index.css @theme.
// Kept as literal hex here because SVG chart libraries (recharts) need
// resolvable color values rather than CSS custom properties in some contexts.
export const CHART_COLORS = {
  brand: "#f2a93b",
  critical: "#ef4444",
  high: "#f2733c",
  medium: "#f2a93b",
  low: "#38bdf8",
  pass: "#34d399",
  inconclusive: "#8b93a1",
  border: "#262a31",
  textMuted: "#6d7480",
  textSecondary: "#a7adb8",
  surfaceRaised: "#1a1d22",
} as const;

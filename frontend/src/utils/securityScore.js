/**
 * Client-side security score placeholder.
 * TODO: Backend should calculate and return this value instead.
 * Formula: start 100, subtract critical -15, high -8, medium -3, low -1, floor at 0.
 */
export function computeSecurityScore({
  critical = 0,
  high = 0,
  medium = 0,
  low = 0,
} = {}) {
  return Math.max(
    0,
    100 - (critical * 15 + high * 8 + medium * 3 + low * 1)
  );
}

export function scoreRingColor(score) {
  if (score > 80) return 'var(--signal-green)';
  if (score >= 50) return 'var(--sev-high)';
  return 'var(--sev-critical)';
}

export function scoreStatus(score) {
  if (score > 80) return 'green';
  if (score >= 50) return 'amber';
  return 'red';
}

/** Map severity label to a numeric rank for "worst wins" comparisons. */
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function worstSeverity(severities = []) {
  let best = null;
  let rank = -1;
  for (const s of severities) {
    const key = String(s || '').toLowerCase();
    const r = SEV_RANK[key] ?? -1;
    if (r > rank) {
      rank = r;
      best = key;
    }
  }
  return best;
}

export function severityColor(sev) {
  switch (String(sev || '').toLowerCase()) {
    case 'critical':
      return 'var(--sev-critical)';
    case 'high':
      return 'var(--sev-high)';
    case 'medium':
      return 'var(--sev-medium)';
    case 'low':
      return 'var(--sev-low)';
    default:
      return 'var(--signal-green)';
  }
}

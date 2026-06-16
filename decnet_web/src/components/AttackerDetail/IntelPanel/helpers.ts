// SPDX-License-Identifier: AGPL-3.0-or-later
export const VERDICT_TONE: Record<string, { color: string; label: string }> = {
  malicious: { color: 'var(--alert)', label: 'MALICIOUS' },
  suspicious: { color: 'var(--warn)', label: 'SUSPICIOUS' },
  benign: { color: 'var(--ok)', label: 'BENIGN' },
  unknown: { color: 'var(--fg-4)', label: 'NO SIGNAL' },
};

export const fmtTs = (iso?: string | null): string => {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
};

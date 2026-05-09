import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

describe('devGate.isDeveloperMode', () => {
  const originalEnv = { ...import.meta.env };

  beforeEach(() => {
    vi.resetModules();
  });

  afterEach(() => {
    // Restore the env keys we touched so other tests aren't perturbed.
    (import.meta.env as Record<string, unknown>).VITE_DECNET_DEVELOPER =
      originalEnv.VITE_DECNET_DEVELOPER;
  });

  it('returns true when VITE_DECNET_DEVELOPER === "1"', async () => {
    (import.meta.env as Record<string, unknown>).VITE_DECNET_DEVELOPER = '1';
    const { isDeveloperMode } = await import('../devGate');
    expect(isDeveloperMode()).toBe(true);
  });

  it('returns false when VITE_DECNET_DEVELOPER is undefined', async () => {
    delete (import.meta.env as Record<string, unknown>).VITE_DECNET_DEVELOPER;
    const { isDeveloperMode } = await import('../devGate');
    expect(isDeveloperMode()).toBe(false);
  });

  it('returns false for any value other than "1"', async () => {
    for (const v of ['0', 'true', '', 'yes']) {
      (import.meta.env as Record<string, unknown>).VITE_DECNET_DEVELOPER = v;
      vi.resetModules();
      const { isDeveloperMode } = await import('../devGate');
      expect(isDeveloperMode()).toBe(false);
    }
  });
});

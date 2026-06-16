// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ArtifactsPanel } from './ArtifactsPanel';
import type { ArtifactLog } from '../types';

// ArtifactDrawer fetches over the network; render a simple placeholder
// so we can assert "the drawer opened" without standing up MSW handlers.
vi.mock('../../ArtifactDrawer', () => ({
  default: ({ storedAs, onClose }: { storedAs: string; onClose: () => void }) => (
    <div data-testid="artifact-drawer">
      drawer for {storedAs}
      <button onClick={onClose}>close</button>
    </div>
  ),
}));

const fields = (extra: Record<string, unknown> = {}) =>
  JSON.stringify({
    stored_as: '/var/captures/abc.bin',
    sha256: 'a'.repeat(64),
    size: 1024,
    orig_path: '/etc/passwd',
    ...extra,
  });

const row = (overrides: Partial<ArtifactLog> = {}): ArtifactLog => ({
  id: 1,
  timestamp: '2026-05-09T11:00:00Z',
  decky: 'decoy-01',
  service: 'ssh',
  fields: fields(),
  ...overrides,
});

describe('ArtifactsPanel', () => {
  it('renders one row per artifact with parsed filename + truncated sha', () => {
    render(
      <ArtifactsPanel
        artifacts={[row()]}
        open={true}
        onToggle={() => {}}
      />,
    );
    expect(screen.getByText('decoy-01')).toBeInTheDocument();
    expect(screen.getByText('/etc/passwd')).toBeInTheDocument();
    expect(screen.getByText(/aaaaaaaaaaaa…/)).toBeInTheDocument();
    expect(screen.getByText(/^OPEN$/)).toBeInTheDocument();
  });

  it('shows the empty-state when artifacts is []', () => {
    render(
      <ArtifactsPanel artifacts={[]} open={true} onToggle={() => {}} />,
    );
    expect(screen.getByText('NO ARTIFACTS CAPTURED')).toBeInTheDocument();
  });

  it('omits the OPEN button when stored_as is absent', () => {
    render(
      <ArtifactsPanel
        artifacts={[row({ fields: JSON.stringify({ orig_path: '/x' }) })]}
        open={true}
        onToggle={() => {}}
      />,
    );
    expect(screen.queryByText(/^OPEN$/)).not.toBeInTheDocument();
  });

  it('opens the drawer on OPEN click and closes on the drawer close', async () => {
    const user = userEvent.setup();
    render(
      <ArtifactsPanel
        artifacts={[row()]}
        open={true}
        onToggle={() => {}}
      />,
    );
    expect(screen.queryByTestId('artifact-drawer')).not.toBeInTheDocument();

    await user.click(screen.getByText(/^OPEN$/));
    expect(screen.getByTestId('artifact-drawer')).toBeInTheDocument();

    await user.click(screen.getByText('close'));
    expect(screen.queryByTestId('artifact-drawer')).not.toBeInTheDocument();
  });
});

// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, type Mock } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DeployWizard } from './DeployWizard';
import api from '../../utils/api';
import type { Archetype } from './types';

vi.mock('../../utils/api', () => ({
  default: { post: vi.fn(), get: vi.fn() },
}));

// ServiceConfigFields fetches the per-service schema; replace with a stub
// so the wizard tests don't need MSW handlers for that side-channel.
vi.mock('../ServiceConfigFields', async () => {
  const actual = await vi.importActual<object>('../ServiceConfigFields');
  return {
    ...actual,
    default: () => null,
  };
});

const archetypes: Archetype[] = [
  { slug: 'web-server', name: 'Web Server', services: ['http', 'https'], icon: 'globe' },
  { slug: 'database', name: 'Database', services: ['postgres'], icon: 'database' },
];

describe('DeployWizard', () => {
  it('renders nothing meaningful when closed', () => {
    render(
      <DeployWizard
        open={false}
        onClose={() => {}}
        onComplete={() => {}}
        archetypes={archetypes}
        fleetSize={0}
      />,
    );
    expect(screen.queryByText('DEPLOY NEW DECKIES')).not.toBeInTheDocument();
  });

  it('opens at step 0 with archetype list rendered', () => {
    render(
      <DeployWizard
        open
        onClose={() => {}}
        onComplete={() => {}}
        archetypes={archetypes}
        fleetSize={0}
      />,
    );
    expect(screen.getByText('DEPLOY NEW DECKIES')).toBeInTheDocument();
    expect(screen.getByText('Web Server')).toBeInTheDocument();
    expect(screen.getByText('Database')).toBeInTheDocument();
  });

  it('disables NEXT until an archetype is selected', async () => {
    const user = userEvent.setup();
    render(
      <DeployWizard
        open
        onClose={() => {}}
        onComplete={() => {}}
        archetypes={archetypes}
        fleetSize={0}
      />,
    );
    const nextBtn = screen.getByText('NEXT →') as HTMLButtonElement;
    expect(nextBtn.disabled).toBe(true);

    await user.click(screen.getByText('Web Server'));
    expect(nextBtn.disabled).toBe(false);
  });

  it('CANCEL button invokes onClose', async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    render(
      <DeployWizard
        open
        onClose={onClose}
        onComplete={() => {}}
        archetypes={archetypes}
        fleetSize={0}
      />,
    );
    await user.click(screen.getByText('CANCEL'));
    expect(onClose).toHaveBeenCalled();
  });

  it('fires onComplete exactly once after a successful deploy, even across re-renders', async () => {
    // Regression: onComplete is an inline arrow in the parent (new ref every
    // render) and it triggers a parent refresh -> re-render. Without the
    // completedRef guard the auto-close effect re-ran on every re-render and
    // rescheduled onComplete forever (runaway /deckies + toast loop).
    (api.post as Mock).mockResolvedValue({
      data: { lifecycle_ids: ['lc-1'], message: 'ok', mode: 'unihost' },
    });
    (api.get as Mock).mockResolvedValue({
      data: { rows: [{
        id: 'lc-1', decky_name: 'qa-01', host_uuid: null, operation: 'deploy',
        status: 'succeeded', error: null,
        started_at: '2026-01-01T00:00:00', updated_at: '2026-01-01T00:00:00',
        completed_at: '2026-01-01T00:00:00',
      }] },
    });

    const onComplete = vi.fn();
    const user = userEvent.setup();
    const props = { open: true, onClose: () => {}, archetypes, fleetSize: 0 };
    // Fresh arrow each render mirrors the parent's unstable onComplete ref.
    const { rerender } = render(
      <DeployWizard {...props} onComplete={() => onComplete()} />,
    );

    await user.click(screen.getByText('Web Server'));
    await user.click(screen.getByText('NEXT →'));
    await user.click(screen.getByText('NEXT →'));
    await user.click(screen.getByText('NEXT →'));
    await user.click(screen.getByText('ESTABLISH FLEET'));

    await waitFor(() => expect(onComplete).toHaveBeenCalledTimes(1), { timeout: 3000 });

    // Simulate the parent re-render storm with fresh onComplete refs.
    for (let i = 0; i < 5; i++) {
      rerender(<DeployWizard {...props} onComplete={() => onComplete()} />);
    }
    await new Promise((r) => setTimeout(r, 1200));
    expect(onComplete).toHaveBeenCalledTimes(1);
  });

  it('still closes when re-renders land during the 700ms close countdown', async () => {
    // Regression: the close timer must survive re-renders inside its window.
    // A naive completedRef guard whose effect cleanup cleared the timer would
    // cancel the pending onComplete on the first in-window re-render and the
    // wizard would never close. The timer lives in a ref to prevent that.
    (api.post as Mock).mockResolvedValue({
      data: { lifecycle_ids: ['lc-1'], message: 'ok', mode: 'unihost' },
    });
    (api.get as Mock).mockResolvedValue({
      data: { rows: [{
        id: 'lc-1', decky_name: 'qa-01', host_uuid: null, operation: 'deploy',
        status: 'succeeded', error: null,
        started_at: '2026-01-01T00:00:00', updated_at: '2026-01-01T00:00:00',
        completed_at: '2026-01-01T00:00:00',
      }] },
    });

    const onComplete = vi.fn();
    const user = userEvent.setup();
    const props = { open: true, onClose: () => {}, archetypes, fleetSize: 0 };
    const { rerender } = render(
      <DeployWizard {...props} onComplete={() => onComplete()} />,
    );

    await user.click(screen.getByText('Web Server'));
    await user.click(screen.getByText('NEXT →'));
    await user.click(screen.getByText('NEXT →'));
    await user.click(screen.getByText('NEXT →'));
    await user.click(screen.getByText('ESTABLISH FLEET'));

    // Hammer fresh-onComplete re-renders across the close countdown window.
    for (let i = 0; i < 8; i++) {
      rerender(<DeployWizard {...props} onComplete={() => onComplete()} />);
      await new Promise((r) => setTimeout(r, 40));
    }

    // The close must still fire exactly once despite the in-window churn.
    await waitFor(() => expect(onComplete).toHaveBeenCalledTimes(1), { timeout: 3000 });
  });
});

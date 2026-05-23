// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DeployWizard } from './DeployWizard';
import type { Archetype } from './types';

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
});

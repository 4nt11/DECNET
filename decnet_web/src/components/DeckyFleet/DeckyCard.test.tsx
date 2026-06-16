// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DeckyCard } from './DeckyCard';
import { makeDecky } from '../../test/fixtures';

// AddServiceConfigModal hits the network for schema; ServiceConfigForm
// also fetches. Both are unrelated to what DeckyCard's own tests cover.
vi.mock('../AddServiceConfigModal', () => ({
  default: () => null,
}));
vi.mock('../ServiceConfigForm', () => ({
  default: () => null,
}));

const baseProps = {
  mutating: false,
  isAdmin: false,
  armed: null,
  tdBusy: false,
  onForce: () => {},
  onTeardown: () => {},
  onIntervalChange: () => {},
  onInspect: () => {},
  availableServices: [],
  onServicesChanged: () => {},
  onTarpitResult: () => {},
};

describe('DeckyCard', () => {
  it('renders the decky name + IP and the rendered service tags', () => {
    render(
      <DeckyCard
        {...baseProps}
        decky={makeDecky({ name: 'decoy-99', ip: '10.0.0.99', services: ['ssh', 'http'] })}
      />,
    );
    expect(screen.getByText('decoy-99')).toBeInTheDocument();
    expect(screen.getByText('10.0.0.99')).toBeInTheDocument();
    expect(screen.getByText('ssh')).toBeInTheDocument();
    expect(screen.getByText('http')).toBeInTheDocument();
  });

  it('renders FORCE MUTATE only for admins on non-swarm deckies', () => {
    const { rerender } = render(
      <DeckyCard {...baseProps} decky={makeDecky()} />,
    );
    expect(screen.queryByText(/FORCE MUTATE/)).not.toBeInTheDocument();

    rerender(
      <DeckyCard {...baseProps} isAdmin decky={makeDecky()} />,
    );
    expect(screen.getByText('FORCE MUTATE')).toBeInTheDocument();
  });

  it('FORCE MUTATE click invokes onForce with the decky name', async () => {
    const onForce = vi.fn();
    const user = userEvent.setup();
    render(
      <DeckyCard
        {...baseProps}
        isAdmin
        onForce={onForce}
        decky={makeDecky({ name: 'decoy-77' })}
      />,
    );
    await user.click(screen.getByText('FORCE MUTATE'));
    expect(onForce).toHaveBeenCalledWith('decoy-77');
  });

  it('shows TEARDOWN (admin + swarm) and CONFIRM when armed key matches', () => {
    const swarmDecky = makeDecky({
      name: 'decoy-swarm',
      swarm: {
        host_uuid: 'h-1',
        host_name: 'edge-1',
        host_address: 'edge-1.example',
        host_status: 'ok',
        state: 'running',
        last_error: null,
        last_seen: null,
      },
    });
    const { rerender } = render(
      <DeckyCard {...baseProps} isAdmin decky={swarmDecky} />,
    );
    expect(screen.getByText('TEARDOWN')).toBeInTheDocument();

    rerender(
      <DeckyCard
        {...baseProps}
        isAdmin
        armed="td:h-1:decoy-swarm"
        decky={swarmDecky}
      />,
    );
    expect(screen.getByText('CONFIRM')).toBeInTheDocument();
  });

  it('shows TEARDOWN for admin on a local (non-swarm) decky, keyed td:local:', () => {
    const local = makeDecky({ name: 'decoy-local' });
    const { rerender } = render(
      <DeckyCard {...baseProps} isAdmin decky={local} />,
    );
    expect(screen.getByText('TEARDOWN')).toBeInTheDocument();

    rerender(
      <DeckyCard {...baseProps} isAdmin armed="td:local:decoy-local" decky={local} />,
    );
    expect(screen.getByText('CONFIRM')).toBeInTheDocument();
  });

  it('clicking the card body fires onInspect', async () => {
    const onInspect = vi.fn();
    const user = userEvent.setup();
    render(
      <DeckyCard
        {...baseProps}
        onInspect={onInspect}
        decky={makeDecky({ name: 'decoy-hit' })}
      />,
    );
    // Click on a non-button element inside the card.
    await user.click(screen.getByText('decoy-hit'));
    expect(onInspect).toHaveBeenCalled();
    expect(onInspect.mock.calls[0][0].name).toBe('decoy-hit');
  });
});

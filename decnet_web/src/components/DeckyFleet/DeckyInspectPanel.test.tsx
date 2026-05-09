import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DeckyInspectPanel } from './DeckyInspectPanel';
import { makeDecky } from '../../test/fixtures';

describe('DeckyInspectPanel', () => {
  it('renders the decky name + identity rows from a fixture', () => {
    render(
      <DeckyInspectPanel
        decky={makeDecky({
          name: 'decoy-04',
          ip: '10.0.0.4',
          hostname: 'corp-fs-04',
          distro: 'debian-12',
          archetype: 'workstation',
        })}
        onClose={() => {}}
      />,
    );
    expect(screen.getByText('decoy-04')).toBeInTheDocument();
    expect(screen.getByText('10.0.0.4')).toBeInTheDocument();
    expect(screen.getByText('corp-fs-04')).toBeInTheDocument();
    expect(screen.getByText('workstation')).toBeInTheDocument();
  });

  it('renders the SERVICES chips when services array is non-empty', () => {
    render(
      <DeckyInspectPanel
        decky={makeDecky({ services: ['ssh', 'http'] })}
        onClose={() => {}}
      />,
    );
    expect(screen.getByText('SERVICES')).toBeInTheDocument();
    expect(screen.getByText('ssh')).toBeInTheDocument();
    expect(screen.getByText('http')).toBeInTheDocument();
  });

  it('renders the SWARM block only when decky.swarm is present', () => {
    const { rerender } = render(
      <DeckyInspectPanel decky={makeDecky()} onClose={() => {}} />,
    );
    expect(screen.queryByText('SWARM')).not.toBeInTheDocument();

    rerender(
      <DeckyInspectPanel
        decky={makeDecky({
          swarm: {
            host_uuid: 'h1',
            host_name: 'edge-01',
            host_address: 'edge-01.example',
            host_status: 'ok',
            state: 'running',
            last_error: null,
            last_seen: '2026-05-09T11:00:00Z',
          },
        })}
        onClose={() => {}}
      />,
    );
    expect(screen.getByText('SWARM')).toBeInTheDocument();
    expect(screen.getByText('edge-01')).toBeInTheDocument();
  });

  it('invokes onClose when the X button is clicked', async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    render(
      <DeckyInspectPanel decky={makeDecky()} onClose={onClose} />,
    );
    const closeBtn = screen.getAllByRole('button')[0];
    await user.click(closeBtn);
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

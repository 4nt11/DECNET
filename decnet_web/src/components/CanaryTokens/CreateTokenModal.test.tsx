import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { CreateTokenModal } from './CreateTokenModal';
import type { DeckyOption, TopologyOption } from './types';

// useFocusTrap depends on focus-trap-react that yells at jsdom.
vi.mock('../../hooks/useFocusTrap', () => ({ useFocusTrap: () => {} }));

const deckies: DeckyOption[] = [{ name: 'decoy-01', ip: '10.0.0.1' }];
const topologies: TopologyOption[] = [{ id: 't-1', name: 'corp-net', status: 'active' }];

describe('CreateTokenModal', () => {
  it('renders the title and the Fleet/MazeNET scope toggle', () => {
    render(
      <CreateTokenModal
        blobs={[]}
        deckies={deckies}
        topologies={topologies}
        onClose={() => {}}
        onCreated={() => {}}
      />,
    );
    expect(screen.getByText('NEW CANARY TOKEN')).toBeInTheDocument();
    expect(screen.getByText('Fleet')).toBeInTheDocument();
    expect(screen.getByText('MazeNET topology')).toBeInTheDocument();
  });

  it('CANCEL invokes onClose', async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    render(
      <CreateTokenModal
        blobs={[]}
        deckies={deckies}
        topologies={topologies}
        onClose={onClose}
        onCreated={() => {}}
      />,
    );
    await user.click(screen.getByText('CANCEL'));
    expect(onClose).toHaveBeenCalled();
  });

  it('shows the empty-deckies message when fleet has no deckies', () => {
    render(
      <CreateTokenModal
        blobs={[]}
        deckies={[]}
        topologies={topologies}
        onClose={() => {}}
        onCreated={() => {}}
      />,
    );
    expect(
      screen.getByText('No fleet deckies running. Deploy a fleet first.'),
    ).toBeInTheDocument();
  });

  it('switching to Operator upload reveals the no-blobs hint', async () => {
    const user = userEvent.setup();
    render(
      <CreateTokenModal
        blobs={[]}
        deckies={deckies}
        topologies={topologies}
        onClose={() => {}}
        onCreated={() => {}}
      />,
    );
    await user.click(screen.getByText('Operator upload'));
    expect(
      screen.getByText(/No blobs uploaded yet/),
    ).toBeInTheDocument();
  });
});

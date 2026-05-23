// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {
  FileDropModal, loadFileDrops, saveFileDrops,
  FILEDROP_LS_KEY, type FileDropEntry,
} from './FileDropModal';
import type { DeckyOption, TopologyOption } from './types';

vi.mock('../../hooks/useFocusTrap', () => ({ useFocusTrap: () => {} }));

const deckies: DeckyOption[] = [{ name: 'decoy-01' }];
const topologies: TopologyOption[] = [{ id: 't-1', name: 'corp', status: 'active' }];

beforeEach(() => {
  localStorage.clear();
});

const sampleEntry = (): FileDropEntry => ({
  id: 'fd-1',
  decky_name: 'd',
  topology_id: null,
  path: '/tmp/x',
  size_bytes: 1,
  filename: 'x',
  mode: 0o644,
  mtime_offset: 0,
  dropped_at: '2026-05-09T11:00:00Z',
});

describe('loadFileDrops / saveFileDrops', () => {
  it('returns [] when localStorage is empty', () => {
    expect(loadFileDrops()).toEqual([]);
  });

  it('round-trips through localStorage', () => {
    saveFileDrops([sampleEntry()]);
    const out = loadFileDrops();
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe('fd-1');
  });

  it('caps to 200 entries on save', () => {
    const many: FileDropEntry[] = Array.from({ length: 250 }, (_, i) => ({
      ...sampleEntry(), id: `fd-${i}`,
    }));
    saveFileDrops(many);
    const stored = JSON.parse(localStorage.getItem(FILEDROP_LS_KEY) ?? '[]');
    expect(stored).toHaveLength(200);
  });

  it('returns [] on malformed JSON in storage', () => {
    localStorage.setItem(FILEDROP_LS_KEY, '{not-an-array');
    expect(loadFileDrops()).toEqual([]);
  });
});

describe('FileDropModal', () => {
  it('renders the title and the Fleet/MazeNET toggle', () => {
    render(
      <FileDropModal
        deckies={deckies}
        topologies={topologies}
        onClose={() => {}}
        onDropped={() => {}}
      />,
    );
    expect(screen.getByText('DROP FILE ON DECKY')).toBeInTheDocument();
    expect(screen.getByText('Fleet')).toBeInTheDocument();
  });

  it('renders the bypass-warning banner', () => {
    render(
      <FileDropModal
        deckies={deckies}
        topologies={topologies}
        onClose={() => {}}
        onDropped={() => {}}
      />,
    );
    expect(
      screen.getByText(/File drops bypass canary instrumentation/),
    ).toBeInTheDocument();
  });

  it('CANCEL invokes onClose', async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    render(
      <FileDropModal
        deckies={deckies}
        topologies={topologies}
        onClose={onClose}
        onDropped={() => {}}
      />,
    );
    await user.click(screen.getByText('CANCEL'));
    expect(onClose).toHaveBeenCalled();
  });
});

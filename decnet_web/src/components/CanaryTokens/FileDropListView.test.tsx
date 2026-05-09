import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { FileDropListView } from './FileDropListView';
import type { FileDropEntry } from './FileDropModal';

const entry = (overrides: Partial<FileDropEntry> = {}): FileDropEntry => ({
  id: 'fd-1',
  decky_name: 'decoy-99',
  topology_id: null,
  path: '/tmp/payload.bin',
  size_bytes: 4096,
  filename: 'payload.bin',
  mode: 0o644,
  mtime_offset: 0,
  dropped_at: '2026-05-09T11:00:00Z',
  ...overrides,
});

describe('FileDropListView', () => {
  it('shows the empty hint when fileDrops is []', () => {
    render(<FileDropListView fileDrops={[]} onClear={() => {}} />);
    expect(screen.getByText(/No file drops in this browser yet/)).toBeInTheDocument();
  });

  it('hides CLEAR LIST when there are no entries', () => {
    render(<FileDropListView fileDrops={[]} onClear={() => {}} />);
    expect(screen.queryByText('CLEAR LIST')).not.toBeInTheDocument();
  });

  it('renders one row per drop with its path + decky name', () => {
    render(
      <FileDropListView fileDrops={[entry()]} onClear={() => {}} />,
    );
    expect(screen.getByText('decoy-99')).toBeInTheDocument();
    expect(screen.getByText('/tmp/payload.bin')).toBeInTheDocument();
  });

  it('CLEAR LIST invokes onClear', async () => {
    const onClear = vi.fn();
    const user = userEvent.setup();
    render(
      <FileDropListView fileDrops={[entry()]} onClear={onClear} />,
    );
    await user.click(screen.getByText('CLEAR LIST'));
    expect(onClear).toHaveBeenCalled();
  });
});

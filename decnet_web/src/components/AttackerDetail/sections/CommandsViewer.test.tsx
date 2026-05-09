import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { CommandsViewer } from './CommandsViewer';
import type { CommandRow } from '../types';

const row = (overrides: Partial<CommandRow> = {}): CommandRow => ({
  service: 'ssh',
  decky: 'decoy-01',
  command: 'whoami',
  timestamp: '2026-05-09T11:00:00Z',
  ...overrides,
});

describe('CommandsViewer', () => {
  it('renders the title with the unfiltered total when serviceFilter is null', () => {
    render(
      <CommandsViewer
        commands={[row()]}
        cmdTotal={5}
        cmdPage={1}
        cmdLimit={50}
        setCmdPage={() => {}}
        serviceFilter={null}
        open={true}
        onToggle={() => {}}
      />,
    );
    expect(screen.getByText(/COMMANDS \(5\)/)).toBeInTheDocument();
  });

  it('appends the filter to the title when serviceFilter is set', () => {
    render(
      <CommandsViewer
        commands={[row()]}
        cmdTotal={3}
        cmdPage={1}
        cmdLimit={50}
        setCmdPage={() => {}}
        serviceFilter="ssh"
        open={true}
        onToggle={() => {}}
      />,
    );
    expect(screen.getByText(/COMMANDS \(3 SSH\)/)).toBeInTheDocument();
  });

  it('shows the empty state when commands is []', () => {
    render(
      <CommandsViewer
        commands={[]}
        cmdTotal={0}
        cmdPage={1}
        cmdLimit={50}
        setCmdPage={() => {}}
        serviceFilter={null}
        open={true}
        onToggle={() => {}}
      />,
    );
    expect(screen.getByText('NO COMMANDS CAPTURED')).toBeInTheDocument();
  });

  it('hides pagination when total fits on one page', () => {
    render(
      <CommandsViewer
        commands={[row()]}
        cmdTotal={1}
        cmdPage={1}
        cmdLimit={50}
        setCmdPage={() => {}}
        serviceFilter={null}
        open={true}
        onToggle={() => {}}
      />,
    );
    expect(screen.queryByText(/Page 1 of/)).not.toBeInTheDocument();
  });

  it('paginates: prev/next buttons fire setCmdPage with the right delta', async () => {
    const user = userEvent.setup();
    const setCmdPage = vi.fn();
    render(
      <CommandsViewer
        commands={[row()]}
        cmdTotal={250}
        cmdPage={3}
        cmdLimit={50}
        setCmdPage={setCmdPage}
        serviceFilter={null}
        open={true}
        onToggle={() => {}}
      />,
    );
    expect(screen.getByText('Page 3 of 5')).toBeInTheDocument();
    const buttons = screen.getAllByRole('button');
    await user.click(buttons[0]); // prev
    expect(setCmdPage).toHaveBeenLastCalledWith(2);
    await user.click(buttons[1]); // next
    expect(setCmdPage).toHaveBeenLastCalledWith(4);
  });
});

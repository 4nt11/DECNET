import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { GlobalsTab } from './GlobalsTab';

const okSave = async () => ({ ok: true } as const);
const okReinit = async () =>
  ({ ok: true, deleted: { logs: 12, bounties: 3, attackers: 4 } } as const);

describe('GlobalsTab', () => {
  it('rejects an invalid interval format with the inline error', async () => {
    const user = userEvent.setup();
    render(
      <GlobalsTab
        isAdmin
        developerMode={false}
        initialInterval="30m"
        onSaveInterval={okSave}
        onReinit={okReinit}
      />,
    );
    const input = screen.getByPlaceholderText('30m');
    await user.clear(input);
    await user.type(input, 'forever');
    await user.click(screen.getByText('SAVE'));
    expect(screen.getByText(/INVALID FORMAT/)).toBeInTheDocument();
  });

  it('hides the DANGER ZONE when developerMode is false', () => {
    render(
      <GlobalsTab
        isAdmin
        developerMode={false}
        initialInterval="30m"
        onSaveInterval={okSave}
        onReinit={okReinit}
      />,
    );
    expect(screen.queryByText(/DANGER ZONE/)).not.toBeInTheDocument();
  });

  it('shows the DANGER ZONE under developer mode and reveals confirm on first click', async () => {
    const user = userEvent.setup();
    render(
      <GlobalsTab
        isAdmin
        developerMode
        initialInterval="30m"
        onSaveInterval={okSave}
        onReinit={okReinit}
      />,
    );
    expect(screen.getByText(/DANGER ZONE/)).toBeInTheDocument();
    await user.click(screen.getByText('PURGE ALL DATA'));
    expect(screen.getByText(/ARE YOU SURE/)).toBeInTheDocument();
  });

  it('YES, PURGE fires onReinit and shows the totals chip on success', async () => {
    const onReinit = vi.fn(okReinit);
    const user = userEvent.setup();
    render(
      <GlobalsTab
        isAdmin
        developerMode
        initialInterval="30m"
        onSaveInterval={okSave}
        onReinit={onReinit}
      />,
    );
    await user.click(screen.getByText('PURGE ALL DATA'));
    await user.click(screen.getByText('YES, PURGE'));
    expect(onReinit).toHaveBeenCalled();
    expect(
      await screen.findByText(/PURGED: 12 logs, 3 bounties, 4 attacker profiles/),
    ).toBeInTheDocument();
  });

  it('viewers see the static interval value with no SAVE button', () => {
    render(
      <GlobalsTab
        isAdmin={false}
        developerMode={false}
        initialInterval="30m"
        onSaveInterval={okSave}
        onReinit={okReinit}
      />,
    );
    expect(screen.getByText('30m')).toBeInTheDocument();
    expect(screen.queryByText('SAVE')).not.toBeInTheDocument();
  });
});

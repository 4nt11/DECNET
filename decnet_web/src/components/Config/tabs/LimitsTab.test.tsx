// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { LimitsTab } from './LimitsTab';

describe('LimitsTab', () => {
  it('renders the static value for viewers', () => {
    render(
      <LimitsTab
        isAdmin={false}
        initialValue={42}
        onSave={async () => ({ ok: true })}
      />,
    );
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.queryByText('SAVE')).not.toBeInTheDocument();
  });

  it('renders preset buttons + SAVE for admins', () => {
    render(
      <LimitsTab
        isAdmin
        initialValue={50}
        onSave={async () => ({ ok: true })}
      />,
    );
    expect(screen.getByText('10')).toBeInTheDocument();
    expect(screen.getByText('SAVE')).toBeInTheDocument();
  });

  it('rejects values outside 1-500 with an inline error', async () => {
    const user = userEvent.setup();
    const onSave = vi.fn();
    render(<LimitsTab isAdmin initialValue={50} onSave={onSave} />);
    const input = screen.getByRole('spinbutton');
    await user.clear(input);
    await user.type(input, '999');
    await user.click(screen.getByText('SAVE'));
    expect(screen.getByText('VALUE MUST BE 1-500')).toBeInTheDocument();
    expect(onSave).not.toHaveBeenCalled();
  });

  it('shows success chip on ok and error chip with the reason on failure', async () => {
    const user = userEvent.setup();
    const { rerender } = render(
      <LimitsTab
        isAdmin
        initialValue={50}
        onSave={async () => ({ ok: true })}
      />,
    );
    await user.click(screen.getByText('SAVE'));
    expect(screen.getByText('DEPLOYMENT LIMIT UPDATED')).toBeInTheDocument();

    rerender(
      <LimitsTab
        isAdmin
        initialValue={50}
        onSave={async () => ({ ok: false, reason: 'too high' })}
      />,
    );
    await user.click(screen.getByText('SAVE'));
    expect(screen.getByText('too high')).toBeInTheDocument();
  });
});

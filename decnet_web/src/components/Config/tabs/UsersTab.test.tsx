import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { UsersTab } from './UsersTab';
import type { UserEntry } from '../types';

const users: UserEntry[] = [
  { uuid: 'u-1', username: 'alice', role: 'admin', must_change_password: false },
  { uuid: 'u-2', username: 'bob', role: 'viewer', must_change_password: true },
];

const okMutation = async () => ({ ok: true } as const);

describe('UsersTab', () => {
  it('renders one row per user with the must-change badge when set', () => {
    render(
      <UsersTab
        users={users}
        onDeleteUser={okMutation}
        onSetUserRole={okMutation}
        onResetUserPassword={okMutation}
        onAddUser={okMutation}
      />,
    );
    expect(screen.getByText('alice')).toBeInTheDocument();
    expect(screen.getByText('bob')).toBeInTheDocument();
    expect(screen.getByText('MUST CHANGE PASSWORD')).toBeInTheDocument();
  });

  it('two-step delete only fires onDeleteUser after CONFIRM', async () => {
    const onDeleteUser = vi.fn(okMutation);
    const user = userEvent.setup();
    render(
      <UsersTab
        users={users}
        onDeleteUser={onDeleteUser}
        onSetUserRole={okMutation}
        onResetUserPassword={okMutation}
        onAddUser={okMutation}
      />,
    );
    const deleteButtons = screen.getAllByText('DELETE');
    await user.click(deleteButtons[0]); // alice -> arms confirm
    expect(onDeleteUser).not.toHaveBeenCalled();
    expect(screen.getByText('CONFIRM?')).toBeInTheDocument();

    await user.click(screen.getByText('YES'));
    expect(onDeleteUser).toHaveBeenCalledWith('u-1');
  });

  it('add-user form fires onAddUser with trimmed input + selected role', async () => {
    const onAddUser = vi.fn(okMutation);
    const user = userEvent.setup();
    render(
      <UsersTab
        users={users}
        onDeleteUser={okMutation}
        onSetUserRole={okMutation}
        onResetUserPassword={okMutation}
        onAddUser={onAddUser}
      />,
    );
    const usernameInput = screen.getAllByRole('textbox')[0];
    const passwordInput = document.querySelector('input[type="password"]') as HTMLInputElement;
    await user.type(usernameInput, '  charlie  ');
    await user.type(passwordInput, 'longenoughpw');
    await user.click(screen.getByText('ADD USER'));
    expect(onAddUser).toHaveBeenCalledWith({
      username: 'charlie',
      password: 'longenoughpw',
      role: 'viewer',
    });
  });

  it('shows the success chip after a successful add', async () => {
    const user = userEvent.setup();
    render(
      <UsersTab
        users={users}
        onDeleteUser={okMutation}
        onSetUserRole={okMutation}
        onResetUserPassword={okMutation}
        onAddUser={okMutation}
      />,
    );
    await user.type(screen.getAllByRole('textbox')[0], 'dave');
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement;
    await user.type(pwInput, 'longenoughpw');
    await user.click(screen.getByText('ADD USER'));
    expect(await screen.findByText('USER CREATED')).toBeInTheDocument();
  });
});

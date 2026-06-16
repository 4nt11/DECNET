// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MailLogPanel } from './MailLogPanel';
import type { MailLog } from '../types';

vi.mock('../../MailDrawer', () => ({
  default: ({ storedAs, onClose }: { storedAs: string; onClose: () => void }) => (
    <div data-testid="mail-drawer">
      drawer for {storedAs}
      <button onClick={onClose}>close</button>
    </div>
  ),
}));

const fields = (extra: Record<string, unknown> = {}) =>
  JSON.stringify({
    stored_as: '/var/mail/attacker.eml',
    subject: 'Hello victim',
    from_hdr: 'attacker@example.invalid',
    date_hdr: 'Sat, 09 May 2026 11:00:00 +0000',
    size: 2048,
    ...extra,
  });

const row = (overrides: Partial<MailLog> = {}): MailLog => ({
  id: 1,
  timestamp: '2026-05-09T11:00:00Z',
  decky: 'decoy-01',
  service: 'smtp',
  fields: fields(),
  ...overrides,
});

describe('MailLogPanel', () => {
  it('renders rows with subject + from header parsed from SD fields', () => {
    render(
      <MailLogPanel
        mail={[row()]}
        mailForbidden={false}
        open={true}
        onToggle={() => {}}
      />,
    );
    expect(screen.getByText('Hello victim')).toBeInTheDocument();
    expect(screen.getByText('attacker@example.invalid')).toBeInTheDocument();
  });

  it('renders the admin-required empty state when mailForbidden is true', () => {
    render(
      <MailLogPanel mail={[]} mailForbidden={true} open={true} onToggle={() => {}} />,
    );
    expect(screen.getByText('ADMIN ROLE REQUIRED')).toBeInTheDocument();
  });

  it('renders the no-mail empty state when not forbidden and list is empty', () => {
    render(
      <MailLogPanel mail={[]} mailForbidden={false} open={true} onToggle={() => {}} />,
    );
    expect(screen.getByText('NO MAIL STORED')).toBeInTheDocument();
  });

  it('falls back through from_hdr -> from_addr -> mail_from', () => {
    render(
      <MailLogPanel
        mail={[
          row({
            fields: JSON.stringify({
              stored_as: '/var/mail/x.eml',
              mail_from: 'envelope@from.invalid',
            }),
          }),
        ]}
        mailForbidden={false}
        open={true}
        onToggle={() => {}}
      />,
    );
    expect(screen.getByText('envelope@from.invalid')).toBeInTheDocument();
  });

  it('opens and closes the MailDrawer on row OPEN button', async () => {
    const user = userEvent.setup();
    render(
      <MailLogPanel
        mail={[row()]}
        mailForbidden={false}
        open={true}
        onToggle={() => {}}
      />,
    );
    expect(screen.queryByTestId('mail-drawer')).not.toBeInTheDocument();
    await user.click(screen.getByText(/^OPEN$/));
    expect(screen.getByTestId('mail-drawer')).toBeInTheDocument();
    await user.click(screen.getByText('close'));
    expect(screen.queryByTestId('mail-drawer')).not.toBeInTheDocument();
  });
});

// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { makeAttacker } from '../../../test/fixtures';
import { AttackerStats } from './AttackerStats';

describe('AttackerStats', () => {
  it('renders the five top-line counter cards from attacker fields', () => {
    render(
      <AttackerStats
        attacker={makeAttacker({
          event_count: 99,
          bounty_count: 7,
          credential_count: 5,
          service_count: 3,
          decky_count: 2,
        })}
      />,
    );
    expect(screen.getByText('99')).toBeInTheDocument();
    expect(screen.getByText('7')).toBeInTheDocument();
    expect(screen.getByText('5')).toBeInTheDocument();
    expect(screen.getByText('EVENTS')).toBeInTheDocument();
    expect(screen.getByText('BOUNTIES')).toBeInTheDocument();
    expect(screen.getByText('CREDENTIALS')).toBeInTheDocument();
    expect(screen.getByText('SERVICES')).toBeInTheDocument();
    expect(screen.getByText('DECKIES')).toBeInTheDocument();
  });

  it('renders the scan-vs-interact row when activity has any signal', () => {
    render(
      <AttackerStats
        attacker={makeAttacker({
          service_activity: { scanned: ['ssh', 'http'], interacted: ['ssh'] },
        })}
      />,
    );
    expect(screen.getByText('SCANNED · SERVICES')).toBeInTheDocument();
    expect(screen.getByText('INTERACTED WITH · SERVICES')).toBeInTheDocument();
  });

  it('hides the scan-vs-interact row when both arrays are empty', () => {
    render(
      <AttackerStats
        attacker={makeAttacker({
          service_activity: { scanned: [], interacted: [] },
        })}
      />,
    );
    expect(screen.queryByText('SCANNED · SERVICES')).not.toBeInTheDocument();
  });

  it('hides the scan-vs-interact row when service_activity is undefined', () => {
    const attacker = makeAttacker();
    delete (attacker as Partial<typeof attacker>).service_activity;
    render(<AttackerStats attacker={attacker} />);
    expect(screen.queryByText('SCANNED · SERVICES')).not.toBeInTheDocument();
  });
});

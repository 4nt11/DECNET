// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DeckyGridEmpty } from './DeckyGridEmpty';

describe('DeckyGridEmpty', () => {
  it('shows the fleet-empty copy when fleetEmpty is true', () => {
    render(
      <DeckyGridEmpty fleetEmpty isAdmin={false} onDeploy={() => {}} />,
    );
    expect(screen.getByText('NO DECOYS DEPLOYED IN THIS SECTOR')).toBeInTheDocument();
  });

  it('shows the filtered-empty copy when fleetEmpty is false', () => {
    render(
      <DeckyGridEmpty fleetEmpty={false} isAdmin={false} onDeploy={() => {}} />,
    );
    expect(screen.getByText('NO DECOYS MATCH CURRENT FILTER')).toBeInTheDocument();
  });

  it('only renders the DEPLOY shortcut for admins on a truly empty fleet', () => {
    const { rerender } = render(
      <DeckyGridEmpty fleetEmpty isAdmin={false} onDeploy={() => {}} />,
    );
    expect(screen.queryByText(/DEPLOY DECKIES/)).not.toBeInTheDocument();

    rerender(
      <DeckyGridEmpty fleetEmpty={false} isAdmin onDeploy={() => {}} />,
    );
    expect(screen.queryByText(/DEPLOY DECKIES/)).not.toBeInTheDocument();

    const onDeploy = vi.fn();
    rerender(
      <DeckyGridEmpty fleetEmpty isAdmin onDeploy={onDeploy} />,
    );
    const user = userEvent.setup();
    return user.click(screen.getByText(/DEPLOY DECKIES/)).then(() => {
      expect(onDeploy).toHaveBeenCalled();
    });
  });
});

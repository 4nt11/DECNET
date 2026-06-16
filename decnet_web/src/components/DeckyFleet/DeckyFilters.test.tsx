// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DeckyFilters } from './DeckyFilters';

const counts = { all: 7, active: 4, hot: 2, idle: 1 } as const;

describe('DeckyFilters', () => {
  it('renders one button per filter with the matching count', () => {
    render(
      <DeckyFilters
        filter="all"
        setFilter={() => {}}
        counts={counts}
        isAdmin={false}
        onDeploy={() => {}}
      />,
    );
    expect(screen.getByText('ALL 7')).toBeInTheDocument();
    expect(screen.getByText('ACTIVE 4')).toBeInTheDocument();
    expect(screen.getByText('HOT 2')).toBeInTheDocument();
    expect(screen.getByText('IDLE 1')).toBeInTheDocument();
  });

  it('clicking a filter button invokes setFilter with its key', async () => {
    const setFilter = vi.fn();
    const user = userEvent.setup();
    render(
      <DeckyFilters
        filter="all"
        setFilter={setFilter}
        counts={counts}
        isAdmin={false}
        onDeploy={() => {}}
      />,
    );
    await user.click(screen.getByText('HOT 2'));
    expect(setFilter).toHaveBeenCalledWith('hot');
  });

  it('hides DEPLOY DECKIES for non-admins, shows it for admins', async () => {
    const onDeploy = vi.fn();
    const { rerender } = render(
      <DeckyFilters
        filter="all"
        setFilter={() => {}}
        counts={counts}
        isAdmin={false}
        onDeploy={onDeploy}
      />,
    );
    expect(screen.queryByText(/DEPLOY DECKIES/)).not.toBeInTheDocument();

    rerender(
      <DeckyFilters
        filter="all"
        setFilter={() => {}}
        counts={counts}
        isAdmin
        onDeploy={onDeploy}
      />,
    );
    const user = userEvent.setup();
    await user.click(screen.getByText(/DEPLOY DECKIES/));
    expect(onDeploy).toHaveBeenCalled();
  });
});

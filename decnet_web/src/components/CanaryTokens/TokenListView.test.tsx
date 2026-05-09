import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { TokenListView } from './TokenListView';
import { makeCanaryToken } from '../../test/fixtures';

const baseProps = {
  loading: false,
  error: null,
  filter: '',
  setFilter: () => {},
  stateFilter: 'all' as const,
  setStateFilter: () => {},
  scopeFilter: 'all' as const,
  setScopeFilter: () => {},
  onPick: () => {},
};

describe('TokenListView', () => {
  it('renders one row per token', () => {
    render(
      <TokenListView
        {...baseProps}
        tokens={[
          makeCanaryToken({ uuid: 't1', decky_name: 'decoy-01' }),
          makeCanaryToken({ uuid: 't2', decky_name: 'decoy-02' }),
        ]}
      />,
    );
    expect(screen.getByText('decoy-01')).toBeInTheDocument();
    expect(screen.getByText('decoy-02')).toBeInTheDocument();
  });

  it('shows the empty-fleet hint when tokens is []', () => {
    render(<TokenListView {...baseProps} tokens={[]} />);
    expect(screen.getByText(/No canary tokens yet/)).toBeInTheDocument();
  });

  it('shows the filtered-empty hint when filter excludes all rows', () => {
    render(
      <TokenListView
        {...baseProps}
        tokens={[makeCanaryToken({ decky_name: 'decoy-01' })]}
        filter="zzzz-no-match"
      />,
    );
    expect(screen.getByText('No tokens match the current filter.')).toBeInTheDocument();
  });

  it('respects stateFilter', () => {
    render(
      <TokenListView
        {...baseProps}
        tokens={[
          makeCanaryToken({ uuid: 't1', decky_name: 'planted-d', state: 'planted' }),
          makeCanaryToken({ uuid: 't2', decky_name: 'revoked-d', state: 'revoked' }),
        ]}
        stateFilter="planted"
      />,
    );
    expect(screen.getByText('planted-d')).toBeInTheDocument();
    expect(screen.queryByText('revoked-d')).not.toBeInTheDocument();
  });

  it('clicking a row invokes onPick with the token', async () => {
    const onPick = vi.fn();
    const user = userEvent.setup();
    render(
      <TokenListView
        {...baseProps}
        tokens={[makeCanaryToken({ uuid: 't1', decky_name: 'decoy-01' })]}
        onPick={onPick}
      />,
    );
    await user.click(screen.getByText('decoy-01'));
    expect(onPick).toHaveBeenCalled();
    expect(onPick.mock.calls[0][0].uuid).toBe('t1');
  });
});

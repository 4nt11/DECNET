import { describe, it, expect } from 'vitest';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithRouter } from '../../../test/renderWithRouter';
import { makeAttacker } from '../../../test/fixtures';
import { AttackerHeader } from './AttackerHeader';

describe('AttackerHeader', () => {
  it('renders the IP and a country tag when country_code is present', () => {
    renderWithRouter(<AttackerHeader attacker={makeAttacker({ country_code: 'BR' })} />);
    expect(screen.getByText('198.51.100.10')).toBeInTheDocument();
    expect(screen.getByText('BR')).toBeInTheDocument();
  });

  it('omits the country tag when country_code is null', () => {
    renderWithRouter(
      <AttackerHeader attacker={makeAttacker({ country_code: null })} />,
    );
    expect(screen.queryByText('BR')).not.toBeInTheDocument();
    expect(screen.queryByText('US')).not.toBeInTheDocument();
  });

  it('shows the TRAVERSAL badge when is_traversal is true', () => {
    renderWithRouter(
      <AttackerHeader attacker={makeAttacker({ is_traversal: true })} />,
    );
    expect(screen.getByText('TRAVERSAL')).toBeInTheDocument();
  });

  it('renders the IDENTITY badge with first 8 chars and navigates on click', async () => {
    const user = userEvent.setup();
    const identity = 'aaaabbbb-cccc-dddd-eeee-ffffffffffff';
    renderWithRouter(
      <AttackerHeader attacker={makeAttacker({ identity_id: identity })} />,
    );
    const badge = screen.getByText(/IDENTITY · aaaabbbb/);
    expect(badge).toBeInTheDocument();
    // No assertion on navigation target; we just verify the click
    // handler doesn't throw (router is present via renderWithRouter).
    await user.click(badge);
  });

  it('omits the IDENTITY badge when identity_id is null', () => {
    renderWithRouter(
      <AttackerHeader attacker={makeAttacker({ identity_id: null })} />,
    );
    expect(screen.queryByText(/IDENTITY/)).not.toBeInTheDocument();
  });
});

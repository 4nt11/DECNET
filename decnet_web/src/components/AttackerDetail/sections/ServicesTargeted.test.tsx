import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { makeAttacker } from '../../../test/fixtures';
import { ServicesTargeted } from './ServicesTargeted';

describe('ServicesTargeted', () => {
  it('renders one upper-cased badge per service', () => {
    render(
      <ServicesTargeted
        attacker={makeAttacker({ services: ['ssh', 'http', 'smtp'] })}
        serviceFilter={null}
        setServiceFilter={() => {}}
        open={true}
        onToggle={() => {}}
      />,
    );
    expect(screen.getByText(/SSH/)).toBeInTheDocument();
    expect(screen.getByText(/HTTP/)).toBeInTheDocument();
    expect(screen.getByText(/SMTP/)).toBeInTheDocument();
  });

  it('shows the empty-state when services is []', () => {
    render(
      <ServicesTargeted
        attacker={makeAttacker({ services: [] })}
        serviceFilter={null}
        setServiceFilter={() => {}}
        open={true}
        onToggle={() => {}}
      />,
    );
    expect(screen.getByText('No services recorded')).toBeInTheDocument();
  });

  it('selecting an inactive badge invokes setServiceFilter with the slug', async () => {
    const setServiceFilter = vi.fn();
    const user = userEvent.setup();
    render(
      <ServicesTargeted
        attacker={makeAttacker({ services: ['ssh'] })}
        serviceFilter={null}
        setServiceFilter={setServiceFilter}
        open={true}
        onToggle={() => {}}
      />,
    );
    await user.click(screen.getByText(/SSH/));
    expect(setServiceFilter).toHaveBeenCalledWith('ssh');
  });

  it('clicking the active badge clears the filter (passes null)', async () => {
    const setServiceFilter = vi.fn();
    const user = userEvent.setup();
    render(
      <ServicesTargeted
        attacker={makeAttacker({ services: ['ssh'] })}
        serviceFilter={'ssh'}
        setServiceFilter={setServiceFilter}
        open={true}
        onToggle={() => {}}
      />,
    );
    await user.click(screen.getByText(/SSH/));
    expect(setServiceFilter).toHaveBeenCalledWith(null);
  });
});

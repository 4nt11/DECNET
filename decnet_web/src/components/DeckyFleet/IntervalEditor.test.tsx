// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { IntervalEditor } from './IntervalEditor';

describe('IntervalEditor', () => {
  it('starts disabled when current is null and saves null', async () => {
    const onSave = vi.fn();
    const user = userEvent.setup();
    render(
      <IntervalEditor
        open
        deckyName="decoy-01"
        current={null}
        onClose={() => {}}
        onSave={onSave}
      />,
    );
    const checkbox = screen.getByLabelText('ENABLE PERIODIC MUTATION') as HTMLInputElement;
    expect(checkbox.checked).toBe(false);
    expect(screen.queryByText(/INTERVAL \(/)).not.toBeInTheDocument();

    await user.click(screen.getByText('SAVE'));
    expect(onSave).toHaveBeenCalledWith(null);
  });

  it('starts enabled when current is a number and saves the slider value', async () => {
    const onSave = vi.fn();
    const user = userEvent.setup();
    render(
      <IntervalEditor
        open
        deckyName="decoy-02"
        current={45}
        onClose={() => {}}
        onSave={onSave}
      />,
    );
    expect(screen.getByText(/INTERVAL \(45 minutes\)/)).toBeInTheDocument();

    await user.click(screen.getByText('SAVE'));
    expect(onSave).toHaveBeenCalledWith(45);
  });

  it('CANCEL invokes onClose without onSave', async () => {
    const onClose = vi.fn();
    const onSave = vi.fn();
    const user = userEvent.setup();
    render(
      <IntervalEditor
        open
        deckyName="decoy-03"
        current={30}
        onClose={onClose}
        onSave={onSave}
      />,
    );
    await user.click(screen.getByText('CANCEL'));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(onSave).not.toHaveBeenCalled();
  });
});

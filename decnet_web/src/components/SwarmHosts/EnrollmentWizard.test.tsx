// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import EnrollmentWizard from './EnrollmentWizard';

vi.mock('../../hooks/useFocusTrap', () => ({
  default: () => {},
  useFocusTrap: () => {},
}));

const stubGen = vi.fn();

describe('EnrollmentWizard', () => {
  it('keeps NEXT disabled until a valid agent name is entered', () => {
    render(
      <EnrollmentWizard
        open
        onClose={() => {}}
        onEnrolled={() => {}}
        generateBundle={stubGen}
      />,
    );
    const next = screen.getByText(/NEXT/i).closest('button')!;
    expect(next).toBeDisabled();

    const input = screen.getAllByRole('textbox').find(
      (i) => (i as HTMLInputElement).value === '',
    ) as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'agent-1' } });
    expect(next).not.toBeDisabled();
  });

  it('renders step labels', () => {
    render(
      <EnrollmentWizard
        open onClose={() => {}} onEnrolled={() => {}} generateBundle={stubGen}
      />,
    );
    expect(screen.getByText(/IDENTITY/)).toBeInTheDocument();
    expect(screen.getByText(/OPTIONS/)).toBeInTheDocument();
    expect(screen.getByText(/BUNDLE/)).toBeInTheDocument();
  });
});

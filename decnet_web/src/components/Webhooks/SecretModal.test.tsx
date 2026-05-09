/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import SecretModal from './SecretModal';

describe('SecretModal', () => {
  it('renders the secret and fires onClose for DONE', () => {
    const onClose = vi.fn();
    render(<SecretModal name="shuffle" secret="abc123def456ghi7" onClose={onClose} />);
    expect(screen.getByText('abc123def456ghi7')).toBeInTheDocument();
    expect(screen.getByText(/SHUFFLE/)).toBeInTheDocument();
    fireEvent.click(screen.getByText('DONE'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('closes when backdrop is clicked but not when the inner modal is clicked', () => {
    const onClose = vi.fn();
    const { container } = render(
      <SecretModal name="x" secret="s" onClose={onClose} />,
    );
    fireEvent.click(container.querySelector('.wh-secret-modal-backdrop')!);
    expect(onClose).toHaveBeenCalledTimes(1);
    fireEvent.click(container.querySelector('.wh-secret-modal')!);
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

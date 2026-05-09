import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { UploadModal } from './UploadModal';

vi.mock('../../hooks/useFocusTrap', () => ({ useFocusTrap: () => {} }));

describe('UploadModal', () => {
  it('renders the title and the empty drop zone hint', () => {
    render(<UploadModal onClose={() => {}} onUploaded={() => {}} />);
    expect(screen.getByText('UPLOAD CANARY ARTIFACT')).toBeInTheDocument();
    expect(screen.getByText('Drop a file here or click to browse')).toBeInTheDocument();
  });

  it('renders the operator-warning banner about server-side injection', () => {
    render(<UploadModal onClose={() => {}} onUploaded={() => {}} />);
    expect(
      screen.getByText(/DECNET injects the callback server-side/),
    ).toBeInTheDocument();
  });

  it('UPLOAD button stays disabled until a file is picked', () => {
    render(<UploadModal onClose={() => {}} onUploaded={() => {}} />);
    const upload = screen.getByText('UPLOAD') as HTMLButtonElement;
    expect(upload.disabled).toBe(true);
  });

  it('CANCEL invokes onClose', async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    render(<UploadModal onClose={onClose} onUploaded={() => {}} />);
    await user.click(screen.getByText('CANCEL'));
    expect(onClose).toHaveBeenCalled();
  });
});

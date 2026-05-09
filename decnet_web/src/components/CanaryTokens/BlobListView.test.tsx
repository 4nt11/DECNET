import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BlobListView } from './BlobListView';
import { makeCanaryBlob } from '../../test/fixtures';

describe('BlobListView', () => {
  it('shows the empty hint when blobs is []', () => {
    render(<BlobListView blobs={[]} onDelete={() => {}} />);
    expect(screen.getByText(/No uploaded artifacts/)).toBeInTheDocument();
  });

  it('renders DELETE for blobs with no token refs and the ref count otherwise', () => {
    render(
      <BlobListView
        blobs={[
          makeCanaryBlob({ uuid: 'b1', filename: 'free.bin', token_count: 0 }),
          makeCanaryBlob({ uuid: 'b2', filename: 'used.bin', token_count: 3 }),
        ]}
        onDelete={() => {}}
      />,
    );
    expect(screen.getByText('DELETE')).toBeInTheDocument();
    expect(screen.getByText('3 REFS')).toBeInTheDocument();
  });

  it('clicking DELETE invokes onDelete with the blob uuid', async () => {
    const onDelete = vi.fn();
    const user = userEvent.setup();
    render(
      <BlobListView
        blobs={[makeCanaryBlob({ uuid: 'b-abc', token_count: 0 })]}
        onDelete={onDelete}
      />,
    );
    await user.click(screen.getByText('DELETE'));
    expect(onDelete).toHaveBeenCalledWith('b-abc');
  });

  it('refused DELETE button is disabled when token_count > 0', () => {
    render(
      <BlobListView
        blobs={[makeCanaryBlob({ uuid: 'b-locked', token_count: 2 })]}
        onDelete={() => {}}
      />,
    );
    const refsBtn = screen.getByText('2 REFS') as HTMLButtonElement;
    expect(refsBtn.disabled).toBe(true);
  });
});

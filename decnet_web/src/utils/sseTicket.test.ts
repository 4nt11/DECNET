// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * @vitest-environment node
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the api module BEFORE importing the unit under test so the module
// factory runs first and replaces the real axios instance.
vi.mock('./api', () => ({
  default: {
    post: vi.fn(),
  },
}));

import api from './api';
import { mintSseTicket } from './sseTicket';

const mockPost = api.post as ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.clearAllMocks();
});

describe('mintSseTicket', () => {
  it('POSTs to /auth/sse-ticket and returns the ticket string', async () => {
    mockPost.mockResolvedValueOnce({
      data: { ticket: 'opaque-abc-123', expires_in: 60 },
    });

    const ticket = await mintSseTicket();

    expect(mockPost).toHaveBeenCalledTimes(1);
    expect(mockPost).toHaveBeenCalledWith('/auth/sse-ticket');
    expect(ticket).toBe('opaque-abc-123');
  });

  it('propagates API errors to the caller', async () => {
    const err = Object.assign(new Error('Unauthorized'), {
      response: { status: 401, data: { detail: 'Could not validate credentials' } },
    });
    mockPost.mockRejectedValueOnce(err);

    await expect(mintSseTicket()).rejects.toThrow('Unauthorized');
    expect(mockPost).toHaveBeenCalledWith('/auth/sse-ticket');
  });

  it('propagates network errors (no response object) to the caller', async () => {
    mockPost.mockRejectedValueOnce(new Error('Network Error'));

    await expect(mintSseTicket()).rejects.toThrow('Network Error');
  });
});

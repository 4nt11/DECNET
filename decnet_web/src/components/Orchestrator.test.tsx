import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

import Orchestrator from './Orchestrator';
import type {
  OrchestratorStreamEvent,
  UseOrchestratorStreamOptions,
} from './useOrchestratorStream';

vi.mock('../utils/api', () => ({
  default: { get: vi.fn() },
}));

// Capture the live stream callback so tests can drive it manually.
let capturedOnEvent:
  | ((event: OrchestratorStreamEvent) => void)
  | null = null;
vi.mock('./useOrchestratorStream', () => ({
  useOrchestratorStream: (opts: UseOrchestratorStreamOptions) => {
    capturedOnEvent = opts.onEvent;
  },
}));

import api from '../utils/api';
const apiGet = api.get as ReturnType<typeof vi.fn>;

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={['/orchestrator']}>
      <Orchestrator />
    </MemoryRouter>,
  );

describe('Orchestrator', () => {
  beforeEach(() => {
    capturedOnEvent = null;
    apiGet.mockReset();
  });

  it('renders the empty state when the API returns no events', async () => {
    apiGet.mockResolvedValueOnce({ data: { data: [], total: 0 } });

    renderPage();

    expect(await screen.findByText(/NO ORCHESTRATOR ACTIVITY YET/i)).toBeInTheDocument();
    // The kind=all path advertises the orchestrator command, not the emailgen one.
    expect(screen.getByText(/decnet orchestrate/i)).toBeInTheDocument();
  });

  it('switches the kind filter and refetches scoped to that kind', async () => {
    apiGet.mockResolvedValue({ data: { data: [], total: 0 } });

    renderPage();
    await waitFor(() => expect(apiGet).toHaveBeenCalledTimes(1));
    expect(apiGet.mock.calls[0][0]).toMatch(/^\/orchestrator\/events\?limit=50&offset=0$/);

    await userEvent.click(screen.getByRole('tab', { name: /^email$/ }));

    await waitFor(() =>
      expect(apiGet.mock.calls.some((c) => /kind=email/.test(c[0]))).toBe(true),
    );
    expect(screen.getByRole('tab', { name: /^email$/ })).toHaveAttribute('aria-selected', 'true');
  });

  it('prepends a row when the live stream pushes a traffic event', async () => {
    apiGet.mockResolvedValueOnce({ data: { data: [], total: 0 } });

    renderPage();
    await waitFor(() => expect(capturedOnEvent).not.toBeNull());

    act(() => {
      capturedOnEvent!({
        name: 'traffic',
        ts: new Date().toISOString(),
        payload: {
          kind: 'traffic',
          protocol: 'http',
          action: 'GET /admin',
          src_decky_uuid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
          dst_decky_uuid: 'ffffffff-1111-2222-3333-444444444444',
          success: true,
          payload: '{}',
        },
      });
    });

    expect(await screen.findByText('GET /admin')).toBeInTheDocument();
    // 1 event shown after a single push.
    expect(screen.getByText(/1 EVENTS SHOWN/i)).toBeInTheDocument();
  });
});

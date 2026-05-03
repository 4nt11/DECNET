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

/** Two endpoints fire at mount — events list + failure-count stats.
 *  This dispatcher maps URLs to canned responses so per-test cases stay
 *  focused on the path they care about. */
const buildApiResponder = (overrides: {
  events?: { data: unknown[]; total: number };
  failures?: number;
} = {}) => {
  const events = overrides.events ?? { data: [], total: 0 };
  const failures = overrides.failures ?? 0;
  return (url: string) => {
    if (url.startsWith('/orchestrator/events/stats')) {
      return Promise.resolve({ data: { count: failures } });
    }
    if (url.startsWith('/orchestrator/events')) {
      return Promise.resolve({ data: events });
    }
    return Promise.resolve({ data: {} });
  };
};

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
    apiGet.mockImplementation(buildApiResponder());

    renderPage();

    expect(await screen.findByText(/NO ORCHESTRATOR ACTIVITY YET/i)).toBeInTheDocument();
    // The kind=all path advertises the orchestrator command, not the emailgen one.
    expect(screen.getByText(/decnet orchestrate/i)).toBeInTheDocument();
  });

  it('switches the kind filter and refetches scoped to that kind', async () => {
    apiGet.mockImplementation(buildApiResponder());

    renderPage();
    await waitFor(() =>
      expect(
        apiGet.mock.calls.some((c) => /^\/orchestrator\/events\?limit=50&offset=0$/.test(c[0])),
      ).toBe(true),
    );

    await userEvent.click(screen.getByRole('tab', { name: /^email$/ }));

    await waitFor(() =>
      expect(apiGet.mock.calls.some((c) => /kind=email/.test(c[0]))).toBe(true),
    );
    expect(screen.getByRole('tab', { name: /^email$/ })).toHaveAttribute('aria-selected', 'true');
  });

  it('prepends a row when the live stream pushes a traffic event', async () => {
    apiGet.mockImplementation(buildApiResponder());

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

  it('renders the failure-count badge from the stats endpoint (DEBT-042)', async () => {
    apiGet.mockImplementation(buildApiResponder({ failures: 42 }));

    renderPage();

    expect(await screen.findByText(/42 FAILURES \/ 1H/i)).toBeInTheDocument();
    // Stats endpoint is the authoritative source — verify it was actually queried.
    expect(
      apiGet.mock.calls.some((c) =>
        /\/orchestrator\/events\/stats\?since=1h&success=false/.test(c[0]),
      ),
    ).toBe(true);
  });

  it('hides the failure-count badge when the stats endpoint reports zero', async () => {
    apiGet.mockImplementation(buildApiResponder({ failures: 0 }));

    renderPage();
    await waitFor(() =>
      expect(
        apiGet.mock.calls.some((c) => /\/orchestrator\/events\/stats/.test(c[0])),
      ).toBe(true),
    );

    expect(screen.queryByText(/FAILURES \/ 1H/i)).not.toBeInTheDocument();
  });
});

// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { http, HttpResponse, server, apiUrl } from '../../test/server';
import { renderWithRouter } from '../../test/renderWithRouter';
import { WorkersPanel } from './WorkersPanel';

const noop = () => {};

describe('WorkersPanel', () => {
  it('renders the worker rows from /workers', async () => {
    server.use(
      http.get(apiUrl('/workers'), () =>
        HttpResponse.json({
          workers: [
            {
              name: 'orchestrator',
              status: 'ok',
              last_heartbeat_ts: 0,
              seconds_since: 12,
              extra: {},
              installed: true,
            },
            {
              name: 'profiler',
              status: 'stale',
              last_heartbeat_ts: 0,
              seconds_since: 600,
              extra: {},
              installed: true,
            },
          ],
          bus_connected: true,
        }),
      ),
    );
    renderWithRouter(<WorkersPanel pushToast={noop} />);
    await waitFor(() => expect(screen.getByText('ORCHESTRATOR')).toBeInTheDocument());
    expect(screen.getByText('PROFILER')).toBeInTheDocument();
    // "OK" appears twice — in the header copy ("OK < 90s") and in the
    // status cell. Just confirm both are present.
    expect(screen.getAllByText('OK').length).toBeGreaterThan(0);
    expect(screen.getByText('STALE')).toBeInTheDocument();
  });

  it('renders the BUS OFFLINE banner when bus_connected is false', async () => {
    server.use(
      http.get(apiUrl('/workers'), () =>
        HttpResponse.json({ workers: [], bus_connected: false }),
      ),
    );
    renderWithRouter(<WorkersPanel pushToast={noop} />);
    await waitFor(() =>
      expect(screen.getByText(/BUS OFFLINE/)).toBeInTheDocument(),
    );
  });

  it('renders an error panel when /workers fails', async () => {
    server.use(
      http.get(apiUrl('/workers'), () =>
        HttpResponse.json({ detail: 'boom' }, { status: 500 }),
      ),
    );
    renderWithRouter(<WorkersPanel pushToast={noop} />);
    await waitFor(() => expect(screen.getByText('boom')).toBeInTheDocument());
  });
});

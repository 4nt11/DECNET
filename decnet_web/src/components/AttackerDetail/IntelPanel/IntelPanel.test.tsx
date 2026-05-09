/**
 * @vitest-environment jsdom
 */
import { describe, it, expect } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { http, HttpResponse, server, apiUrl } from '../../../test/server';
import { IntelPanel } from './IntelPanel';
import type { IntelRow } from './types';

const intel = (over: Partial<IntelRow> = {}): IntelRow => ({
  attacker_uuid: 'a-1',
  attacker_ip: '1.2.3.4',
  aggregate_verdict: 'malicious',
  cached_at: '2026-05-01T00:00:00Z',
  expires_at: '2026-05-02T00:00:00Z',
  greynoise_classification: 'malicious',
  greynoise_queried_at: '2026-05-01T00:00:00Z',
  abuseipdb_score: 90,
  abuseipdb_queried_at: '2026-05-01T00:00:00Z',
  feodo_listed: true,
  feodo_raw: { malware: 'Emotet' },
  feodo_queried_at: '2026-05-01T00:00:00Z',
  threatfox_listed: false,
  threatfox_queried_at: '2026-05-01T00:00:00Z',
  ...over,
});

describe('IntelPanel', () => {
  it('renders the aggregate verdict and per-provider rows on success', async () => {
    server.use(
      http.get(apiUrl('/attackers/a-1/intel'), () => HttpResponse.json(intel())),
    );
    render(<IntelPanel uuid="a-1" />);
    await waitFor(() => expect(screen.getByText('MALICIOUS')).toBeInTheDocument());
    expect(screen.getByText('GREYNOISE')).toBeInTheDocument();
    expect(screen.getByText('ABUSEIPDB')).toBeInTheDocument();
    expect(screen.getByText('FEODO TRACKER')).toBeInTheDocument();
    expect(screen.getByText('THREATFOX')).toBeInTheDocument();
    expect(screen.getByText('90/100')).toBeInTheDocument();
    expect(screen.getByText(/known C2/)).toBeInTheDocument();
    expect(screen.getByText(/Emotet/)).toBeInTheDocument();
  });

  it('shows the absent placeholder on 404', async () => {
    server.use(
      http.get(apiUrl('/attackers/a-1/intel'), () =>
        HttpResponse.json({ detail: 'not cached' }, { status: 404 }),
      ),
    );
    render(<IntelPanel uuid="a-1" />);
    await waitFor(() =>
      expect(screen.getByText(/NO INTEL CACHED YET/)).toBeInTheDocument(),
    );
  });

  it('shows the error placeholder on 500', async () => {
    server.use(
      http.get(apiUrl('/attackers/a-1/intel'), () =>
        HttpResponse.json({ detail: 'boom' }, { status: 500 }),
      ),
    );
    render(<IntelPanel uuid="a-1" />);
    await waitFor(() =>
      expect(screen.getByText('FAILED TO LOAD INTEL')).toBeInTheDocument(),
    );
  });
});

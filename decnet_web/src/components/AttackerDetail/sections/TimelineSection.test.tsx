import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { makeAttacker } from '../../../test/fixtures';
import { TimelineSection } from './TimelineSection';

describe('TimelineSection', () => {
  it('renders the labelled timestamp + ASN + reverse-DNS rows', () => {
    render(
      <TimelineSection
        attacker={makeAttacker({
          asn: 12345,
          as_name: 'EXAMPLE-AS',
          asn_source: 'ipinfo',
          ptr_record: 'host.example.com',
        })}
        open={true}
        onToggle={() => {}}
      />,
    );
    expect(screen.getByText('FIRST SEEN:')).toBeInTheDocument();
    expect(screen.getByText('LAST SEEN:')).toBeInTheDocument();
    expect(screen.getByText(/AS12345/)).toBeInTheDocument();
    expect(screen.getByText('host.example.com')).toBeInTheDocument();
  });

  it('renders "unknown" when origin and ASN are absent', () => {
    render(
      <TimelineSection
        attacker={makeAttacker({ country_code: null, asn: null })}
        open={true}
        onToggle={() => {}}
      />,
    );
    expect(screen.getAllByText('unknown')).toHaveLength(2);
  });

  it('renders the ROTATION badge when ip_leaks total >= 20', () => {
    render(
      <TimelineSection
        attacker={makeAttacker({
          ip_leaks: [
            {
              timestamp: '2026-05-01T10:00:00Z',
              bounty_type: 'xff_leak',
              payload: { real_ip_claim: '1.1.1.1', source_header: 'X-Forwarded-For' },
            },
          ],
          ip_leaks_total: 42,
        })}
        open={true}
        onToggle={() => {}}
      />,
    );
    expect(screen.getByText(/ROTATION · 42/)).toBeInTheDocument();
  });

  it('does NOT render leaked-IPs row when ip_leaks is empty', () => {
    render(
      <TimelineSection
        attacker={makeAttacker()}
        open={true}
        onToggle={() => {}}
      />,
    );
    expect(screen.queryByText(/LEAKED IPs/)).not.toBeInTheDocument();
  });

  it('hides body content when open=false', () => {
    render(
      <TimelineSection
        attacker={makeAttacker()}
        open={false}
        onToggle={() => {}}
      />,
    );
    expect(screen.queryByText('FIRST SEEN:')).not.toBeInTheDocument();
  });

  it('fires onToggle when the section header is clicked', async () => {
    const onToggle = vi.fn();
    const user = userEvent.setup();
    render(
      <TimelineSection
        attacker={makeAttacker()}
        open={true}
        onToggle={onToggle}
      />,
    );
    await user.click(screen.getByText('TIMELINE'));
    expect(onToggle).toHaveBeenCalledTimes(1);
  });
});

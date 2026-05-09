/**
 * @vitest-environment jsdom
 */
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import {
  FingerprintGroup, FpUserAgent, FpHttpQuirks, FpResumption,
  FpCertificate, FpSpoofedSource, FpTcpStack,
} from './renderers';

describe('FpUserAgent', () => {
  it('renders the value, category tag, and any signals', () => {
    render(
      <FpUserAgent
        p={{
          value: 'sqlmap/1.7',
          category: 'scanner',
          tool: 'sqlmap',
          signals: ['injection_like', 'suspicious_short'],
        }}
      />,
    );
    expect(screen.getByText('sqlmap/1.7')).toBeInTheDocument();
    expect(screen.getByText('SCANNER')).toBeInTheDocument();
    expect(screen.getByText('SQLMAP')).toBeInTheDocument();
    expect(screen.getByText('INJECTION LIKE')).toBeInTheDocument();
  });

  it('shows the empty-UA placeholder when value is missing', () => {
    render(<FpUserAgent p={{ category: 'empty' }} />);
    expect(screen.getByText(/empty User-Agent/)).toBeInTheDocument();
    expect(screen.getByText('EMPTY')).toBeInTheDocument();
  });
});

describe('FpHttpQuirks', () => {
  it('renders order hash, casing hash, and stable header count', () => {
    render(
      <FpHttpQuirks
        p={{
          order_hash: 'aaaaaaaabbbbbbbbcccccccc',
          casing_hash: 'dddddddd',
          tool_guess: 'curl',
          casing_category: 'all_lower',
          stable_count: 7,
          order: ['Host', 'User-Agent', 'Accept'],
        }}
      />,
    );
    expect(screen.getByText('CURL')).toBeInTheDocument();
    expect(screen.getByText('CASE · ALL_LOWER')).toBeInTheDocument();
    expect(screen.getByText('7 STABLE HEADERS')).toBeInTheDocument();
  });
});

describe('FpResumption', () => {
  it('parses comma-separated mechanisms into upper-case tags', () => {
    render(<FpResumption p={{ mechanisms: 'session_id,session_ticket' }} />);
    expect(screen.getByText('SESSION ID')).toBeInTheDocument();
    expect(screen.getByText('SESSION TICKET')).toBeInTheDocument();
  });

  it('accepts an array of mechanisms', () => {
    render(<FpResumption p={{ mechanisms: ['psk'] }} />);
    expect(screen.getByText('PSK')).toBeInTheDocument();
  });
});

describe('FpCertificate', () => {
  it('renders a self-signed badge and shortened sha-256', () => {
    render(
      <FpCertificate
        p={{
          subject_cn: 'evil.example',
          self_signed: 'true',
          cert_sha256: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        }}
      />,
    );
    expect(screen.getByText('SELF-SIGNED')).toBeInTheDocument();
    expect(screen.getByText('evil.example')).toBeInTheDocument();
    expect(screen.getByText(/abcdef1234567890…/)).toBeInTheDocument();
  });
});

describe('FpSpoofedSource', () => {
  it('renders the WAF-bypass tag and claim category', () => {
    render(
      <FpSpoofedSource
        p={{
          claimed_ip: '1.1.1.1',
          source_header: 'X-Forwarded-For',
          claim_category: 'rfc1918',
          source_ip: '8.8.8.8',
        }}
      />,
    );
    expect(screen.getByText('WAF-BYPASS ATTEMPT')).toBeInTheDocument();
    expect(screen.getByText('RFC1918')).toBeInTheDocument();
    expect(screen.getByText(/8\.8\.8\.8/)).toBeInTheDocument();
  });
});

describe('FpTcpStack', () => {
  it('renders DF flag, SACK/TS toggles, and window scale', () => {
    render(
      <FpTcpStack
        p={{
          hash: 'tcp-hash',
          ttl: 64,
          window_size: 65535,
          df_bit: '1',
          sack_ok: '1',
          timestamp: '0',
          window_scale: '7',
        }}
      />,
    );
    expect(screen.getByText('DF')).toBeInTheDocument();
    expect(screen.getByText('SACK')).toBeInTheDocument();
    expect(screen.getByText('WSCALE:7')).toBeInTheDocument();
    expect(screen.queryByText('TS')).toBeNull();
  });
});

describe('FingerprintGroup', () => {
  it('dispatches by fpType and renders the canonical label', () => {
    render(
      <FingerprintGroup
        fpType="ja3"
        items={[{ payload: { ja3: 'aaaaaaaa', ja4: 'bbbbbbbb' } }]}
      />,
    );
    expect(screen.getByText('TLS FINGERPRINT')).toBeInTheDocument();
    expect(screen.getByText('aaaaaaaa')).toBeInTheDocument();
    expect(screen.getByText('bbbbbbbb')).toBeInTheDocument();
  });

  it('falls back to FpGeneric for unknown types', () => {
    render(
      <FingerprintGroup
        fpType="weird_unknown"
        items={[{ payload: { value: 'mystery-value' } }]}
      />,
    );
    expect(screen.getByText('WEIRD UNKNOWN')).toBeInTheDocument();
    expect(screen.getByText('mystery-value')).toBeInTheDocument();
  });
});

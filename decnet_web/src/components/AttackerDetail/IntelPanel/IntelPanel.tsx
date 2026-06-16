// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useState } from 'react';
import { AlertTriangle, Eye, Shield } from '../../../icons';
import api from '../../../utils/api';
import { fmtTs, VERDICT_TONE } from './helpers';
import type { IntelRow } from './types';

interface ProviderRowProps {
  name: string;
  queriedAt?: string | null;
  detail: React.ReactNode;
}

const ProviderRow: React.FC<ProviderRowProps> = ({ name, queriedAt, detail }) => (
  <div style={{
    display: 'grid',
    gridTemplateColumns: '160px 1fr auto',
    gap: '12px',
    padding: '10px 16px',
    borderTop: '1px solid var(--matrix-tint-5)',
    alignItems: 'center',
    fontSize: '0.85rem',
  }}>
    <div style={{ letterSpacing: '1px', opacity: 0.7 }}>{name}</div>
    <div>{detail}</div>
    <div style={{ opacity: 0.4, fontSize: '0.7rem', whiteSpace: 'nowrap' }}>
      {queriedAt ? fmtTs(queriedAt) : 'pending'}
    </div>
  </div>
);

export const IntelPanel: React.FC<{ uuid: string }> = ({ uuid }) => {
  const [intel, setIntel] = useState<IntelRow | null>(null);
  const [state, setState] = useState<'loading' | 'absent' | 'ok' | 'error'>('loading');

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setState('loading');
      try {
        const res = await api.get(`/attackers/${encodeURIComponent(uuid)}/intel`);
        if (!cancelled) {
          setIntel(res.data);
          setState('ok');
        }
      } catch (err: unknown) {
        if (cancelled) return;
        const status = (err as { response?: { status?: number } })?.response?.status;
        if (status === 404) {
          setIntel(null);
          setState('absent');
        } else {
          setState('error');
        }
      }
    };
    load();
    return () => { cancelled = true; };
  }, [uuid]);

  if (state === 'loading') {
    return (
      <div style={{ padding: '24px', textAlign: 'center', opacity: 0.5 }}>
        QUERYING INTEL CACHE...
      </div>
    );
  }

  if (state === 'error') {
    return (
      <div style={{ padding: '24px', textAlign: 'center', opacity: 0.6, color: '#ff8080' }}>
        FAILED TO LOAD INTEL
      </div>
    );
  }

  if (state === 'absent' || !intel) {
    return (
      <div style={{ padding: '24px', textAlign: 'center', opacity: 0.5 }}>
        NO INTEL CACHED YET — `decnet enrich` will populate within {' '}
        <span style={{ opacity: 0.7 }}>~1 poll cycle</span> of next observation.
      </div>
    );
  }

  const tone = VERDICT_TONE[intel.aggregate_verdict || 'unknown'];

  return (
    <div>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: '14px 16px',
        borderBottom: '1px solid var(--matrix-tint-5)',
      }}>
        <Shield size={16} style={{ color: tone.color }} />
        <span style={{
          letterSpacing: '2px',
          fontWeight: 600,
          color: tone.color,
        }}>
          {tone.label}
        </span>
        <span style={{ opacity: 0.4, fontSize: '0.7rem' }}>
          aggregate verdict
        </span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '16px', fontSize: '0.7rem', opacity: 0.5 }}>
          <span>cached {fmtTs(intel.cached_at)}</span>
          <span>expires {fmtTs(intel.expires_at)}</span>
        </div>
      </div>

      <ProviderRow
        name="GREYNOISE"
        queriedAt={intel.greynoise_queried_at}
        detail={
          intel.greynoise_classification ? (
            <span>
              classification: <span style={{ color: VERDICT_TONE[intel.greynoise_classification]?.color || 'inherit' }}>
                {intel.greynoise_classification}
              </span>
            </span>
          ) : (
            <span style={{ opacity: 0.4 }}>no answer</span>
          )
        }
      />

      <ProviderRow
        name="ABUSEIPDB"
        queriedAt={intel.abuseipdb_queried_at}
        detail={
          intel.abuseipdb_score !== null && intel.abuseipdb_score !== undefined ? (
            <span>
              abuse confidence:{' '}
              <span style={{
                color: intel.abuseipdb_score >= 75 ? VERDICT_TONE.malicious.color
                     : intel.abuseipdb_score >= 25 ? VERDICT_TONE.suspicious.color
                     : VERDICT_TONE.benign.color,
                fontWeight: 600,
              }}>
                {intel.abuseipdb_score}/100
              </span>
            </span>
          ) : (
            <span style={{ opacity: 0.4 }}>no answer</span>
          )
        }
      />

      <ProviderRow
        name="FEODO TRACKER"
        queriedAt={intel.feodo_queried_at}
        detail={
          intel.feodo_listed === true ? (
            <span style={{ color: VERDICT_TONE.malicious.color, fontWeight: 600 }}>
              <AlertTriangle size={12} style={{ verticalAlign: 'middle' }} /> known C2
              {intel.feodo_raw?.malware && (
                <span style={{ opacity: 0.7, marginLeft: '8px', fontWeight: 400 }}>
                  ({intel.feodo_raw.malware})
                </span>
              )}
            </span>
          ) : intel.feodo_listed === false ? (
            <span style={{ opacity: 0.5 }}>not on C2 blocklist</span>
          ) : (
            <span style={{ opacity: 0.4 }}>no answer</span>
          )
        }
      />

      <ProviderRow
        name="THREATFOX"
        queriedAt={intel.threatfox_queried_at}
        detail={
          intel.threatfox_listed === true ? (
            <span style={{ color: VERDICT_TONE.malicious.color, fontWeight: 600 }}>
              <Eye size={12} style={{ verticalAlign: 'middle' }} /> IOC match
              {Array.isArray(intel.threatfox_raw) && intel.threatfox_raw[0]?.malware && (
                <span style={{ opacity: 0.7, marginLeft: '8px', fontWeight: 400 }}>
                  ({intel.threatfox_raw[0].malware})
                </span>
              )}
            </span>
          ) : intel.threatfox_listed === false ? (
            <span style={{ opacity: 0.5 }}>no IOC match</span>
          ) : (
            <span style={{ opacity: 0.4 }}>no answer</span>
          )
        }
      />
    </div>
  );
};

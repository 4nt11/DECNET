import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Crosshair, Fingerprint, Globe, Radio } from '../icons';
import api from '../utils/api';
import { useIdentityStream } from './useIdentityStream';
import './Dashboard.css';

/*
 * IdentityDetail — read-only view of a resolved attacker identity.
 *
 * The clusterer worker that populates these rows is a separate
 * downstream effort; until it ships, /identities/* responses are
 * empty and this page renders the not-found state. See
 * development/IDENTITY_RESOLUTION.md.
 *
 * The page is intentionally narrow at v1: header (uuid + campaign
 * link if assigned), aggregated stats (observation count, fingerprint
 * counts), and a list of linked observations that link back to
 * AttackerDetail. Bigger surfaces (intel summary, kd_digraph_simhash
 * neighbors, federation gossip status) ship after the clusterer
 * lands and there's data to render.
 */

interface IdentityData {
  uuid: string;
  schema_version: number;
  campaign_id: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  created_at: string;
  updated_at: string;
  confidence: number | null;
  observation_count: number;
  observation_count_live: number;
  ja3_hashes: string | null;
  hassh_hashes: string | null;
  payload_simhashes: string | null;
  c2_endpoints: string | null;
  kd_digraph_simhash: string | null;
  merged_into_uuid: string | null;
  notes: string | null;
}

interface ObservationRow {
  uuid: string;
  ip: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  asn?: number | null;
  country_code?: string | null;
}

const safeParseJsonList = (raw: string | null): string[] => {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};

const IdentityDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [identity, setIdentity] = useState<IdentityData | null>(null);
  const [observations, setObservations] = useState<ObservationRow[]>([]);
  const [observationTotal, setObservationTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    const fetchIdentity = async () => {
      setLoading(true);
      try {
        const res = await api.get(`/identities/${id}`);
        setIdentity(res.data);
        setError(null);
      } catch (err: any) {
        if (err.response?.status === 404) {
          setError('IDENTITY NOT FOUND');
        } else {
          setError('FAILED TO LOAD IDENTITY');
        }
      } finally {
        setLoading(false);
      }
    };
    fetchIdentity();
  }, [id]);

  useEffect(() => {
    if (!id) return;
    const fetchObservations = async () => {
      try {
        const res = await api.get(`/identities/${id}/observations?limit=50&offset=0`);
        setObservations(res.data.data ?? []);
        setObservationTotal(res.data.total ?? 0);
      } catch {
        setObservations([]);
        setObservationTotal(0);
      }
    };
    fetchObservations();
  }, [id]);

  // Live updates: when the clusterer fires an identity event that
  // touches this identity (links a fresh observation, soft-merges,
  // resurrects on unmerge), refetch both the row and the observations
  // list so the page reflects current truth without a manual refresh.
  useIdentityStream({
    enabled: !!id,
    onEvent: (ev) => {
      if (!id) return;
      const payload = ev.payload || {};
      const refs = new Set<string>();
      const addUuid = (v: unknown) => {
        if (typeof v === 'string') refs.add(v);
      };
      addUuid(payload.identity_uuid);
      addUuid(payload.winner_uuid);
      addUuid(payload.loser_uuid);
      addUuid(payload.resurrected_uuid);
      addUuid(payload.former_winner_uuid);

      if (refs.has(id)) {
        api.get(`/identities/${id}`)
          .then((res) => setIdentity(res.data))
          .catch(() => {});
        api.get(`/identities/${id}/observations?limit=50&offset=0`)
          .then((res) => {
            setObservations(res.data.data ?? []);
            setObservationTotal(res.data.total ?? 0);
          })
          .catch(() => {});
      }
    },
  });

  if (loading) {
    return (
      <div className="dashboard">
        <div style={{ textAlign: 'center', padding: '80px', opacity: 0.5, letterSpacing: '4px' }}>
          LOADING IDENTITY…
        </div>
      </div>
    );
  }

  if (error || !identity) {
    return (
      <div className="dashboard">
        <button onClick={() => navigate('/attackers')} className="back-button">
          <ArrowLeft size={18} />
          <span>BACK TO ATTACKERS</span>
        </button>
        <div style={{ textAlign: 'center', padding: '80px', opacity: 0.5, letterSpacing: '4px' }}>
          {error || 'IDENTITY NOT FOUND'}
        </div>
      </div>
    );
  }

  const ja3List = safeParseJsonList(identity.ja3_hashes);
  const hasshList = safeParseJsonList(identity.hassh_hashes);
  const payloadList = safeParseJsonList(identity.payload_simhashes);
  const c2List = safeParseJsonList(identity.c2_endpoints);

  return (
    <div className="dashboard">
      <button onClick={() => navigate('/attackers')} className="back-button">
        <ArrowLeft size={18} />
        <span>BACK TO ATTACKERS</span>
      </button>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <Fingerprint size={32} className="violet-accent" />
        <h1 className="matrix-text" style={{ fontSize: '1.4rem', letterSpacing: '2px' }}>
          IDENTITY · {identity.uuid}
        </h1>
        {identity.campaign_id && (
          <span
            className="traversal-badge"
            style={{ fontSize: '0.8rem', cursor: 'default', letterSpacing: '2px' }}
            title="Campaign assignment from the campaign clusterer"
          >
            CAMPAIGN · {identity.campaign_id.slice(0, 8)}
          </span>
        )}
        {identity.merged_into_uuid && (
          <span
            className="traversal-badge"
            style={{ fontSize: '0.8rem', cursor: 'pointer', letterSpacing: '2px', opacity: 0.7 }}
            title="This identity was soft-merged into another. Click to view the canonical winner."
            onClick={() => navigate(`/identities/${identity.merged_into_uuid}`)}
          >
            MERGED INTO {identity.merged_into_uuid.slice(0, 8)}
          </span>
        )}
      </div>

      {/* Stats row */}
      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)' }}>
        <div className="stat-card" title="Live count of attacker observations FK'd to this identity">
          <div className="stat-value matrix-text">{identity.observation_count_live}</div>
          <div className="stat-label">OBSERVATIONS</div>
        </div>
        <div className="stat-card" title="Distinct JA3 TLS fingerprints across this identity's tooling">
          <div className="stat-value violet-accent">{ja3List.length}</div>
          <div className="stat-label">JA3</div>
        </div>
        <div className="stat-card" title="Distinct HASSH SSH-client fingerprints">
          <div className="stat-value violet-accent">{hasshList.length}</div>
          <div className="stat-label">HASSH</div>
        </div>
        <div className="stat-card" title="Distinct payload SimHashes (Hamming-comparable)">
          <div className="stat-value matrix-text">{payloadList.length}</div>
          <div className="stat-label">PAYLOADS</div>
        </div>
        <div className="stat-card" title="C2 callback endpoints observed">
          <div className="stat-value matrix-text">{c2List.length}</div>
          <div className="stat-label">C2 ENDPOINTS</div>
        </div>
      </div>

      {/* Confidence + schema version, only show if populated */}
      {(identity.confidence !== null || identity.schema_version > 1) && (
        <div style={{ display: 'flex', gap: '24px', padding: '12px 0', opacity: 0.7, fontSize: '0.85rem' }}>
          {identity.confidence !== null && (
            <span title="Identity-cohesion score from the clusterer (0–1)">
              CONFIDENCE · {identity.confidence.toFixed(3)}
            </span>
          )}
          <span title="Federation gossip schema version">
            SCHEMA · v{identity.schema_version}
          </span>
        </div>
      )}

      {/* Fingerprint detail rows */}
      {ja3List.length > 0 && (
        <FingerprintList icon={<Globe size={18} />} label="JA3" items={ja3List} />
      )}
      {hasshList.length > 0 && (
        <FingerprintList icon={<Globe size={18} />} label="HASSH" items={hasshList} />
      )}
      {c2List.length > 0 && (
        <FingerprintList icon={<Radio size={18} />} label="C2 ENDPOINTS" items={c2List} />
      )}

      {/* Observations table */}
      <div style={{ marginTop: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
          <Crosshair size={20} className="violet-accent" />
          <h2 className="matrix-text" style={{ fontSize: '1.0rem', letterSpacing: '2px' }}>
            OBSERVATIONS · {observationTotal}
          </h2>
        </div>
        {observations.length === 0 ? (
          <div style={{ padding: '24px', opacity: 0.5, fontFamily: 'var(--font-mono)' }}>
            No observations linked yet. The clusterer assigns observations
            asynchronously; they should appear shortly after the next
            clusterer pass.
          </div>
        ) : (
          <table className="data-table" style={{ width: '100%' }}>
            <thead>
              <tr>
                <th>IP</th>
                <th>FIRST SEEN</th>
                <th>LAST SEEN</th>
                <th style={{ textAlign: 'right' }}>EVENTS</th>
              </tr>
            </thead>
            <tbody>
              {observations.map((obs) => (
                <tr
                  key={obs.uuid}
                  style={{ cursor: 'pointer' }}
                  onClick={() => navigate(`/attackers/${obs.uuid}`)}
                >
                  <td>{obs.ip}</td>
                  <td style={{ opacity: 0.7 }}>{obs.first_seen}</td>
                  <td style={{ opacity: 0.7 }}>{obs.last_seen}</td>
                  <td style={{ textAlign: 'right' }}>{obs.event_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {identity.notes && (
        <div style={{ marginTop: '24px', padding: '12px', borderLeft: '2px solid var(--violet)', opacity: 0.85 }}>
          <div style={{ fontSize: '0.75rem', opacity: 0.7, letterSpacing: '2px', marginBottom: '4px' }}>
            ANALYST NOTES
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap' }}>
            {identity.notes}
          </div>
        </div>
      )}
    </div>
  );
};

const FingerprintList: React.FC<{
  icon: React.ReactNode;
  label: string;
  items: string[];
}> = ({ icon, label, items }) => (
  <div style={{ marginTop: '16px' }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
      {icon}
      <span className="matrix-text" style={{ fontSize: '0.85rem', letterSpacing: '2px' }}>
        {label}
      </span>
    </div>
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
      {items.map((v) => (
        <code
          key={v}
          style={{
            fontSize: '0.75rem',
            padding: '4px 8px',
            background: 'var(--card-bg)',
            border: '1px solid var(--border-color)',
            borderRadius: '2px',
          }}
        >
          {v}
        </code>
      ))}
    </div>
  </div>
);

export default IdentityDetail;

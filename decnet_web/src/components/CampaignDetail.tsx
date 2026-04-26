import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Crosshair, Fingerprint, Globe, Radio } from '../icons';
import api from '../utils/api';
import { useCampaignStream } from './useCampaignStream';
import './Dashboard.css';

/*
 * CampaignDetail — read-only view of a campaign-clustered operation.
 *
 * The layer above identity resolution. Member identities are visible
 * here as rows that link back to IdentityDetail. Same visual vocabulary
 * as IdentityDetail by design — the substrate (soft merges, schema
 * version, JSON fingerprint summaries, live SSE updates) is identical
 * one layer up.
 */

interface CampaignData {
  uuid: string;
  schema_version: number;
  first_seen_at: string | null;
  last_seen_at: string | null;
  created_at: string;
  updated_at: string;
  confidence: number | null;
  identity_count: number;
  identity_count_live: number;
  ja3_hashes: string | null;
  hassh_hashes: string | null;
  payload_simhashes: string | null;
  c2_endpoints: string | null;
  merged_into_uuid: string | null;
  notes: string | null;
}

interface IdentityRow {
  uuid: string;
  first_seen_at: string | null;
  last_seen_at: string | null;
  observation_count: number;
  campaign_id: string | null;
  merged_into_uuid: string | null;
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

const CampaignDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [campaign, setCampaign] = useState<CampaignData | null>(null);
  const [identities, setIdentities] = useState<IdentityRow[]>([]);
  const [identityTotal, setIdentityTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    const fetchCampaign = async () => {
      setLoading(true);
      try {
        const res = await api.get(`/campaigns/${id}`);
        setCampaign(res.data);
        setError(null);
      } catch (err: any) {
        if (err.response?.status === 404) {
          setError('CAMPAIGN NOT FOUND');
        } else {
          setError('FAILED TO LOAD CAMPAIGN');
        }
      } finally {
        setLoading(false);
      }
    };
    fetchCampaign();
  }, [id]);

  useEffect(() => {
    if (!id) return;
    const fetchIdentities = async () => {
      try {
        const res = await api.get(`/campaigns/${id}/identities?limit=50&offset=0`);
        setIdentities(res.data.data ?? []);
        setIdentityTotal(res.data.total ?? 0);
      } catch {
        setIdentities([]);
        setIdentityTotal(0);
      }
    };
    fetchIdentities();
  }, [id]);

  // Live updates: refetch when a campaign event references this uuid.
  useCampaignStream({
    enabled: !!id,
    onEvent: (ev) => {
      if (!id) return;
      const payload = ev.payload || {};
      const refs = new Set<string>();
      const addUuid = (v: unknown) => {
        if (typeof v === 'string') refs.add(v);
      };
      addUuid(payload.campaign_uuid);
      addUuid(payload.winner_uuid);
      addUuid(payload.loser_uuid);
      addUuid(payload.resurrected_uuid);
      addUuid(payload.former_winner_uuid);

      if (refs.has(id)) {
        api.get(`/campaigns/${id}`)
          .then((res) => setCampaign(res.data))
          .catch(() => {});
        api.get(`/campaigns/${id}/identities?limit=50&offset=0`)
          .then((res) => {
            setIdentities(res.data.data ?? []);
            setIdentityTotal(res.data.total ?? 0);
          })
          .catch(() => {});
      }
    },
  });

  if (loading) {
    return (
      <div className="dashboard">
        <div style={{ textAlign: 'center', padding: '80px', opacity: 0.5, letterSpacing: '4px' }}>
          LOADING CAMPAIGN…
        </div>
      </div>
    );
  }

  if (error || !campaign) {
    return (
      <div className="dashboard">
        <button onClick={() => navigate('/attackers')} className="back-button">
          <ArrowLeft size={18} />
          <span>BACK TO ATTACKERS</span>
        </button>
        <div style={{ textAlign: 'center', padding: '80px', opacity: 0.5, letterSpacing: '4px' }}>
          {error || 'CAMPAIGN NOT FOUND'}
        </div>
      </div>
    );
  }

  const ja3List = safeParseJsonList(campaign.ja3_hashes);
  const hasshList = safeParseJsonList(campaign.hassh_hashes);
  const payloadList = safeParseJsonList(campaign.payload_simhashes);
  const c2List = safeParseJsonList(campaign.c2_endpoints);

  return (
    <div className="dashboard">
      <button onClick={() => navigate('/attackers')} className="back-button">
        <ArrowLeft size={18} />
        <span>BACK TO ATTACKERS</span>
      </button>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <Fingerprint size={32} className="violet-accent" />
        <h1 className="matrix-text" style={{ fontSize: '1.4rem', letterSpacing: '2px' }}>
          CAMPAIGN · {campaign.uuid}
        </h1>
        {campaign.merged_into_uuid && (
          <span
            className="traversal-badge"
            style={{ fontSize: '0.8rem', cursor: 'pointer', letterSpacing: '2px', opacity: 0.7 }}
            title="This campaign was soft-merged into another. Click to view the canonical winner."
            onClick={() => navigate(`/campaigns/${campaign.merged_into_uuid}`)}
          >
            MERGED INTO {campaign.merged_into_uuid.slice(0, 8)}
          </span>
        )}
      </div>

      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)' }}>
        <div className="stat-card" title="Live count of identities FK'd to this campaign">
          <div className="stat-value matrix-text">{campaign.identity_count_live}</div>
          <div className="stat-label">IDENTITIES</div>
        </div>
        <div className="stat-card" title="Distinct JA3 fingerprints across member identities">
          <div className="stat-value violet-accent">{ja3List.length}</div>
          <div className="stat-label">JA3</div>
        </div>
        <div className="stat-card" title="Distinct HASSH fingerprints">
          <div className="stat-value violet-accent">{hasshList.length}</div>
          <div className="stat-label">HASSH</div>
        </div>
        <div className="stat-card" title="Distinct payload SimHashes aggregated across identities">
          <div className="stat-value matrix-text">{payloadList.length}</div>
          <div className="stat-label">PAYLOADS</div>
        </div>
        <div className="stat-card" title="C2 callback endpoints aggregated across identities">
          <div className="stat-value matrix-text">{c2List.length}</div>
          <div className="stat-label">C2 ENDPOINTS</div>
        </div>
      </div>

      {(campaign.confidence !== null || campaign.schema_version > 1) && (
        <div style={{ display: 'flex', gap: '24px', padding: '12px 0', opacity: 0.7, fontSize: '0.85rem' }}>
          {campaign.confidence !== null && (
            <span title="Campaign-cohesion score from the clusterer (0–1)">
              CONFIDENCE · {campaign.confidence.toFixed(3)}
            </span>
          )}
          <span title="Federation gossip schema version">
            SCHEMA · v{campaign.schema_version}
          </span>
        </div>
      )}

      {ja3List.length > 0 && (
        <FingerprintList icon={<Globe size={18} />} label="JA3" items={ja3List} />
      )}
      {hasshList.length > 0 && (
        <FingerprintList icon={<Globe size={18} />} label="HASSH" items={hasshList} />
      )}
      {c2List.length > 0 && (
        <FingerprintList icon={<Radio size={18} />} label="C2 ENDPOINTS" items={c2List} />
      )}

      <div style={{ marginTop: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
          <Crosshair size={20} className="violet-accent" />
          <h2 className="matrix-text" style={{ fontSize: '1.0rem', letterSpacing: '2px' }}>
            IDENTITIES · {identityTotal}
          </h2>
        </div>
        {identities.length === 0 ? (
          <div style={{ padding: '24px', opacity: 0.5, fontFamily: 'var(--font-mono)' }}>
            No identities linked yet. The campaign clusterer assigns
            identities asynchronously; they should appear shortly after
            the next clusterer pass.
          </div>
        ) : (
          <table className="data-table" style={{ width: '100%' }}>
            <thead>
              <tr>
                <th>IDENTITY</th>
                <th>FIRST SEEN</th>
                <th>LAST SEEN</th>
                <th style={{ textAlign: 'right' }}>OBSERVATIONS</th>
              </tr>
            </thead>
            <tbody>
              {identities.map((ident) => (
                <tr
                  key={ident.uuid}
                  style={{ cursor: 'pointer' }}
                  onClick={() => navigate(`/identities/${ident.uuid}`)}
                >
                  <td>{ident.uuid.slice(0, 12)}…</td>
                  <td style={{ opacity: 0.7 }}>{ident.first_seen_at ?? '—'}</td>
                  <td style={{ opacity: 0.7 }}>{ident.last_seen_at ?? '—'}</td>
                  <td style={{ textAlign: 'right' }}>{ident.observation_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {campaign.notes && (
        <div style={{ marginTop: '24px', padding: '12px', borderLeft: '2px solid var(--violet)', opacity: 0.85 }}>
          <div style={{ fontSize: '0.75rem', opacity: 0.7, letterSpacing: '2px', marginBottom: '4px' }}>
            ANALYST NOTES
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap' }}>
            {campaign.notes}
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

export default CampaignDetail;

// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Crosshair, Filter, Fingerprint, Globe, Radio } from '../icons';
import api from '../utils/api';
import EmptyState from './EmptyState/EmptyState';
import { useCampaignStream } from './useCampaignStream';
import './Dashboard.css';

/*
 * CampaignDetail — read-only view of a campaign-clustered operation.
 *
 * Layer above identity resolution. Member identities link back to
 * IdentityDetail; same visual vocabulary as the rest of the app
 * (page-header / sections / chips), no inline-style drift.
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

  // Refetch when a campaign event references this uuid.
  useCampaignStream({
    enabled: !!id,
    onEvent: (ev) => {
      if (!id) return;
      const refs = new Set<string>();
      const addUuid = (v: unknown) => {
        if (typeof v === 'string') refs.add(v);
      };
      const payload = ev.payload || {};
      addUuid(payload.campaign_uuid);
      addUuid(payload.winner_uuid);
      addUuid(payload.loser_uuid);
      addUuid(payload.resurrected_uuid);
      addUuid(payload.former_winner_uuid);
      if (refs.has(id)) {
        api.get(`/campaigns/${id}`).then((res) => setCampaign(res.data)).catch(() => {});
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
      <div className="bounty-root">
        <EmptyState icon={Crosshair} title="LOADING CAMPAIGN…" />
      </div>
    );
  }

  if (error || !campaign) {
    return (
      <div className="bounty-root">
        <button onClick={() => navigate('/campaigns')} className="back-button">
          <ArrowLeft size={18} />
          <span>BACK TO CAMPAIGNS</span>
        </button>
        <EmptyState icon={Crosshair} title={error || 'CAMPAIGN NOT FOUND'} />
      </div>
    );
  }

  const ja3List = safeParseJsonList(campaign.ja3_hashes);
  const hasshList = safeParseJsonList(campaign.hassh_hashes);
  const payloadList = safeParseJsonList(campaign.payload_simhashes);
  const c2List = safeParseJsonList(campaign.c2_endpoints);

  return (
    <div className="bounty-root">
      <button onClick={() => navigate('/campaigns')} className="back-button">
        <ArrowLeft size={18} />
        <span>BACK TO CAMPAIGNS</span>
      </button>

      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <Crosshair size={22} className="violet-accent" />
            <h1>CAMPAIGN · {campaign.uuid.slice(0, 12)}…</h1>
            {campaign.merged_into_uuid && (
              <span
                className="chip dim-chip"
                style={{ cursor: 'pointer' }}
                onClick={() => navigate(`/campaigns/${campaign.merged_into_uuid}`)}
                title="Soft-merged. Click to view canonical winner."
              >
                MERGED → {campaign.merged_into_uuid.slice(0, 8)}…
              </span>
            )}
          </div>
          <span className="page-sub">
            {campaign.identity_count_live} IDENTITIES ·
            {' '}{ja3List.length} JA3 · {hasshList.length} HASSH ·
            {' '}{payloadList.length} PAYLOAD · {c2List.length} C2
            {campaign.confidence !== null && (
              <> · CONFIDENCE {campaign.confidence.toFixed(3)}</>
            )}
            {' '}· SCHEMA v{campaign.schema_version}
          </span>
        </div>
      </div>

      {(ja3List.length > 0 || hasshList.length > 0 || c2List.length > 0) && (
        <div className="logs-section">
          <div className="section-header">
            <div className="section-title">
              <Fingerprint size={14} />
              <span>AGGREGATED FINGERPRINTS</span>
            </div>
          </div>
          <div className="logs-table-container" style={{ padding: 12 }}>
            {ja3List.length > 0 && (
              <FingerprintGroup icon={<Globe size={14} />} label="JA3" items={ja3List} />
            )}
            {hasshList.length > 0 && (
              <FingerprintGroup icon={<Globe size={14} />} label="HASSH" items={hasshList} />
            )}
            {c2List.length > 0 && (
              <FingerprintGroup icon={<Radio size={14} />} label="C2 ENDPOINTS" items={c2List} />
            )}
          </div>
        </div>
      )}

      <div className="logs-section">
        <div className="section-header">
          <div className="section-title">
            <Filter size={14} />
            <span>{identityTotal} IDENTITIES IN THIS CAMPAIGN</span>
          </div>
        </div>
        <div className="logs-table-container">
          {identities.length === 0 ? (
            <EmptyState
              icon={Crosshair}
              title="NO IDENTITIES LINKED YET"
              hint="the campaign clusterer assigns identities asynchronously"
            />
          ) : (
            <table className="logs-table">
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
                    className="clickable"
                    onClick={() => navigate(`/identities/${ident.uuid}`)}
                  >
                    <td className="matrix-text" style={{ fontFamily: 'var(--font-mono)' }}>
                      {ident.uuid.slice(0, 12)}…
                    </td>
                    <td className="dim">{ident.first_seen_at ?? '—'}</td>
                    <td className="dim">{ident.last_seen_at ?? '—'}</td>
                    <td className="matrix-text" style={{ textAlign: 'right' }}>
                      {ident.observation_count}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {campaign.notes && (
        <div className="logs-section">
          <div className="section-header">
            <div className="section-title">
              <span>ANALYST NOTES</span>
            </div>
          </div>
          <div className="logs-table-container" style={{ padding: 12, fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap' }}>
            {campaign.notes}
          </div>
        </div>
      )}
    </div>
  );
};

const FingerprintGroup: React.FC<{
  icon: React.ReactNode;
  label: string;
  items: string[];
}> = ({ icon, label, items }) => (
  <div className="fp-group">
    <div className="fp-group-label">
      {icon}
      <span>{label}</span>
    </div>
    <div className="fp-group-items">
      {items.map((v) => (
        <span key={v} className="chip dim-chip">{v}</span>
      ))}
    </div>
  </div>
);

export default CampaignDetail;

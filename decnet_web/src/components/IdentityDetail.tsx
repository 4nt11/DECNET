// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Crosshair, Filter, Fingerprint, Globe, Radio } from '../icons';
import api from '../utils/api';
import EmptyState from './EmptyState/EmptyState';
import TTPsObservedSection from './TTPsObservedSection';
import { useIdentityStream } from './useIdentityStream';
import './Dashboard.css';

/*
 * IdentityDetail — read-only view of a resolved attacker identity.
 *
 * Header (page-header), aggregated stats in the sub-line, fingerprint
 * groups in their own section, observations in a logs-section table.
 * Same vocabulary as CampaignDetail one layer up.
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

  useIdentityStream({
    enabled: !!id,
    onEvent: (ev) => {
      if (!id) return;
      const refs = new Set<string>();
      const addUuid = (v: unknown) => {
        if (typeof v === 'string') refs.add(v);
      };
      const payload = ev.payload || {};
      addUuid(payload.identity_uuid);
      addUuid(payload.winner_uuid);
      addUuid(payload.loser_uuid);
      addUuid(payload.resurrected_uuid);
      addUuid(payload.former_winner_uuid);
      if (refs.has(id)) {
        api.get(`/identities/${id}`).then((res) => setIdentity(res.data)).catch(() => {});
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
      <div className="bounty-root">
        <EmptyState icon={Fingerprint} title="LOADING IDENTITY…" />
      </div>
    );
  }

  if (error || !identity) {
    return (
      <div className="bounty-root">
        <button onClick={() => navigate('/identities')} className="back-button">
          <ArrowLeft size={18} />
          <span>BACK TO IDENTITIES</span>
        </button>
        <EmptyState icon={Fingerprint} title={error || 'IDENTITY NOT FOUND'} />
      </div>
    );
  }

  const ja3List = safeParseJsonList(identity.ja3_hashes);
  const hasshList = safeParseJsonList(identity.hassh_hashes);
  const payloadList = safeParseJsonList(identity.payload_simhashes);
  const c2List = safeParseJsonList(identity.c2_endpoints);

  return (
    <div className="bounty-root">
      <button onClick={() => navigate('/identities')} className="back-button">
        <ArrowLeft size={18} />
        <span>BACK TO IDENTITIES</span>
      </button>

      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <Fingerprint size={22} className="violet-accent" />
            <h1>IDENTITY · {identity.uuid.slice(0, 12)}…</h1>
            {identity.campaign_id && (
              <span
                className="chip violet"
                style={{ cursor: 'pointer' }}
                onClick={() => navigate(`/campaigns/${identity.campaign_id}`)}
                title="Campaign assignment from the campaign clusterer"
              >
                CAMPAIGN · {identity.campaign_id.slice(0, 8)}…
              </span>
            )}
            {identity.merged_into_uuid && (
              <span
                className="chip dim-chip"
                style={{ cursor: 'pointer' }}
                onClick={() => navigate(`/identities/${identity.merged_into_uuid}`)}
                title="Soft-merged. Click to view canonical winner."
              >
                MERGED → {identity.merged_into_uuid.slice(0, 8)}…
              </span>
            )}
          </div>
          <span className="page-sub">
            {identity.observation_count_live} OBSERVATIONS ·
            {' '}{ja3List.length} JA3 · {hasshList.length} HASSH ·
            {' '}{payloadList.length} PAYLOAD · {c2List.length} C2
            {identity.confidence !== null && (
              <> · CONFIDENCE {identity.confidence.toFixed(3)}</>
            )}
            {' '}· SCHEMA v{identity.schema_version}
          </span>
        </div>
      </div>

      <TTPsObservedSection scope="identity" uuid={identity.uuid} />

      {(ja3List.length > 0 || hasshList.length > 0 || c2List.length > 0) && (
        <div className="logs-section">
          <div className="section-header">
            <div className="section-title">
              <Fingerprint size={14} />
              <span>FINGERPRINTS</span>
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
            <span>{observationTotal} OBSERVATIONS LINKED</span>
          </div>
        </div>
        <div className="logs-table-container">
          {observations.length === 0 ? (
            <EmptyState
              icon={Crosshair}
              title="NO OBSERVATIONS LINKED YET"
              hint="the clusterer assigns observations asynchronously"
            />
          ) : (
            <table className="logs-table">
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
                    className="clickable"
                    onClick={() => navigate(`/attackers/${obs.uuid}`)}
                  >
                    <td className="matrix-text">{obs.ip}</td>
                    <td className="dim">{obs.first_seen}</td>
                    <td className="dim">{obs.last_seen}</td>
                    <td className="matrix-text" style={{ textAlign: 'right' }}>
                      {obs.event_count}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {identity.notes && (
        <div className="logs-section">
          <div className="section-header">
            <div className="section-title">
              <span>ANALYST NOTES</span>
            </div>
          </div>
          <div className="logs-table-container" style={{ padding: 12, fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap' }}>
            {identity.notes}
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

export default IdentityDetail;

import React, { useEffect, useRef, useState } from 'react';
import { X, Crosshair } from '../icons';
import api from '../utils/api';
import { useEscapeKey } from '../hooks/useEscapeKey';
import { useFocusTrap } from '../hooks/useFocusTrap';
import './TTPInspector.css';

/*
 * TTPInspector — sidebar that explains *why* the rule engine flagged a
 * technique. Renders one card per `ttp_tag` row hitting the
 * (scope, uuid, technique_id, sub_technique_id?) selector, including
 * the rule_id, source_kind / source_id, confidence, and the persisted
 * `evidence` JSON the engine attached at fire time.
 *
 * Click target is :class:`TechniqueBar` in TTPsObservedSection. Drawer
 * geometry mirrors CredentialReuseInspector / BountyInspector.
 */

export interface TTPTagDetailRow {
  uuid: string;
  source_kind: string;
  source_id: string;
  attacker_uuid: string | null;
  identity_uuid: string | null;
  session_id: string | null;
  decky_id: string | null;
  tactic: string;
  technique_id: string;
  sub_technique_id: string | null;
  confidence: number;
  rule_id: string;
  rule_version: number;
  evidence: Record<string, unknown>;
  attack_release: string;
  created_at: string;
}

export type TTPInspectorScope = 'identity' | 'attacker' | 'session';

interface Props {
  scope: TTPInspectorScope;
  uuid: string;
  techniqueId: string;
  subTechniqueId: string | null;
  tactic: string;
  count: number;
  confidenceMax: number;
  onClose: () => void;
}

const TTPInspector: React.FC<Props> = ({
  scope, uuid, techniqueId, subTechniqueId, tactic, count, confidenceMax, onClose,
}) => {
  const panelRef = useRef<HTMLDivElement | null>(null);
  useEscapeKey(onClose, true);
  useFocusTrap(panelRef, true);
  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = prev; };
  }, []);

  const [rows, setRows] = useState<TTPTagDetailRow[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const fetch = async () => {
      try {
        const params: Record<string, string> = {};
        if (subTechniqueId) params.sub_technique_id = subTechniqueId;
        const path = `/ttp/tags/by-${scope}/${uuid}/${techniqueId}`;
        const res = await api.get(path, { params });
        if (cancelled) return;
        setRows(Array.isArray(res.data) ? res.data : []);
        setError(null);
      } catch (err: any) {
        if (cancelled) return;
        setRows([]);
        setError(
          err?.response?.status === 403 ? 'Insufficient role for tag detail.' :
          'Failed to load tag detail.',
        );
      } finally {
        if (!cancelled) setLoaded(true);
      }
    };
    fetch();
    return () => { cancelled = true; };
  }, [scope, uuid, techniqueId, subTechniqueId]);

  const label = subTechniqueId ?? techniqueId;

  return (
    <div
      className="ttp-drawer-backdrop"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="ttp-drawer" ref={panelRef}>
        <div className="bd-head">
          <h3>
            <Crosshair size={14} />
            <span>{label}</span>
          </h3>
          <button className="close-btn" onClick={onClose} aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <div className="bd-body">
          <div className="ttp-meta" style={{
            gridTemplateColumns: '110px 1fr',
            display: 'grid',
            gap: '4px 12px',
            fontSize: '0.75rem',
          }}>
            <div className="k" style={{ color: 'var(--dim-color)' }}>TACTIC</div>
            <div className="v">{tactic}</div>
            <div className="k" style={{ color: 'var(--dim-color)' }}>TECHNIQUE</div>
            <div className="v">{techniqueId}{subTechniqueId ? ` / ${subTechniqueId}` : ''}</div>
            <div className="k" style={{ color: 'var(--dim-color)' }}>FIRES</div>
            <div className="v">{count}</div>
            <div className="k" style={{ color: 'var(--dim-color)' }}>MAX CONF</div>
            <div className="v">{confidenceMax.toFixed(2)}</div>
          </div>

          <div>
            <div className="type-label">EVIDENCE</div>
            {!loaded ? null : error ? (
              <div className="ttp-empty">{error}</div>
            ) : rows.length === 0 ? (
              <div className="ttp-empty">No tag rows in scope.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {rows.map((row) => (
                  <TTPTagCard key={row.uuid} row={row} />
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

const TTPTagCard: React.FC<{ row: TTPTagDetailRow }> = ({ row }) => {
  const evidenceText = JSON.stringify(row.evidence ?? {}, null, 2);
  return (
    <div className="ttp-tag-card">
      <div className="ttp-card-head">
        <span className="ttp-rule-id">{row.rule_id} v{row.rule_version}</span>
        <span className="ttp-confidence">conf {row.confidence.toFixed(2)}</span>
      </div>
      <div className="ttp-meta">
        <div className="k">SOURCE</div>
        <div className="v">{row.source_kind} / {row.source_id}</div>
        {row.session_id && (
          <>
            <div className="k">SESSION</div>
            <div className="v">{row.session_id}</div>
          </>
        )}
        {row.decky_id && (
          <>
            <div className="k">DECKY</div>
            <div className="v">{row.decky_id}</div>
          </>
        )}
        <div className="k">SEEN</div>
        <div className="v">{new Date(row.created_at).toLocaleString()}</div>
        <div className="k">ATT&CK</div>
        <div className="v">{row.attack_release}</div>
      </div>
      <pre className="ttp-evidence">{evidenceText}</pre>
    </div>
  );
};

export default TTPInspector;

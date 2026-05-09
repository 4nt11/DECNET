import React, { useEffect, useRef, useState } from 'react';
import { X, Crosshair } from '../icons';
import { useEscapeKey } from '../hooks/useEscapeKey';
import { useFocusTrap } from '../hooks/useFocusTrap';
import { fetchTagsForTechnique, fetchGroupsForTechnique } from '../utils/ttpApi';
import type { TTPScope } from '../utils/ttpApi';
import type { GroupRef, TTPTagDetailRow } from '../types/ttp';
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

// Re-export so existing imports of TTPTagDetailRow from this file keep working.
export type { TTPTagDetailRow } from '../types/ttp';

export type TTPInspectorScope = TTPScope;

interface Props {
  scope: TTPInspectorScope;
  uuid: string;
  techniqueId: string;
  subTechniqueId: string | null;
  techniqueName: string | null;
  subTechniqueName: string | null;
  tactic: string;
  count: number;
  confidenceMax: number;
  mitre_url?: string | null;
  onClose: () => void;
}

function mitreUrlForId(tid: string): string {
  const [parent, sub] = tid.split('.');
  return sub
    ? `https://attack.mitre.org/techniques/${parent}/${sub}`
    : `https://attack.mitre.org/techniques/${parent}`;
}

const MitreLink: React.FC<{ tid: string; href?: string | null }> = ({ tid, href }) => {
  const url = href ?? mitreUrlForId(tid);
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      className="ttp-mitre-link"
      onClick={(e) => e.stopPropagation()}
    >
      {tid} ↗
    </a>
  );
};

const TTPInspector: React.FC<Props> = ({
  scope, uuid, techniqueId, subTechniqueId, techniqueName, subTechniqueName,
  tactic, count, confidenceMax, mitre_url, onClose,
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
    fetchTagsForTechnique(scope, uuid, techniqueId, subTechniqueId)
      .then((data) => { if (!cancelled) { setRows(data); setError(null); } })
      .catch((err: any) => {
        if (cancelled) return;
        setRows([]);
        setError(
          err?.response?.status === 403 ? 'Insufficient role for tag detail.' :
          'Failed to load tag detail.',
        );
      })
      .finally(() => { if (!cancelled) setLoaded(true); });
    return () => { cancelled = true; };
  }, [scope, uuid, techniqueId, subTechniqueId]);

  const [groups, setGroups] = useState<GroupRef[] | null>(null);
  const [groupsLoading, setGroupsLoading] = useState(false);
  const [groupsError, setGroupsError] = useState<string | null>(null);

  const groupTarget = subTechniqueId ?? techniqueId;
  useEffect(() => {
    let cancelled = false;
    setGroups(null);
    setGroupsError(null);
    setGroupsLoading(true);
    fetchGroupsForTechnique(groupTarget)
      .then((data) => { if (!cancelled) setGroups(data); })
      .catch((err: any) => {
        if (cancelled) return;
        setGroupsError(
          err?.response?.status === 404 ? 'Technique not found in ATT&CK bundle.' :
          'Failed to load groups.',
        );
      })
      .finally(() => { if (!cancelled) setGroupsLoading(false); });
    return () => { cancelled = true; };
  }, [groupTarget]);

  const id = subTechniqueId ?? techniqueId;
  const name = subTechniqueName ?? techniqueName;
  const headerLabel = name ? `${id} — ${name}` : id;

  return (
    <div
      className="ttp-drawer-backdrop"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="ttp-drawer" ref={panelRef}>
        <div className="bd-head">
          <h3>
            <Crosshair size={14} />
            <span>{headerLabel}</span>
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
            <div className="v">
              <MitreLink tid={techniqueId} href={subTechniqueId ? undefined : mitre_url} />
              {techniqueName ? ` — ${techniqueName}` : ''}
              {subTechniqueId && (
                <div style={{ marginTop: 2 }}>
                  ↳ <MitreLink tid={subTechniqueId} href={mitre_url} />
                  {subTechniqueName ? ` — ${subTechniqueName}` : ''}
                </div>
              )}
            </div>
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

          <div>
            <div className="type-label">GROUPS</div>
            {groupsLoading ? (
              <div className="ttp-empty">Loading groups…</div>
            ) : groupsError ? (
              <div className="ttp-empty">{groupsError}</div>
            ) : groups === null ? null : groups.length === 0 ? (
              <div className="ttp-empty">No MITRE-tracked groups documented for this technique.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {groups.map((g) => (
                  <div key={g.group_id} className="ttp-group-row">
                    {g.mitre_url ? (
                      <a
                        href={g.mitre_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="ttp-mitre-link"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {g.group_id} ↗
                      </a>
                    ) : (
                      <span className="ttp-group-id">{g.group_id}</span>
                    )}
                    <span className="ttp-group-name">{g.name}</span>
                    {g.aliases.length > 0 && (
                      <span className="ttp-group-aliases" title={g.aliases.join(', ')}>
                        {g.aliases.join(', ')}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// Evidence keys we promote to the top of the per-card key/value
// table for shell-command tags. Order matters — these render in
// the listed order; everything else goes after, alphabetically.
const _EVIDENCE_PRIMARY_ORDER = [
  'uid', 'user', 'src', 'pwd', 'cmd', 'command', 'command_text',
];

const _EVIDENCE_LABEL: Record<string, string> = {
  uid: 'UID',
  user: 'USER',
  src: 'SRC',
  pwd: 'PWD',
  cmd: 'CMD',
  command: 'CMD',
  command_text: 'CMD',
};

interface EvidenceRow {
  key: string;
  label: string;
  value: string;
}

function flattenEvidence(evidence: Record<string, unknown>): EvidenceRow[] {
  const seen = new Set<string>();
  const rows: EvidenceRow[] = [];
  const stringify = (v: unknown): string => {
    if (v === null || v === undefined) return '—';
    if (typeof v === 'string') return v;
    if (typeof v === 'number' || typeof v === 'boolean') return String(v);
    return JSON.stringify(v);
  };
  for (const k of _EVIDENCE_PRIMARY_ORDER) {
    if (k in evidence && !seen.has(k)) {
      seen.add(k);
      rows.push({
        key: k,
        label: _EVIDENCE_LABEL[k] ?? k.toUpperCase(),
        value: stringify(evidence[k]),
      });
    }
  }
  const remaining = Object.keys(evidence)
    .filter((k) => !seen.has(k))
    .sort();
  for (const k of remaining) {
    rows.push({
      key: k,
      label: _EVIDENCE_LABEL[k] ?? k.toUpperCase(),
      value: stringify(evidence[k]),
    });
  }
  return rows;
}

const TTPTagCard: React.FC<{ row: TTPTagDetailRow }> = ({ row }) => {
  const evidenceRows = flattenEvidence(row.evidence ?? {});
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
        <div className="v">
          {row.mitre_url ? (
            <a
              href={row.mitre_url}
              target="_blank"
              rel="noopener noreferrer"
              className="ttp-mitre-link"
            >
              {row.sub_technique_id ?? row.technique_id} ↗
            </a>
          ) : (row.sub_technique_id ?? row.technique_id)}
          {' '}{row.attack_release}
        </div>
      </div>
      {evidenceRows.length === 0 ? (
        <div className="ttp-empty" style={{ padding: '8px' }}>—</div>
      ) : (
        <div className="ttp-evidence-kvs">
          {evidenceRows.map((r) => (
            <React.Fragment key={r.key}>
              <div className="ttp-evidence-k">{r.label}</div>
              <div className="ttp-evidence-v">{r.value}</div>
            </React.Fragment>
          ))}
        </div>
      )}
    </div>
  );
};

export default TTPInspector;

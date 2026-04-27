import React, { useMemo } from 'react';
import { X, Cpu, Copy, ArrowRight } from '../icons';
import { useToast } from './Toasts/useToast';

export interface OrchestratorInspectorEntry {
  uuid: string;
  ts: string;
  kind: 'traffic' | 'file' | 'email' | string;
  protocol: string;
  action: string;
  src_decky_uuid: string | null;
  dst_decky_uuid: string;
  success: boolean;
  payload: string;
  // Email-only extras populated when `kind === 'email'`.
  subject?: string;
  sender_email?: string;
  recipient_email?: string;
  language?: string;
  thread_id?: string;
  mail_decky_uuid?: string;
  message_id?: string;
  in_reply_to?: string | null;
}

interface Props {
  event: OrchestratorInspectorEntry;
  onClose: () => void;
}

const renderDeckyId = (id: string | null): string => id ?? '—';

const sourceTag = (id: string | null): 'topology' | 'fleet' | 'shard' | null => {
  if (!id) return null;
  // Composite "host_uuid:name" identifies fleet/shard rows;
  // bare UUIDs (8-4-4-4-12) are MazeNET TopologyDecky.uuid.
  if (id.includes(':')) return id.startsWith('local:') ? 'fleet' : 'shard';
  return /^[0-9a-f]{8}-/i.test(id) ? 'topology' : null;
};

const OrchestratorInspector: React.FC<Props> = ({ event, onClose }) => {
  const { push } = useToast();

  const prettyPayload = useMemo(() => {
    try {
      return JSON.stringify(JSON.parse(event.payload), null, 2);
    } catch {
      return event.payload;
    }
  }, [event.payload]);

  const copy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      push({ text: `${label} COPIED`, tone: 'matrix', icon: 'copy' });
    } catch {
      push({ text: 'CLIPBOARD BLOCKED', tone: 'alert', icon: 'alert-triangle' });
    }
  };

  const copyEvent = () => copy(JSON.stringify(event, null, 2), 'EVENT JSON');
  const copyPayload = () => copy(prettyPayload, 'PAYLOAD JSON');

  const kindCls =
    event.kind === 'traffic' || event.kind === 'file' || event.kind === 'email'
      ? event.kind : '';
  const isEmail = event.kind === 'email';
  const srcSrc = sourceTag(event.src_decky_uuid);
  const dstSrc = sourceTag(event.dst_decky_uuid);
  const isLive = event.uuid.startsWith('live-');

  return (
    <div
      className="orchestrator-drawer-backdrop"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="orchestrator-drawer">
        <div className="bd-head">
          <h3>
            <Cpu size={14} />
            <span>
              {isLive ? 'LIVE EVENT' : `EVENT #${event.uuid.slice(0, 8)}`}
            </span>
            <span className={`kind-chip ${kindCls}`} style={{ marginLeft: 8 }}>
              {event.kind.toUpperCase()}
            </span>
          </h3>
          <button className="close-btn" onClick={onClose} aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <div className="bd-body">
          <div className="kvs">
            <div className="k">TS</div>
            <div className="v">{new Date(event.ts).toLocaleString()}</div>

            <div className="k">PROTOCOL</div>
            <div className="v">
              <span className="chip dim-chip">{event.protocol.toUpperCase()}</span>
            </div>

            <div className="k">{isEmail ? 'SUBJECT' : 'ACTION'}</div>
            <div className="v mono matrix-text">{event.action}</div>

            {isEmail && event.language && (
              <>
                <div className="k">LANGUAGE</div>
                <div className="v">
                  <span className="chip dim-chip">{event.language.toUpperCase()}</span>
                </div>
              </>
            )}
            {isEmail && event.thread_id && (
              <>
                <div className="k">THREAD</div>
                <div className="v">
                  <span className="hash-text">{event.thread_id}</span>
                </div>
              </>
            )}
            {isEmail && event.in_reply_to && (
              <>
                <div className="k">IN-REPLY-TO</div>
                <div className="v">
                  <span className="hash-text">{event.in_reply_to}</span>
                </div>
              </>
            )}
            {isEmail && event.mail_decky_uuid && (
              <>
                <div className="k">MAIL DECKY</div>
                <div className="v">
                  <span className="hash-text">{event.mail_decky_uuid}</span>
                </div>
              </>
            )}

            <div className="k">OUTCOME</div>
            <div className="v">
              <span className={event.success ? 'ok-yes' : 'ok-no'}>
                {event.success ? '✓ SUCCESS' : '✗ FAILURE'}
              </span>
            </div>

            <div className="k">SRC</div>
            <div className="v">
              {event.src_decky_uuid ? (
                <span className="src-dst-cell">
                  <span className="hash-text">{renderDeckyId(event.src_decky_uuid)}</span>
                  {srcSrc && <span className={`chip src-${srcSrc}`}>{srcSrc.toUpperCase()}</span>}
                </span>
              ) : (
                <span className="dim">—</span>
              )}
            </div>

            <div className="k"><ArrowRight size={12} /></div>
            <div className="v">
              <span className="src-dst-cell">
                <span className="hash-text">{renderDeckyId(event.dst_decky_uuid)}</span>
                {dstSrc && <span className={`chip src-${dstSrc}`}>{dstSrc.toUpperCase()}</span>}
              </span>
            </div>

            {!isLive && (
              <>
                <div className="k">EVENT UUID</div>
                <div className="v">
                  <div className="hash-row">
                    <span className="hash-text">{event.uuid}</span>
                    <button
                      className="icon-btn"
                      onClick={() => copy(event.uuid, 'UUID')}
                      aria-label="Copy event UUID"
                    >
                      <Copy size={12} />
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>

          <div>
            <div className="type-label">PAYLOAD</div>
            <pre className="code-block">{prettyPayload}</pre>
          </div>

          <div>
            <div className="type-label">EXPORT</div>
            <div className="bd-actions">
              <button className="btn ghost" onClick={copyEvent}>
                <Copy size={12} /> COPY EVENT JSON
              </button>
              <button className="btn ghost" onClick={copyPayload}>
                <Copy size={12} /> COPY PAYLOAD
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default OrchestratorInspector;

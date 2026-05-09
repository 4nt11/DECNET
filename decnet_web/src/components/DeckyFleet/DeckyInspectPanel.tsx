import React, { useEffect } from 'react';
import { X } from '../../icons';
import { useEscapeKey } from '../../hooks/useEscapeKey';
import { dotFor, stateColor } from './helpers';
import type { Decky } from './types';

interface Props {
  decky: Decky;
  onClose: () => void;
}

/** Right-side slide-in inspect panel for a single Decky. Renders the
 *  rollup of identity / archetype / mutate scheduling fields plus
 *  the swarm placement metadata when present. */
export const DeckyInspectPanel: React.FC<Props> = ({ decky, onClose }) => {
  useEscapeKey(onClose, true);
  const status = dotFor(decky);

  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = prev; };
  }, []);

  const fmtDate = (ts: number | string | null | undefined) => {
    if (!ts) return '—';
    const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
    return isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
  };

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0,
        backgroundColor: 'rgba(0,0,0,0.55)',
        display: 'flex', justifyContent: 'flex-end',
        zIndex: 1200,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 360,
          background: 'var(--secondary-color)',
          borderLeft: '1px solid var(--border)',
          display: 'flex', flexDirection: 'column',
          height: '100%',
          overflowY: 'auto',
        }}
      >
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '16px 20px',
          borderBottom: '1px solid var(--border)',
          gap: 12,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span className={`status-dot ${status}`} />
            <span style={{ fontWeight: 700, letterSpacing: 3, fontSize: '0.95rem', color: 'var(--matrix)' }}>
              {decky.name}
            </span>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--dim-color)', padding: 4 }}
          >
            <X size={16} />
          </button>
        </div>

        <div style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {[
              ['IP', decky.ip],
              ['HOSTNAME', decky.hostname],
              ['DISTRO', decky.distro],
              ['ARCHETYPE', decky.archetype],
              ['LAST MUTATED', fmtDate(decky.last_mutated)],
              ['MUTATE INTERVAL', decky.mutate_interval != null ? `${decky.mutate_interval}s` : '—'],
            ].map(([label, val]) => val ? (
              <div key={label} style={{ display: 'flex', gap: 10, fontSize: '0.78rem' }}>
                <span style={{ minWidth: 130, opacity: 0.45, letterSpacing: 1 }}>{label}</span>
                <span style={{ color: 'var(--matrix)', wordBreak: 'break-all' }}>{val}</span>
              </div>
            ) : null)}
          </div>

          {decky.services.length > 0 && (
            <div>
              <div style={{ fontSize: '0.65rem', opacity: 0.45, letterSpacing: 1.5, marginBottom: 8 }}>SERVICES</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {decky.services.map(svc => (
                  <span key={svc} className="chip violet" style={{ fontSize: '0.65rem' }}>{svc}</span>
                ))}
              </div>
            </div>
          )}

          {decky.swarm && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, paddingTop: 8, borderTop: '1px solid var(--border)' }}>
              <div style={{ fontSize: '0.65rem', opacity: 0.45, letterSpacing: 1.5, marginBottom: 2 }}>SWARM</div>
              {[
                ['HOST', decky.swarm.host_name],
                ['ADDRESS', decky.swarm.host_address],
                ['STATE', decky.swarm.state],
                ['LAST SEEN', fmtDate(decky.swarm.last_seen)],
                ['ERROR', decky.swarm.last_error],
              ].map(([label, val]) => val ? (
                <div key={label} style={{ display: 'flex', gap: 10, fontSize: '0.78rem' }}>
                  <span style={{ minWidth: 130, opacity: 0.45, letterSpacing: 1 }}>{label}</span>
                  <span style={{
                    color: label === 'STATE' ? stateColor(val) : label === 'ERROR' ? 'var(--alert)' : 'var(--matrix)',
                    wordBreak: 'break-all',
                  }}>{val}</span>
                </div>
              ) : null)}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Activity, AlertTriangle, ArrowLeft, Cpu, Crosshair, Eye, Fingerprint, Globe, Keyboard, Shield, Clock, Sparkles, Wifi, Lock, FileKey, Radio, Timer, FileText, AtSign } from '../icons';
import api from '../utils/api';
import SessionDrawer from './SessionDrawer';
import EmptyState from './EmptyState/EmptyState';
import TTPsObservedSection from './TTPsObservedSection';
import { useAttackerDetail } from './AttackerDetail/useAttackerDetail';
import { AttackerHeader } from './AttackerDetail/sections/AttackerHeader';
import { AttackerStats } from './AttackerDetail/sections/AttackerStats';
import { TimelineSection } from './AttackerDetail/sections/TimelineSection';
import { ServicesTargeted } from './AttackerDetail/sections/ServicesTargeted';
import { CommandsViewer } from './AttackerDetail/sections/CommandsViewer';
import { ArtifactsPanel } from './AttackerDetail/sections/ArtifactsPanel';
import { MailLogPanel } from './AttackerDetail/sections/MailLogPanel';
import { Tag, Section } from './AttackerDetail/ui';
import {
  FingerprintGroup, getPayload,
} from './AttackerDetail/fingerprints';
import {
  BehaviorHeadline, BeaconBlock, DetectedToolsBlock, PhaseSequenceBlock,
  TcpStackBlock, TimingStatsBlock, BehaviouralPrimitivesPanel,
} from './AttackerDetail/behaviour';
import type {
  BehaviouralObservation,
  AttributionPrimitiveState,
} from './AttackerDetail/types';
import './Dashboard.css';

// Re-export so existing external importers (tests, future siblings) stay
// source-compatible while the canonical definitions live in
// ./AttackerDetail/{types,behaviour}.
export { BehaviouralPrimitivesPanel };
export type { BehaviouralObservation, AttributionPrimitiveState };



// ─── Threat-Intel Panel ─────────────────────────────────────────────────────

// Mirrors decnet/web/db/models/attacker_intel.py — server returns the row
// fields plus null gaps where a provider hasn't answered yet. We treat
// every column as optional on the wire.
type IntelRow = {
  attacker_uuid: string;
  attacker_ip: string;
  schema_version?: number;
  aggregate_verdict?: 'malicious' | 'suspicious' | 'benign' | 'unknown' | null;
  greynoise_classification?: string | null;
  greynoise_raw?: any;
  greynoise_queried_at?: string | null;
  abuseipdb_score?: number | null;
  abuseipdb_raw?: any;
  abuseipdb_queried_at?: string | null;
  feodo_listed?: boolean | null;
  feodo_raw?: any;
  feodo_queried_at?: string | null;
  threatfox_listed?: boolean | null;
  threatfox_raw?: any;
  threatfox_queried_at?: string | null;
  cached_at?: string | null;
  expires_at?: string | null;
};

const VERDICT_TONE: Record<string, { color: string; label: string }> = {
  malicious: { color: 'var(--alert)', label: 'MALICIOUS' },
  suspicious: { color: 'var(--warn)', label: 'SUSPICIOUS' },
  benign: { color: 'var(--ok)', label: 'BENIGN' },
  unknown: { color: 'var(--fg-4)', label: 'NO SIGNAL' },
};

const fmtTs = (iso?: string | null): string => {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
};

const ProviderRow: React.FC<{
  name: string;
  queriedAt?: string | null;
  detail: React.ReactNode;
}> = ({ name, queriedAt, detail }) => (
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

const IntelPanel: React.FC<{ uuid: string }> = ({ uuid }) => {
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
      } catch (err: any) {
        if (cancelled) return;
        if (err?.response?.status === 404) {
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


// ─── Main component ─────────────────────────────────────────────────────────

const AttackerDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  // Data layer is owned by the hook: REST fetches, attribution table,
  // and per-attacker / per-identity SSE streams all live there.
  const {
    attacker,
    observations,
    attribution,
    loading,
    error,
    commands,
    cmdTotal,
    cmdPage,
    setCmdPage,
    serviceFilter,
    setServiceFilter,
    cmdLimit,
    artifacts,
    smtpTargets,
    mail,
    mailForbidden,
    sessions,
  } = useAttackerDetail(id);

  // Section collapse state
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
    timeline: true,
    services: true,
    deckies: true,
    behavior: true,
    behavioural: true,
    commands: true,
    fingerprints: true,
    intel: true,
    artifacts: true,
    sessions: true,
    smtpTargets: true,
    mail: true,
  });

  // Drawer selection (ephemeral UI; data feeds come from the hook).
  // Drawer selection (session). Artifact + mail drawer state are
  // owned by their respective sections.
  const [session, setSession] = useState<{ decky: string; sid: string; fields: Record<string, any> } | null>(null);

  const toggle = (key: string) => setOpenSections((prev) => ({ ...prev, [key]: !prev[key] }));

  if (loading) {
    return (
      <div className="dashboard">
        <div style={{ textAlign: 'center', padding: '80px', opacity: 0.5, letterSpacing: '4px' }}>
          LOADING THREAT PROFILE...
        </div>
      </div>
    );
  }

  if (error || !attacker) {
    return (
      <div className="dashboard">
        <button onClick={() => navigate('/attackers')} className="back-button">
          <ArrowLeft size={18} />
          <span>BACK TO PROFILES</span>
        </button>
        <div style={{ textAlign: 'center', padding: '80px', opacity: 0.5, letterSpacing: '4px' }}>
          {error || 'ATTACKER NOT FOUND'}
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard page-scroll">
      {/* Back Button */}
      <button onClick={() => navigate('/attackers')} className="back-button">
        <ArrowLeft size={18} />
        <span>BACK TO PROFILES</span>
      </button>

      <AttackerHeader attacker={attacker} />

      <AttackerStats attacker={attacker} />

      {/* TTPs Observed (per-IP slice) — see TTP_TAGGING.md §"UI surface" */}
      <TTPsObservedSection scope="attacker" uuid={attacker.uuid} />

      <TimelineSection
        attacker={attacker}
        open={openSections.timeline}
        onToggle={() => toggle('timeline')}
      />

      <ServicesTargeted
        attacker={attacker}
        serviceFilter={serviceFilter}
        setServiceFilter={setServiceFilter}
        open={openSections.services}
        onToggle={() => toggle('services')}
      />

      {/* Deckies & Traversal */}
      <Section title="DECKY INTERACTIONS" open={openSections.deckies} onToggle={() => toggle('deckies')}>
        <div style={{ padding: '16px', fontSize: '0.85rem' }}>
          {attacker.traversal_path ? (
            <div>
              <span className="dim">TRAVERSAL PATH: </span>
              <span className="violet-accent">{attacker.traversal_path}</span>
            </div>
          ) : (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
              {attacker.deckies.map((d) => (
                <span key={d} className="service-badge" style={{ borderColor: 'var(--accent-color)', color: 'var(--accent-color)' }}>
                  {d}
                </span>
              ))}
              {attacker.deckies.length === 0 && <span className="dim">No deckies recorded</span>}
            </div>
          )}
        </div>
      </Section>

      {/* Behavioral Profile */}
      <Section
        title="BEHAVIORAL PROFILE"
        open={openSections.behavior}
        onToggle={() => toggle('behavior')}
      >
        {attacker.behavior ? (
          <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <BehaviorHeadline b={attacker.behavior} />
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <BeaconBlock b={attacker.behavior} />
              <DetectedToolsBlock b={attacker.behavior} />
              <TcpStackBlock b={attacker.behavior} />
              <TimingStatsBlock b={attacker.behavior} />
              <PhaseSequenceBlock b={attacker.behavior} />
            </div>
          </div>
        ) : (
          <EmptyState
            icon={Activity}
            title="NO BEHAVIORAL DATA YET"
            hint="profiler has not run for this attacker"
            size="compact"
          />
        )}
      </Section>

      {/* Behavioural primitives (BEHAVE-SHELL) */}
      <Section
        title="BEHAVE PRIMITIVES"
        open={openSections.behavioural}
        onToggle={() => toggle('behavioural')}
      >
        <BehaviouralPrimitivesPanel observations={observations} attribution={attribution} />
      </Section>

      <CommandsViewer
        commands={commands}
        cmdTotal={cmdTotal}
        cmdPage={cmdPage}
        cmdLimit={cmdLimit}
        setCmdPage={setCmdPage}
        serviceFilter={serviceFilter}
        open={openSections.commands}
        onToggle={() => toggle('commands')}
      />

      {/* Fingerprints — grouped by type */}
      {(() => {
        const filteredFps = serviceFilter
          ? attacker.fingerprints.filter((fp) => {
              const p = getPayload(fp);
              return p.service === serviceFilter;
            })
          : attacker.fingerprints;

        // Group fingerprints by type. tls_certificate is split on the
        // presence of target_ip — prober payloads carry it, sniffer
        // payloads do not — so each source ends up under the right
        // active/passive bucket below.
        const groups: Record<string, any[]> = {};
        filteredFps.forEach((fp) => {
          const p = getPayload(fp);
          let fpType: string = p.fingerprint_type || 'unknown';
          if (fpType === 'tls_certificate') {
            fpType = p.target_ip ? 'tls_certificate_active' : 'tls_certificate_passive';
          }
          if (!groups[fpType]) groups[fpType] = [];
          groups[fpType].push(fp);
        });

        // Active probes first, then passive, then unknown
        const activeTypes = ['jarm', 'hassh_server', 'tcpfp', 'tls_certificate_active'];
        const passiveTypes = ['ja3', 'ja4l', 'tls_resumption', 'tls_certificate_passive', 'http_useragent', 'http_quirks', 'spoofed_source', 'vnc_client_version'];
        const knownTypes = [...activeTypes, ...passiveTypes];
        const unknownTypes = Object.keys(groups).filter((t) => !knownTypes.includes(t));

        const hasActive = activeTypes.some((t) => groups[t]);
        const hasPassive = [...passiveTypes, ...unknownTypes].some((t) => groups[t]);

        return (
          <Section
            title={<>FINGERPRINTS ({filteredFps.length}{serviceFilter ? ` / ${attacker.fingerprints.length}` : ''})</>}
            open={openSections.fingerprints}
            onToggle={() => toggle('fingerprints')}
          >
            {filteredFps.length > 0 ? (
              <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
                {/* Active probes section */}
                {hasActive && (
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                      <Crosshair size={14} className="violet-accent" />
                      <span style={{ fontSize: '0.75rem', letterSpacing: '2px', opacity: 0.6 }}>ACTIVE PROBES</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      {activeTypes.filter((t) => groups[t]).map((fpType) => (
                        <FingerprintGroup key={fpType} fpType={fpType} items={groups[fpType]} />
                      ))}
                    </div>
                  </div>
                )}

                {/* Passive fingerprints section */}
                {hasPassive && (
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                      <Fingerprint size={14} className="violet-accent" />
                      <span style={{ fontSize: '0.75rem', letterSpacing: '2px', opacity: 0.6 }}>PASSIVE FINGERPRINTS</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      {[...passiveTypes, ...unknownTypes].filter((t) => groups[t]).map((fpType) => (
                        <FingerprintGroup key={fpType} fpType={fpType} items={groups[fpType]} />
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ padding: '24px', textAlign: 'center', opacity: 0.5 }}>
                {serviceFilter ? `NO ${serviceFilter.toUpperCase()} FINGERPRINTS CAPTURED` : 'NO FINGERPRINTS CAPTURED'}
              </div>
            )}
          </Section>
        );
      })()}

      {/* Threat-Intel Enrichment — UUID-keyed, fetches in parallel with the parent. */}
      <Section
        title={<><Globe size={14} style={{ verticalAlign: 'middle', marginRight: '6px' }} />THREAT INTEL</>}
        open={openSections.intel}
        onToggle={() => toggle('intel')}
      >
        <IntelPanel uuid={id!} />
      </Section>

      <ArtifactsPanel
        artifacts={artifacts}
        open={openSections.artifacts}
        onToggle={() => toggle('artifacts')}
      />

      {/* SMTP Victim Domains (viewer-safe rollup) */}
      <Section
        title={<>SMTP VICTIM DOMAINS ({smtpTargets.length})</>}
        open={openSections.smtpTargets}
        onToggle={() => toggle('smtpTargets')}
      >
        {smtpTargets.length > 0 ? (
          <div className="logs-table-container">
            <table className="logs-table">
              <thead>
                <tr>
                  <th>DOMAIN</th>
                  <th>COUNT</th>
                  <th>FIRST SEEN</th>
                  <th>LAST SEEN</th>
                </tr>
              </thead>
              <tbody>
                {smtpTargets.map((row) => (
                  <tr key={row.domain}>
                    <td className="matrix-text" style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                      {row.domain}
                    </td>
                    <td className="matrix-text" style={{ fontFamily: 'monospace' }}>
                      {row.count}
                    </td>
                    <td className="dim" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                      {new Date(row.first_seen).toLocaleString()}
                    </td>
                    <td className="dim" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                      {new Date(row.last_seen).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon={AtSign}
            title="NO SMTP VICTIMS OBSERVED"
            size="compact"
          />
        )}
      </Section>

      <MailLogPanel
        mail={mail}
        mailForbidden={mailForbidden}
        open={openSections.mail}
        onToggle={() => toggle('mail')}
      />

      {/* Recorded PTY Sessions (SSH / Telnet) */}
      <Section
        title={<>SESSION TRANSCRIPTS ({sessions.length})</>}
        open={openSections.sessions}
        onToggle={() => toggle('sessions')}
      >
        {sessions.length > 0 ? (
          <div className="logs-table-container">
            <table className="logs-table">
              <thead>
                <tr>
                  <th>TIMESTAMP</th>
                  <th>DECKY</th>
                  <th>SERVICE</th>
                  <th>DURATION</th>
                  <th>BYTES</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((row) => {
                  let fields: Record<string, any> = {};
                  try { fields = JSON.parse(row.fields || '{}'); } catch {}
                  const sid = fields.sid ? String(fields.sid) : null;
                  const dur = fields.duration_s;
                  const bytes = fields.bytes;
                  return (
                    <tr key={row.id}>
                      <td className="dim" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                        {new Date(row.timestamp).toLocaleString()}
                      </td>
                      <td className="violet-accent">{row.decky}</td>
                      <td className="matrix-text">{fields.service ?? row.service}</td>
                      <td className="matrix-text" style={{ fontFamily: 'monospace' }}>
                        {dur ? `${dur}s` : '—'}
                      </td>
                      <td className="matrix-text" style={{ fontFamily: 'monospace' }}>
                        {bytes ? `${bytes} B` : '—'}
                      </td>
                      <td>
                        {sid && (
                          <button
                            onClick={() => setSession({ decky: row.decky, sid, fields })}
                            title="Replay recorded session"
                            style={{
                              display: 'flex', alignItems: 'center', gap: '6px',
                              fontSize: '0.7rem',
                              backgroundColor: 'var(--info-tint-10)',
                              padding: '2px 8px',
                              borderRadius: '4px',
                              border: '1px solid var(--info)',
                              color: 'var(--info)',
                              cursor: 'pointer',
                            }}
                          >
                            REPLAY
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon={FileText}
            title="NO SESSION TRANSCRIPTS RECORDED"
            size="compact"
          />
        )}
      </Section>

      {session && (
        <SessionDrawer
          decky={session.decky}
          sid={session.sid}
          fields={session.fields}
          onClose={() => setSession(null)}
        />
      )}

      {/* UUID footer */}
      <div style={{ textAlign: 'right', fontSize: '0.65rem', opacity: 0.3, marginTop: '8px' }}>
        UUID: {attacker.uuid}
      </div>
    </div>
  );
};

export default AttackerDetail;

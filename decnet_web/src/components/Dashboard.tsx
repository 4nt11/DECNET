import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './Dashboard.css';
import { Shield, Users, Activity, Clock, Paperclip, Crosshair, Flame, Archive, ShieldOff, Server, LayoutDashboard } from '../icons';
import { parseEventBody } from '../utils/parseEventBody';
import ArtifactDrawer from './ArtifactDrawer';
import EmptyState from './EmptyState/EmptyState';

interface Stats {
  total_logs: number;
  unique_attackers: number;
  active_deckies: number;
  deployed_deckies: number;
}

interface LogEntry {
  id: number;
  timestamp: string;
  decky: string;
  service: string;
  event_type: string | null;
  attacker_ip: string;
  raw_line: string;
  fields: string | null;
  msg: string | null;
  severity?: string;
  is_bounty?: boolean;
}

interface DashboardProps {
  searchQuery: string;
}

type ThreatLevel = 'nominal' | 'elevated' | 'critical';

const SPARK_LEN = 12;

function Sparkline({ data, alert }: { data: number[]; alert?: boolean }) {
  const max = Math.max(...data, 1);
  return (
    <div className={`spark ${alert ? 'alert' : ''}`}>
      {data.map((v, i) => (
        <span
          key={i}
          style={{
            height: `${(v / max) * 100}%`,
            opacity: 0.4 + (v / max) * 0.6,
          }}
        />
      ))}
    </div>
  );
}

function rollWindow(prev: number[], next: number): number[] {
  const out = prev.slice(-SPARK_LEN + 1);
  out.push(next);
  while (out.length < SPARK_LEN) out.unshift(0);
  return out;
}

function computeThreat(hits5m: number): ThreatLevel {
  if (hits5m > 100) return 'critical';
  if (hits5m > 50) return 'elevated';
  return 'nominal';
}

function getSector(): string {
  try {
    const raw = localStorage.getItem('decnet_tweaks');
    if (!raw) return 'PRODUCTION';
    const t = JSON.parse(raw);
    return (t?.sector || 'PRODUCTION').toString().toUpperCase();
  } catch {
    return 'PRODUCTION';
  }
}

const Dashboard: React.FC<DashboardProps> = ({ searchQuery }) => {
  const navigate = useNavigate();
  const [stats, setStats] = useState<Stats | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [artifact, setArtifact] = useState<{ decky: string; storedAs: string; fields: Record<string, unknown> } | null>(null);
  const [newestLogId, setNewestLogId] = useState<number | null>(null);
  const [sparkTotal, setSparkTotal] = useState<number[]>(() => Array(SPARK_LEN).fill(0));
  const [sparkAttackers, setSparkAttackers] = useState<number[]>(() => Array(SPARK_LEN).fill(0));
  const [sparkBounties, setSparkBounties] = useState<number[]>(() => Array(SPARK_LEN).fill(0));
  const lastStatsRef = useRef<{ total: number; uniq: number; bounties: number } | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const logsContainerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const connect = () => {
      if (eventSourceRef.current) eventSourceRef.current.close();

      const token = localStorage.getItem('token');
      const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';
      let url = `${baseUrl}/stream?token=${token}`;
      if (searchQuery) url += `&search=${encodeURIComponent(searchQuery)}`;

      const es = new EventSource(url);
      eventSourceRef.current = es;

      es.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === 'logs') {
            const incoming: LogEntry[] = payload.data;
            if (incoming.length > 0) {
              setNewestLogId(incoming[0].id);
            }
            setLogs(prev => [...incoming, ...prev].slice(0, 100));
          } else if (payload.type === 'stats') {
            setStats(payload.data);
            setLoading(false);
          }
        } catch (err) {
          console.error('Failed to parse SSE payload', err);
        }
      };

      es.onerror = () => {
        es.close();
        eventSourceRef.current = null;
        reconnectTimerRef.current = setTimeout(connect, 3000);
      };
    };

    connect();

    return () => {
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      if (eventSourceRef.current) eventSourceRef.current.close();
    };
  }, [searchQuery]);

  // Keep the live feed scrolled to the top so the sticky thead never floats.
  useEffect(() => {
    if (logsContainerRef.current) logsContainerRef.current.scrollTop = 0;
  }, [logs]);

  // Tick once a second so the 5-min rolling window stays accurate even
  // when logs haven't arrived.
  const [nowTick, setNowTick] = useState(() => Date.now());
  useEffect(() => {
    const iv = setInterval(() => setNowTick(Date.now()), 1000);
    return () => clearInterval(iv);
  }, []);

  // Derived metrics from live log buffer
  const { hits5m, alertCount, uniqueAttackers5m, bountiesCount, deckiesUnderSiege, topAttackers } = useMemo(() => {
    const cutoff = nowTick - 5 * 60_000;
    const recent = logs.filter(l => {
      const t = Date.parse(l.timestamp);
      return !isNaN(t) && t >= cutoff;
    });
    const alertN = recent.filter(l => l.severity === 'warn' || l.is_bounty).length;
    const uniq = new Set(recent.map(l => l.attacker_ip)).size;
    const bounties = logs.filter(l => l.is_bounty).length;

    const deckyHits = new Map<string, number>();
    for (const l of recent) deckyHits.set(l.decky, (deckyHits.get(l.decky) || 0) + 1);
    const siege = Array.from(deckyHits.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([name, hits]) => ({
        name,
        hits,
        status: hits > 30 ? 'hot' : hits > 10 ? 'warn' : 'active',
      }));

    const attackerHits = new Map<string, number>();
    for (const l of logs) attackerHits.set(l.attacker_ip, (attackerHits.get(l.attacker_ip) || 0) + 1);
    const maxAttackerHits = Math.max(1, ...attackerHits.values());
    const top = Array.from(attackerHits.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .map(([ip, hits]) => ({
        ip,
        hits,
        pct: Math.min(100, (hits / maxAttackerHits) * 100),
        hot: hits > maxAttackerHits * 0.6,
      }));

    return {
      hits5m: recent.length,
      alertCount: alertN,
      uniqueAttackers5m: uniq,
      bountiesCount: bounties,
      deckiesUnderSiege: siege,
      topAttackers: top,
    };
  }, [logs, nowTick]);

  const threat = computeThreat(hits5m);

  // Broadcast stats + threat for Layout's listener
  useEffect(() => {
    if (!stats) return;
    window.dispatchEvent(new CustomEvent('decnet:stats', {
      detail: { ...stats, threat, hits_5m: hits5m, alert_count: alertCount },
    }));
  }, [stats, threat, hits5m, alertCount]);

  // Roll sparklines on each stats frame
  useEffect(() => {
    if (!stats) return;
    const total = stats.total_logs;
    const uniq = stats.unique_attackers;
    const last = lastStatsRef.current;
    if (last) {
      const dTotal = Math.max(0, total - last.total);
      const dUniq = Math.max(0, uniq - last.uniq);
      const dBounties = Math.max(0, bountiesCount - last.bounties);
      setSparkTotal(prev => rollWindow(prev, dTotal));
      setSparkAttackers(prev => rollWindow(prev, dUniq));
      setSparkBounties(prev => rollWindow(prev, dBounties));
    }
    lastStatsRef.current = { total, uniq, bounties: bountiesCount };
  }, [stats, bountiesCount]);

  if (loading && !stats) return <div className="loader">INITIALIZING SENSORS...</div>;

  const sector = getSector();

  return (
    <div className="dashboard">
      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <LayoutDashboard size={22} className="violet-accent" />
            <h1>DASHBOARD</h1>
          </div>
          <span className="page-sub">SECTOR · {sector} · LIVE</span>
        </div>
        <div className="section-actions">
          <span className="chip matrix fx-blink">
            <span className="status-dot active" /> LIVE
          </span>
        </div>
      </div>

      {threat === 'critical' && (
        <div className="breach-banner">
          <span className="pulse" />
          <span style={{ flex: 1 }}>
            ACTIVE BREACH — {hits5m} hits in last 5 min · {uniqueAttackers5m} attackers
          </span>
          <button onClick={() => navigate('/live-logs')}>INSPECT SESSION</button>
        </div>
      )}

      <div className="stats-grid">
        <div className="stat-card">
          <div className="row">
            <span className="stat-label">TOTAL INTERACTIONS</span>
            <div className="stat-icon"><Activity size={18} /></div>
          </div>
          <div className="stat-value">{(stats?.total_logs ?? 0).toLocaleString()}</div>
          <div className="row">
            <div className="stat-delta up">+{hits5m} in last 5m</div>
            <Sparkline data={sparkTotal} />
          </div>
        </div>

        <div className="stat-card alert">
          <div className="row">
            <span className="stat-label">UNIQUE ATTACKERS</span>
            <div className="stat-icon"><Crosshair size={18} /></div>
          </div>
          <div className="stat-value">{(stats?.unique_attackers ?? 0).toLocaleString()}</div>
          <div className="row">
            <div className="stat-delta up">{uniqueAttackers5m} active in 5m</div>
            <Sparkline data={sparkAttackers} alert />
          </div>
        </div>

        <div className="stat-card">
          <div className="row">
            <span className="stat-label">ACTIVE DECKIES</span>
            <div className="stat-icon"><Shield size={18} /></div>
          </div>
          <div className="stat-value">
            {stats?.active_deckies ?? 0}
            <span className="dim" style={{ fontSize: '1rem' }}> / {stats?.deployed_deckies ?? 0}</span>
          </div>
          <div className="row">
            <div className="stat-delta">OF TOTAL FLEET</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="row">
            <span className="stat-label">BOUNTIES CAPTURED</span>
            <div className="stat-icon"><Archive size={18} /></div>
          </div>
          <div className="stat-value">{bountiesCount.toLocaleString()}</div>
          <div className="row">
            <div className="stat-delta">THIS SESSION</div>
            <Sparkline data={sparkBounties} />
          </div>
        </div>
      </div>

      <div className="dash-grid">
        <div className="logs-section">
          <div className="section-header">
            <div className="section-title">
              <Clock size={16} />
              <span>LIVE INTERACTION FEED</span>
              <span className="chip matrix fx-blink">
                <span className="status-dot active" /> LIVE
              </span>
            </div>
            <div className="section-actions">
              <span>{logs.length} RECENT</span>
            </div>
          </div>
          <div className="logs-table-container" ref={logsContainerRef}>
            <table className="logs-table">
              <thead>
                <tr>
                  <th>TIME</th>
                  <th></th>
                  <th>DECKY</th>
                  <th>SVC</th>
                  <th>ATTACKER</th>
                  <th>EVENT</th>
                </tr>
              </thead>
              <tbody>
                {logs.length > 0 ? logs.slice(0, 14).map(log => {
                  let parsedFields: Record<string, unknown> = {};
                  if (log.fields) {
                    try {
                      parsedFields = JSON.parse(log.fields);
                    } catch {
                      // ignore
                    }
                  }

                  let msgHead: string | null = null;
                  let msgTail: string | null = null;
                  if (Object.keys(parsedFields).length === 0) {
                    const parsed = parseEventBody(log.msg);
                    parsedFields = parsed.fields;
                    msgHead = parsed.head;
                    msgTail = parsed.tail;
                  } else if (log.msg && log.msg !== '-') {
                    msgTail = log.msg;
                  }

                  const isAlert = log.severity === 'warn' || log.is_bounty;
                  const isNew = log.id === newestLogId;

                  return (
                    <tr key={log.id} className={isNew ? 'row-enter' : ''}>
                      <td className="dim" style={{ fontSize: '0.7rem', whiteSpace: 'nowrap' }}>
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </td>
                      <td>
                        {log.is_bounty
                          ? <span className="chip violet"><Archive size={8} /> BOUNTY</span>
                          : <span className={`status-dot ${isAlert ? 'hot' : 'active'}`} />}
                      </td>
                      <td className="violet-accent">{log.decky}</td>
                      <td><span className="chip dim-chip">{log.service}</span></td>
                      <td className="matrix-text">{log.attacker_ip}</td>
                      <td style={{ minWidth: 0, maxWidth: 0, width: '100%' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0 }}>
                          <div style={{ fontWeight: 700, fontSize: '0.78rem', color: 'var(--text-color)' }}>
                            {(() => {
                              const et = log.event_type && log.event_type !== '-' ? log.event_type : null;
                              const parts = [et, msgHead].filter(Boolean) as string[];
                              return (
                                <>
                                  {parts.join(' · ')}
                                  {msgTail && (
                                    <span style={{ fontWeight: 'normal', opacity: 0.8 }}>
                                      {parts.length ? ' — ' : ''}{msgTail}
                                    </span>
                                  )}
                                </>
                              );
                            })()}
                          </div>
                          {Object.keys(parsedFields).length > 0 && (
                            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', minWidth: 0 }}>
                              {parsedFields.stored_as != null && (
                                <button
                                  onClick={() => setArtifact({
                                    decky: log.decky,
                                    storedAs: String(parsedFields.stored_as),
                                    fields: parsedFields,
                                  })}
                                  title="Inspect captured artifact"
                                  style={{
                                    display: 'inline-flex', alignItems: 'center', gap: 4,
                                    fontSize: '0.62rem',
                                    backgroundColor: 'rgba(255, 170, 0, 0.1)',
                                    padding: '2px 8px',
                                    borderRadius: 4,
                                    border: '1px solid rgba(255, 170, 0, 0.5)',
                                    color: '#ffaa00',
                                    cursor: 'pointer',
                                    letterSpacing: 1,
                                  }}
                                >
                                  <Paperclip size={10} /> ARTIFACT
                                </button>
                              )}
                              {Object.entries(parsedFields)
                                .filter(([k]) => k !== 'meta_json_b64' && k !== 'stored_as')
                                .map(([k, v]) => {
                                  const rendered = typeof v === 'object' ? JSON.stringify(v) : String(v);
                                  return (
                                    <span
                                      key={k}
                                      className="chip matrix chip-kv"
                                      style={{ fontSize: '0.62rem' }}
                                      title={`${k}: ${rendered}`}
                                    >
                                      <span className="dim" style={{ marginRight: 3 }}>{k}:</span>
                                      {rendered}
                                    </span>
                                  );
                                })}
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                }) : (
                  <tr className="empty-row">
                    <td colSpan={6} style={{ padding: 0 }}>
                      <EmptyState
                        icon={Activity}
                        title="NO INTERACTION DETECTED"
                        hint="waiting for the first decky hit"
                      />
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="dash-side">
          <div className="logs-section">
            <div className="section-header">
              <div className="section-title">
                <Flame size={16} />
                <span>DECKIES UNDER SIEGE</span>
              </div>
            </div>
            {deckiesUnderSiege.length > 0 ? (
              <div className="panel-body">
                {deckiesUnderSiege.map(d => (
                  <div
                    key={d.name}
                    className="attacker-row"
                    onClick={() => window.dispatchEvent(new CustomEvent('decnet:cmd', { detail: { id: 'filter-decky', payload: d.name } }))}
                  >
                    <span className={`status-dot ${d.status}`} />
                    <span className="violet-accent" style={{ width: 110, fontSize: '0.75rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.name}</span>
                    <div className="attacker-bar-wrap">
                      <div
                        className={`attacker-bar ${d.status === 'hot' ? 'hot' : ''}`}
                        style={{ width: `${Math.min(100, (d.hits / Math.max(1, deckiesUnderSiege[0].hits)) * 100)}%` }}
                      />
                    </div>
                    <span className="dim" style={{ fontSize: '0.7rem', width: 32, textAlign: 'right' }}>{d.hits}</span>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState icon={Server} title="NO ACTIVITY" hint="all deckies quiet" />
            )}
          </div>

          <div className="logs-section">
            <div className="section-header">
              <div className="section-title">
                <Users size={16} />
                <span>TOP ATTACKERS</span>
              </div>
            </div>
            {topAttackers.length > 0 ? (
              <div className="panel-body">
                {topAttackers.map(a => (
                  <div
                    key={a.ip}
                    className="attacker-row"
                    onClick={() => window.dispatchEvent(new CustomEvent('decnet:cmd', { detail: { id: 'filter-attacker', payload: a.ip } }))}
                  >
                    <span className={`chip ${a.hot ? 'alert-chip' : 'dim-chip'}`} style={{ minWidth: 34, textAlign: 'center', justifyContent: 'center' }}>??</span>
                    <span className="matrix-text" style={{ flex: 1, fontSize: '0.7rem', fontVariantNumeric: 'tabular-nums', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.ip}</span>
                    <div className="attacker-bar-wrap">
                      <div
                        className={`attacker-bar ${a.hot ? 'hot' : ''}`}
                        style={{ width: `${a.pct}%` }}
                      />
                    </div>
                    <span className="dim" style={{ fontSize: '0.7rem', width: 32, textAlign: 'right' }}>{a.hits}</span>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState icon={ShieldOff} title="NO ATTACKERS YET" hint="nothing on the radar" />
            )}
          </div>
        </div>
      </div>

      {artifact && (
        <ArtifactDrawer
          decky={artifact.decky}
          storedAs={artifact.storedAs}
          fields={artifact.fields as Record<string, string>}
          onClose={() => setArtifact(null)}
        />
      )}
    </div>
  );
};

export default Dashboard;

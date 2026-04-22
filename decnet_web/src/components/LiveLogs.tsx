import React, { useEffect, useState, useRef, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Terminal, Search, BarChart3, ChevronLeft, ChevronRight,
  Play, Pause, Paperclip, Download, Radio, X as XIcon,
} from 'lucide-react';
import api from '../utils/api';
import { parseEventBody } from '../utils/parseEventBody';
import ArtifactDrawer from './ArtifactDrawer';
import EmptyState from './EmptyState/EmptyState';
import './Dashboard.css';
import './LiveLogs.css';

interface LogEntry {
  id: number;
  timestamp: string;
  decky: string;
  service: string;
  event_type: string;
  attacker_ip: string;
  raw_line: string;
  fields: string;
  msg: string;
  is_bounty?: boolean;
}

const LIMIT = 50;

const LiveLogs: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();

  const query = searchParams.get('q') || '';
  const timeRange = searchParams.get('time') || '1h';
  const isLive = searchParams.get('live') !== 'false';
  const page = parseInt(searchParams.get('page') || '1');

  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [totalLogs, setTotalLogs] = useState(0);
  const [loading, setLoading] = useState(true);
  const [streaming, setStreaming] = useState(isLive);
  const [searchInput, setSearchInput] = useState(query);
  const [selectedHour, setSelectedHour] = useState<number | null>(null);

  const eventSourceRef = useRef<EventSource | null>(null);

  const [artifact, setArtifact] = useState<{ decky: string; storedAs: string; fields: Record<string, any> } | null>(null);

  useEffect(() => { setSearchInput(query); }, [query]);

  const startTimeParam = (): string | null => {
    if (timeRange === 'all') return null;
    const minutes = timeRange === '15m' ? 15 : timeRange === '1h' ? 60 : timeRange === '24h' ? 1440 : 0;
    if (!minutes) return null;
    return new Date(Date.now() - minutes * 60000).toISOString().replace('T', ' ').substring(0, 19);
  };

  const fetchData = async () => {
    setLoading(true);
    try {
      const offset = (page - 1) * LIMIT;
      let url = `/logs?limit=${LIMIT}&offset=${offset}&search=${encodeURIComponent(query)}`;
      const startTime = startTimeParam();
      if (startTime) url += `&start_time=${startTime}`;
      const res = await api.get(url);
      setLogs(res.data.data);
      setTotalLogs(res.data.total);
    } catch (err) {
      console.error('Failed to fetch logs', err);
    } finally {
      setLoading(false);
    }
  };

  const setupSSE = () => {
    if (eventSourceRef.current) eventSourceRef.current.close();

    const token = localStorage.getItem('token');
    const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';
    let url = `${baseUrl}/stream?token=${token}&search=${encodeURIComponent(query)}`;
    const startTime = startTimeParam();
    if (startTime) url += `&start_time=${startTime}`;

    const es = new EventSource(url);
    eventSourceRef.current = es;

    es.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'logs') {
          setLogs(prev => [...payload.data, ...prev].slice(0, 500));
        } else if (payload.type === 'stats') {
          setTotalLogs(payload.data.total_logs);
        }
      } catch (err) {
        console.error('Failed to parse SSE payload', err);
      }
    };

    es.onerror = () => console.error('SSE connection lost, reconnecting...');
  };

  // Always seed with REST backlog on mount / filter changes.
  useEffect(() => {
    fetchData();
  }, [query, timeRange, page]);

  // SSE follows the streaming toggle independently.
  useEffect(() => {
    if (streaming) {
      setupSSE();
    } else if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, [streaming, query, timeRange]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setSearchParams({ q: searchInput, time: timeRange, live: streaming.toString(), page: '1' });
  };

  const handleToggleLive = () => {
    const newStreaming = !streaming;
    setStreaming(newStreaming);
    setSearchParams({ q: query, time: timeRange, live: newStreaming.toString(), page: '1' });
  };

  const handleTimeChange = (newTime: string) => {
    setSearchParams({ q: query, time: newTime, live: streaming.toString(), page: '1' });
  };

  const changePage = (newPage: number) => {
    setSearchParams({ q: query, time: timeRange, live: 'false', page: newPage.toString() });
  };

  const buckets = useMemo(() => {
    const b = Array.from({ length: 24 }, (_, i) => ({ i, count: 0, bounties: 0 }));
    logs.forEach(l => {
      const h = parseInt(String(l.timestamp).slice(11, 13), 10);
      if (!isNaN(h) && h >= 0 && h < 24) {
        b[h].count++;
        if (l.is_bounty) b[h].bounties++;
      }
    });
    return b;
  }, [logs]);
  const maxBar = Math.max(...buckets.map(b => b.count), 1);
  const peakHour = buckets.findIndex(b => b.count === maxBar);

  const filteredLogs = useMemo(() => {
    if (selectedHour == null) return logs;
    return logs.filter(l => parseInt(String(l.timestamp).slice(11, 13), 10) === selectedHour);
  }, [logs, selectedHour]);

  const handleExport = () => {
    const header = 'timestamp,decky,service,attacker_ip,event_type,msg';
    const rows = filteredLogs.map(l =>
      [l.timestamp, l.decky, l.service, l.attacker_ip, l.event_type, (l.msg || '').replace(/"/g, '""')]
        .map(v => `"${v ?? ''}"`).join(',')
    );
    const blob = new Blob([[header, ...rows].join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `decnet-logs-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const totalPages = Math.max(1, Math.ceil(totalLogs / LIMIT));

  return (
    <div className="logs-root">
      <div className="page-header">
        <div className="page-title-group">
          <h1>LOGS</h1>
          <span className="page-sub">
            {filteredLogs.length.toLocaleString()} SHOWN · {totalLogs.toLocaleString()} MATCHES · STREAM {streaming ? 'LIVE' : 'PAUSED'}
          </span>
        </div>
        <div className="actions">
          <button className={`btn ${streaming ? '' : 'violet'}`} onClick={handleToggleLive}>
            {streaming
              ? <><Pause size={12} className="fx-blink" /> PAUSE</>
              : <><Play size={12} /> GO LIVE</>}
          </button>
          <button className="btn ghost" onClick={handleExport} disabled={filteredLogs.length === 0}>
            <Download size={12} /> EXPORT
          </button>
        </div>
      </div>

      <form className="logs-controls" onSubmit={handleSearch}>
        <div className="search-container">
          <Search size={14} className="search-icon" />
          <input
            type="text"
            placeholder="Query (e.g. decky:decky-03 service:ssh attacker:89.248)"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
          {searchInput && (
            <button
              type="button"
              className="close-btn"
              onClick={() => { setSearchInput(''); setSearchParams({ q: '', time: timeRange, live: streaming.toString(), page: '1' }); }}
              style={{ background: 'transparent', border: 'none', color: 'inherit', cursor: 'pointer', padding: 0, display: 'flex' }}
              aria-label="Clear search"
            >
              <XIcon size={12} />
            </button>
          )}
        </div>
        <select
          className="time-select"
          value={timeRange}
          onChange={(e) => handleTimeChange(e.target.value)}
        >
          <option value="15m">LAST 15 MIN</option>
          <option value="1h">LAST 1 HOUR</option>
          <option value="24h">LAST 24 HOURS</option>
          <option value="all">ALL TIME</option>
        </select>
      </form>

      <div className="histogram-wrap">
        <div className="histogram-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <BarChart3 size={12} />
            <span>ATTACK VOLUME — PAST 24 HOURS</span>
            {selectedHour != null && (
              <span className="violet-accent" style={{ marginLeft: 8 }}>
                · {String(selectedHour).padStart(2, '0')}:00 SELECTED —
                <span className="clear-sel" onClick={() => setSelectedHour(null)}>clear</span>
              </span>
            )}
          </div>
          <span>PEAK: {maxBar} @ HOUR {String(peakHour).padStart(2, '0')}</span>
        </div>
        <div className="histogram">
          {buckets.map(b => (
            <div
              key={b.i}
              className={`bar ${selectedHour === b.i ? 'selected' : ''} ${b.bounties > 0 ? 'has-bounty' : ''}`}
              style={{ height: `${(b.count / maxBar) * 100}%` }}
              title={`${String(b.i).padStart(2, '0')}:00 — ${b.count} events${b.bounties ? `, ${b.bounties} bounties` : ''}`}
              onClick={() => setSelectedHour(selectedHour === b.i ? null : b.i)}
            />
          ))}
        </div>
        <div className="histogram-axis">
          <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:59</span>
        </div>
      </div>

      <div className="logs-section">
        <div className="section-header">
          <div className="section-title">
            <Terminal size={14} />
            <span>LOG EXPLORER</span>
          </div>
          <div className="section-actions">
            <span>SHOWING {filteredLogs.length} OF {totalLogs.toLocaleString()}</span>
            {!streaming && (
              <div className="pager" style={{ marginLeft: 16 }}>
                <span className="dim">Page {page} of {totalPages}</span>
                <button disabled={page === 1} onClick={() => changePage(page - 1)} aria-label="Previous page">
                  <ChevronLeft size={14} />
                </button>
                <button disabled={page >= totalPages} onClick={() => changePage(page + 1)} aria-label="Next page">
                  <ChevronRight size={14} />
                </button>
              </div>
            )}
          </div>
        </div>

        <div className="logs-table-container" style={{ maxHeight: 520 }}>
          <table className="logs-table">
            <thead>
              <tr>
                <th>TIME</th>
                <th>DECKY</th>
                <th>SVC</th>
                <th>ATTACKER</th>
                <th>EVENT</th>
              </tr>
            </thead>
            <tbody>
              {filteredLogs.length > 0 ? filteredLogs.map(log => {
                let parsedFields: Record<string, any> = {};
                if (log.fields) {
                  try { parsedFields = JSON.parse(log.fields); } catch { /* noop */ }
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
                const et = log.event_type && log.event_type !== '-' ? log.event_type : null;
                const headParts = [et, msgHead].filter(Boolean) as string[];
                const hasBadges = Object.keys(parsedFields).length > 0 || parsedFields.stored_as;

                return (
                  <tr key={log.id}>
                    <td className="t-time">{new Date(log.timestamp).toLocaleString()}</td>
                    <td className="t-decky">{log.decky}</td>
                    <td className="t-svc">{log.service}</td>
                    <td>{log.attacker_ip}</td>
                    <td className="t-event">
                      <div className="event-head">
                        {headParts.join(' · ')}
                        {msgTail && (
                          <span className="event-tail">
                            {headParts.length ? ' — ' : ''}{msgTail}
                          </span>
                        )}
                      </div>
                      {hasBadges && (
                        <div className="badges">
                          {parsedFields.stored_as && (
                            <button
                              className="artifact-btn"
                              onClick={() => setArtifact({
                                decky: log.decky,
                                storedAs: String(parsedFields.stored_as),
                                fields: parsedFields,
                              })}
                              title="Inspect captured artifact"
                            >
                              <Paperclip size={11} /> ARTIFACT
                            </button>
                          )}
                          {Object.entries(parsedFields)
                            .filter(([k]) => k !== 'meta_json_b64' && k !== 'stored_as')
                            .map(([k, v]) => (
                              <span key={k} className="field-badge">
                                <span className="k">{k}:</span>
                                {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                              </span>
                            ))}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              }) : (
                <tr>
                  <td colSpan={5}>
                    <EmptyState
                      icon={Radio}
                      title={loading ? 'RETRIEVING DATA…' : 'NO LOGS MATCHING CRITERIA'}
                      hint={loading ? undefined : 'adjust filters or wait for new events'}
                    />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {artifact && (
        <ArtifactDrawer
          decky={artifact.decky}
          storedAs={artifact.storedAs}
          fields={artifact.fields}
          onClose={() => setArtifact(null)}
        />
      )}
    </div>
  );
};

export default LiveLogs;

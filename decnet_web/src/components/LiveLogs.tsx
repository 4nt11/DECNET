import React, { useEffect, useState, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { 
  Terminal, Search, Activity, 
  ChevronLeft, ChevronRight, Play, Pause
} from 'lucide-react';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell
} from 'recharts';
import api from '../utils/api';
import './Dashboard.css';

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
}

interface HistogramData {
  time: string;
  count: number;
}

const LiveLogs: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  
  // URL-synced state
  const query = searchParams.get('q') || '';
  const timeRange = searchParams.get('time') || '1h';
  const isLive = searchParams.get('live') !== 'false';
  const page = parseInt(searchParams.get('page') || '1');

  // Local state
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [histogram, setHistogram] = useState<HistogramData[]>([]);
  const [totalLogs, setTotalLogs] = useState(0);
  const [loading, setLoading] = useState(true);
  const [streaming, setStreaming] = useState(isLive);
  const [searchInput, setSearchInput] = useState(query);
  
  const eventSourceRef = useRef<EventSource | null>(null);
  const limit = 50;

  // Sync search input if URL changes (e.g. back button)
  useEffect(() => {
    setSearchInput(query);
  }, [query]);

  const fetchData = async () => {
    if (streaming) return; // Don't fetch historical if streaming
    
    setLoading(true);
    try {
      const offset = (page - 1) * limit;
      let url = `/logs?limit=${limit}&offset=${offset}&search=${encodeURIComponent(query)}`;
      
      // Calculate time bounds for historical fetch
      const now = new Date();
      let startTime: string | null = null;
      if (timeRange !== 'all') {
        const minutes = timeRange === '15m' ? 15 : timeRange === '1h' ? 60 : timeRange === '24h' ? 1440 : 0;
        if (minutes > 0) {
          startTime = new Date(now.getTime() - minutes * 60000).toISOString();
          url += `&start_time=${startTime}`;
        }
      }

      const res = await api.get(url);
      setLogs(res.data.data);
      setTotalLogs(res.data.total);

      // Fetch histogram for historical view
      const histUrl = `/logs/histogram?search=${encodeURIComponent(query)}` + (startTime ? `&start_time=${startTime}` : '');
      const histRes = await api.get(histUrl);
      setHistogram(histRes.data);

    } catch (err) {
      console.error('Failed to fetch historical logs', err);
    } finally {
      setLoading(false);
    }
  };

  const setupSSE = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    const token = localStorage.getItem('token');
    const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';
    let url = `${baseUrl}/stream?token=${token}&search=${encodeURIComponent(query)}`;
    
    if (timeRange !== 'all') {
      const minutes = timeRange === '15m' ? 15 : timeRange === '1h' ? 60 : timeRange === '24h' ? 1440 : 0;
      if (minutes > 0) {
        const startTime = new Date(Date.now() - minutes * 60000).toISOString();
        url += `&start_time=${startTime}`;
      }
    }

    const es = new EventSource(url);
    eventSourceRef.current = es;

    es.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'logs') {
          setLogs(prev => [...payload.data, ...prev].slice(0, 500));
        } else if (payload.type === 'histogram') {
          setHistogram(payload.data);
        } else if (payload.type === 'stats') {
          setTotalLogs(payload.data.total_logs);
        }
      } catch (err) {
        console.error('Failed to parse SSE payload', err);
      }
    };

    es.onerror = () => {
      console.error('SSE connection lost, reconnecting...');
    };
  };

  useEffect(() => {
    if (streaming) {
      setupSSE();
      setLoading(false);
    } else {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      fetchData();
    }

    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    };
  }, [query, timeRange, streaming, page]);

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

  return (
    <div className="dashboard">
      {/* Control Bar */}
      <div className="logs-section" style={{ border: 'none', background: 'transparent', padding: 0 }}>
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: '16px', marginBottom: '24px' }}>
          <div className="search-container" style={{ flexGrow: 1, maxWidth: 'none' }}>
            <Search className="search-icon" size={18} />
            <input 
              type="text" 
              placeholder="Query logs (e.g. decky:decky-01 service:http attacker:192.168.1.5 status:failed)" 
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
            />
          </div>
          <select 
            value={timeRange} 
            onChange={(e) => handleTimeChange(e.target.value)}
            className="search-container"
            style={{ width: 'auto', color: 'var(--text-color)', cursor: 'pointer' }}
          >
            <option value="15m">LAST 15 MIN</option>
            <option value="1h">LAST 1 HOUR</option>
            <option value="24h">LAST 24 HOURS</option>
            <option value="all">ALL TIME</option>
          </select>
          <button 
            type="button"
            onClick={handleToggleLive}
            style={{ 
              display: 'flex', alignItems: 'center', gap: '8px', 
              border: `1px solid ${streaming ? 'var(--text-color)' : 'var(--border-color)'}`,
              color: streaming ? 'var(--text-color)' : 'var(--dim-color)',
              minWidth: '120px', justifyContent: 'center'
            }}
          >
            {streaming ? <><Play size={14} className="neon-blink" /> LIVE</> : <><Pause size={14} /> PAUSED</>}
          </button>
        </form>
      </div>

      {/* Histogram Chart */}
      <div className="logs-section" style={{ height: '200px', padding: '20px', marginBottom: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.7rem', color: 'var(--dim-color)' }}>
            <Activity size={12} /> ATTACK VOLUME OVER TIME
          </div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-color)' }}>
            MATCHES: {totalLogs.toLocaleString()}
          </div>
        </div>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={histogram}>
            <CartesianGrid strokeDasharray="3 3" stroke="#30363d" vertical={false} />
            <XAxis 
              dataKey="time" 
              hide 
            />
            <YAxis 
              stroke="#30363d" 
              fontSize={10} 
              tickFormatter={(val) => Math.floor(val).toString()}
            />
            <Tooltip 
              contentStyle={{ backgroundColor: '#0d1117', border: '1px solid #30363d', fontSize: '0.8rem' }}
              itemStyle={{ color: 'var(--text-color)' }}
              labelStyle={{ color: 'var(--dim-color)', marginBottom: '4px' }}
              cursor={{ fill: 'rgba(0, 255, 65, 0.05)' }}
            />
            <Bar dataKey="count" fill="var(--text-color)" radius={[2, 2, 0, 0]}>
              {histogram.map((entry, index) => (
                <Cell key={`cell-${index}`} fillOpacity={0.6 + (entry.count / (Math.max(...histogram.map(h => h.count)) || 1)) * 0.4} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Logs Table */}
      <div className="logs-section">
        <div className="section-header" style={{ display: 'flex', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Terminal size={20} />
            <h2>LOG EXPLORER</h2>
          </div>
          {!streaming && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <span className="dim" style={{ fontSize: '0.8rem' }}>
                Page {page} of {Math.ceil(totalLogs / limit)}
              </span>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button 
                  disabled={page === 1} 
                  onClick={() => changePage(page - 1)}
                  style={{ padding: '4px', border: '1px solid var(--border-color)', opacity: page === 1 ? 0.3 : 1 }}
                >
                  <ChevronLeft size={16} />
                </button>
                <button 
                  disabled={page >= Math.ceil(totalLogs / limit)} 
                  onClick={() => changePage(page + 1)}
                  style={{ padding: '4px', border: '1px solid var(--border-color)', opacity: page >= Math.ceil(totalLogs / limit) ? 0.3 : 1 }}
                >
                  <ChevronRight size={16} />
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="logs-table-container">
          <table className="logs-table">
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>DECKY</th>
                <th>SERVICE</th>
                <th>ATTACKER</th>
                <th>EVENT</th>
              </tr>
            </thead>
            <tbody>
              {logs.length > 0 ? logs.map(log => {
                let parsedFields: Record<string, any> = {};
                if (log.fields) {
                  try {
                    parsedFields = JSON.parse(log.fields);
                  } catch (e) {}
                }

                return (
                  <tr key={log.id}>
                    <td className="dim" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>{new Date(log.timestamp).toLocaleString()}</td>
                    <td className="violet-accent">{log.decky}</td>
                    <td className="matrix-text">{log.service}</td>
                    <td>{log.attacker_ip}</td>
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        <div style={{ fontWeight: 'bold', color: 'var(--text-color)', fontSize: '0.9rem' }}>
                          {log.event_type} {log.msg && log.msg !== '-' && <span style={{ fontWeight: 'normal', opacity: 0.8 }}>— {log.msg}</span>}
                        </div>
                        {Object.keys(parsedFields).length > 0 && (
                          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                            {Object.entries(parsedFields).map(([k, v]) => (
                              <span key={k} style={{ 
                                fontSize: '0.7rem', 
                                backgroundColor: 'rgba(0, 255, 65, 0.1)', 
                                padding: '2px 8px', 
                                borderRadius: '4px', 
                                border: '1px solid rgba(0, 255, 65, 0.3)',
                                wordBreak: 'break-all'
                              }}>
                                <span style={{ opacity: 0.6 }}>{k}:</span> {typeof v === 'object' ? JSON.stringify(v) : v}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              }) : (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', padding: '40px', opacity: 0.5 }}>
                    {loading ? 'RETRIEVING DATA...' : 'NO LOGS MATCHING CRITERIA'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default LiveLogs;

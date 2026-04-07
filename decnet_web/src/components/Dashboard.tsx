import React, { useEffect, useState } from 'react';
import api from '../utils/api';
import './Dashboard.css';
import { Shield, Users, Activity, Clock } from 'lucide-react';

interface Stats {
  total_logs: number;
  unique_attackers: number;
  active_deckies: number;
}

interface LogEntry {
  id: number;
  timestamp: string;
  decky: string;
  service: string;
  event_type: string | null;
  attacker_ip: string;
  raw_line: string;
}

interface DashboardProps {
  searchQuery: string;
}

const Dashboard: React.FC<DashboardProps> = ({ searchQuery }) => {
  const [stats, setStats] = useState<Stats | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const [statsRes, logsRes] = await Promise.all([
        api.get('/stats'),
        api.get('/logs', { params: { limit: 50, search: searchQuery } })
      ]);
      setStats(statsRes.data);
      setLogs(logsRes.data.data);
    } catch (err) {
      console.error('Failed to fetch dashboard data', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000); // Live update every 5s
    return () => clearInterval(interval);
  }, [searchQuery]);

  if (loading && !stats) return <div className="loader">INITIALIZING SENSORS...</div>;

  return (
    <div className="dashboard">
      <div className="stats-grid">
        <StatCard 
          icon={<Activity size={32} />} 
          label="TOTAL INTERACTIONS" 
          value={stats?.total_logs || 0} 
        />
        <StatCard 
          icon={<Users size={32} />} 
          label="UNIQUE ATTACKERS" 
          value={stats?.unique_attackers || 0} 
        />
        <StatCard 
          icon={<Shield size={32} />} 
          label="ACTIVE DECKIES" 
          value={stats?.active_deckies || 0} 
        />
      </div>

      <div className="logs-section">
        <div className="section-header">
          <Clock size={20} />
          <h2>LIVE INTERACTION LOG</h2>
        </div>
        <div className="logs-table-container">
          <table className="logs-table">
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>DECKY</th>
                <th>SERVICE</th>
                <th>ATTACKER IP</th>
                <th>EVENT</th>
              </tr>
            </thead>
            <tbody>
              {logs.length > 0 ? logs.map(log => (
                <tr key={log.id}>
                  <td className="dim">{new Date(log.timestamp).toLocaleString()}</td>
                  <td className="violet-accent">{log.decky}</td>
                  <td className="matrix-text">{log.service}</td>
                  <td>{log.attacker_ip}</td>
                  <td className="raw-line">{log.raw_line}</td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={5} style={{textAlign: 'center', padding: '40px'}}>NO INTERACTION DETECTED</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

interface StatCardProps {
  icon: React.ReactNode;
  label: string;
  value: number;
}

const StatCard: React.FC<StatCardProps> = ({ icon, label, value }) => (
  <div className="stat-card">
    <div className="stat-icon">{icon}</div>
    <div className="stat-content">
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value.toLocaleString()}</span>
    </div>
  </div>
);

export default Dashboard;

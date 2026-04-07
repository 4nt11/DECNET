import React from 'react';
import { Terminal } from 'lucide-react';
import './Dashboard.css';

const LiveLogs: React.FC = () => {
  return (
    <div className="logs-section">
      <div className="section-header">
        <Terminal size={20} />
        <h2>FULL LIVE LOG STREAM</h2>
      </div>
      <div style={{ padding: '40px', textAlign: 'center', opacity: 0.5 }}>
        <p>STREAM ESTABLISHED. WAITING FOR INCOMING DATA...</p>
        <p style={{ marginTop: '10px', fontSize: '0.8rem' }}>(Dedicated Live Logs view placeholder)</p>
      </div>
    </div>
  );
};

export default LiveLogs;

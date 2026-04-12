import React from 'react';
import { Settings } from 'lucide-react';
import './Dashboard.css';

const Config: React.FC = () => {
  return (
    <div className="logs-section">
      <div className="section-header">
        <Settings size={20} />
        <h2>SYSTEM CONFIGURATION</h2>
      </div>
      <div style={{ padding: '40px', textAlign: 'center', opacity: 0.5 }}>
        <p>CONFIGURATION READ-ONLY MODE ACTIVE.</p>
        <p style={{ marginTop: '10px', fontSize: '0.8rem' }}>(Config view placeholder)</p>
      </div>
    </div>
  );
};

export default Config;

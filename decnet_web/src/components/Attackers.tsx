import React from 'react';
import { Activity } from 'lucide-react';
import './Dashboard.css';

const Attackers: React.FC = () => {
  return (
    <div className="logs-section">
      <div className="section-header">
        <Activity size={20} />
        <h2>ATTACKER PROFILES</h2>
      </div>
      <div style={{ padding: '40px', textAlign: 'center', opacity: 0.5 }}>
        <p>NO ACTIVE THREATS PROFILED YET.</p>
        <p style={{ marginTop: '10px', fontSize: '0.8rem' }}>(Attackers view placeholder)</p>
      </div>
    </div>
  );
};

export default Attackers;

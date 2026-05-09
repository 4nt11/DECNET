import React from 'react';
import './ThemeLab.css';

/* Kitchen-sink theme lab.
 *
 * Dev-only page (gated upstream in App.tsx via isDeveloperMode()).
 * Subsequent tasks fill this in with every design-system primitive
 * and a Dark/Light toggle. For now: header stub so the route + gate
 * can land in isolation. */
const ThemeLab: React.FC = () => {
  return (
    <div className="theme-lab" data-testid="theme-lab">
      <header className="page-header">
        <h1>THEME LAB</h1>
        <p className="theme-lab-subtitle">
          dev only · primitive zoo for theme regression
        </p>
      </header>
    </div>
  );
};

export default ThemeLab;

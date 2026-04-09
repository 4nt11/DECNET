import React, { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import { Menu, X, Search, Activity, LayoutDashboard, Terminal, Settings, LogOut, Server } from 'lucide-react';
import api from '../utils/api';
import './Layout.css';

interface LayoutProps {
  children: React.ReactNode;
  onLogout: () => void;
  onSearch: (q: string) => void;
}

const Layout: React.FC<LayoutProps> = ({ children, onLogout, onSearch }) => {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [search, setSearch] = useState('');
  const [systemActive, setSystemActive] = useState(false);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSearch(search);
  };

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await api.get('/stats');
        setSystemActive(res.data.deployed_deckies > 0);
      } catch (err) {
        console.error('Failed to fetch system status', err);
      }
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="layout-container">
      {/* Sidebar */}
      <aside className={`sidebar ${sidebarOpen ? 'open' : 'closed'}`}>
        <div className="sidebar-header">
          <Activity size={24} className="violet-accent" />
          {sidebarOpen && <span className="logo-text">DECNET</span>}
          <button className="toggle-btn" onClick={() => setSidebarOpen(!sidebarOpen)}>
            {sidebarOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
        
        <nav className="sidebar-nav">
          <NavItem to="/" icon={<LayoutDashboard size={20} />} label="Dashboard" open={sidebarOpen} />
          <NavItem to="/fleet" icon={<Server size={20} />} label="Decoy Fleet" open={sidebarOpen} />
          <NavItem to="/live-logs" icon={<Terminal size={20} />} label="Live Logs" open={sidebarOpen} />
          <NavItem to="/attackers" icon={<Activity size={20} />} label="Attackers" open={sidebarOpen} />
          <NavItem to="/config" icon={<Settings size={20} />} label="Config" open={sidebarOpen} />
        </nav>

        <div className="sidebar-footer">
          <button className="logout-btn" onClick={onLogout}>
            <LogOut size={20} />
            {sidebarOpen && <span>Logout</span>}
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        {/* Topbar */}
        <header className="topbar">
          <form onSubmit={handleSearchSubmit} className="search-container">
            <Search size={18} className="search-icon" />
            <input 
              type="text" 
              placeholder="Search logs, deckies, IPs..." 
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </form>
          <div className="topbar-status">
             <span className="matrix-text" style={{ color: systemActive ? 'var(--text-color)' : 'var(--accent-color)' }}>
               SYSTEM: {systemActive ? 'ACTIVE' : 'INACTIVE'}
             </span>
          </div>
        </header>

        {/* Dynamic Content */}
        <div className="content-viewport">
          {children}
        </div>
      </main>
    </div>
  );
};

interface NavItemProps {
  to: string;
  icon: React.ReactNode;
  label: string;
  open: boolean;
}

const NavItem: React.FC<NavItemProps> = ({ to, icon, label, open }) => (
  <NavLink to={to} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`} end={to === '/'}>
    {icon}
    {open && <span className="nav-label">{label}</span>}
  </NavLink>
);

export default Layout;

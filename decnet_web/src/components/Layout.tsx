import React, { useState } from 'react';
import { Menu, X, Search, Activity, LayoutDashboard, Terminal, Settings, LogOut } from 'lucide-react';
import './Layout.css';

interface LayoutProps {
  children: React.ReactNode;
  onLogout: () => void;
  onSearch: (q: string) => void;
}

const Layout: React.FC<LayoutProps> = ({ children, onLogout, onSearch }) => {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [search, setSearch] = useState('');

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSearch(search);
  };

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
          <NavItem icon={<LayoutDashboard size={20} />} label="Dashboard" active open={sidebarOpen} />
          <NavItem icon={<Terminal size={20} />} label="Live Logs" open={sidebarOpen} />
          <NavItem icon={<Activity size={20} />} label="Attackers" open={sidebarOpen} />
          <NavItem icon={<Settings size={20} />} label="Config" open={sidebarOpen} />
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
             <span className="matrix-text neon-blink">SYSTEM: ACTIVE</span>
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
  icon: React.ReactNode;
  label: string;
  active?: boolean;
  open: boolean;
}

const NavItem: React.FC<NavItemProps> = ({ icon, label, active, open }) => (
  <div className={`nav-item ${active ? 'active' : ''}`}>
    {icon}
    {open && <span className="nav-label">{label}</span>}
  </div>
);

export default Layout;

import React, { useState, useEffect } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  Menu, X, Search, Activity, LayoutDashboard, Terminal, Settings, LogOut,
  Server, Archive, Package, Network, ChevronDown, ChevronRight, HardDrive,
  ShieldAlert, Bell, Webhook,
} from 'lucide-react';
import { prefetchRoute } from '../routePrefetch';
import './Layout.css';

type ThreatLevel = 'nominal' | 'elevated' | 'critical';

interface LayoutProps {
  children: React.ReactNode;
  onLogout: () => void;
  onSearch: (q: string) => void;
  onOpenCmd?: () => void;
  sector?: string;
  persona?: string;
  threat?: ThreatLevel;
  alertCount?: number;
  build?: string;
}

const ROUTE_LABELS: Record<string, string> = {
  '/': 'DASHBOARD',
  '/fleet': 'FLEET',
  '/mazenet': 'MAZENET',
  '/live-logs': 'LIVE LOGS',
  '/webhooks': 'WEBHOOKS',
  '/bounty': 'BOUNTY',
  '/attackers': 'ATTACKERS',
  '/config': 'CONFIG',
  '/swarm-updates': 'REMOTE UPDATES',
  '/swarm/hosts': 'SWARM HOSTS',
};

function labelForPath(pathname: string): string {
  if (ROUTE_LABELS[pathname]) return ROUTE_LABELS[pathname];
  const prefix = Object.keys(ROUTE_LABELS).find(p => p !== '/' && pathname.startsWith(p));
  return prefix ? ROUTE_LABELS[prefix] : pathname.replace(/^\//, '').toUpperCase();
}

function formatClock(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

const Layout: React.FC<LayoutProps> = ({
  children,
  onLogout,
  onSearch,
  onOpenCmd,
  sector = 'PRODUCTION',
  persona = 'ADMIN',
  threat: threatProp = 'nominal',
  alertCount: alertCountProp = 0,
  build = 'v0.1',
}) => {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [search, setSearch] = useState('');
  const [systemActive, setSystemActive] = useState(false);
  const [clockTime, setClockTime] = useState(() => formatClock(new Date()));
  const [threat, setThreat] = useState<ThreatLevel>(threatProp);
  const [alertCount, setAlertCount] = useState<number>(alertCountProp);
  const location = useLocation();

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSearch(search);
  };

  useEffect(() => {
    const onStats = (e: Event) => {
      const detail = (e as CustomEvent).detail;
      setSystemActive(detail.deployed_deckies > 0);
      if (detail.threat) setThreat(detail.threat as ThreatLevel);
      if (typeof detail.alert_count === 'number') setAlertCount(detail.alert_count);
    };
    window.addEventListener('decnet:stats', onStats);
    return () => window.removeEventListener('decnet:stats', onStats);
  }, []);

  useEffect(() => {
    const iv = setInterval(() => setClockTime(formatClock(new Date())), 1000);
    return () => clearInterval(iv);
  }, []);

  const routeLabel = labelForPath(location.pathname);
  const showThreat = threat !== 'nominal';
  const threatLabel = threat.toUpperCase();

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
          <NavItem to="/mazenet" icon={<Network size={20} />} label="MazeNET" open={sidebarOpen} />
          <NavGroup label="ALERTS" icon={<Bell size={20} />} open={sidebarOpen}>
            <NavItem
              to="/live-logs"
              icon={<Terminal size={18} />}
              label="Live Logs"
              open={sidebarOpen}
              indent
              badge={alertCount}
            />
            <NavItem
              to="/webhooks"
              icon={<Webhook size={18} />}
              label="Webhooks"
              open={sidebarOpen}
              indent
            />
          </NavGroup>
          <NavItem to="/bounty" icon={<Archive size={20} />} label="Bounty" open={sidebarOpen} />
          <NavItem to="/attackers" icon={<Activity size={20} />} label="Attackers" open={sidebarOpen} />
          <NavGroup label="SWARM" icon={<Network size={20} />} open={sidebarOpen}>
            <NavItem to="/swarm/hosts" icon={<HardDrive size={18} />} label="SWARM Hosts" open={sidebarOpen} indent />
            <NavItem to="/swarm-updates" icon={<Package size={18} />} label="Remote Updates" open={sidebarOpen} indent />
          </NavGroup>
          <NavItem to="/config" icon={<Settings size={20} />} label="Config" open={sidebarOpen} />
        </nav>

        <div className="sidebar-footer">
          <button className="logout-btn" onClick={onLogout}>
            <LogOut size={20} />
            {sidebarOpen && <span>Logout</span>}
          </button>
          {sidebarOpen && (
            <div className="sidebar-meta">
              <div>SECTOR · {sector.toUpperCase()}</div>
              <div>OPERATOR · {persona.toUpperCase()}</div>
              <div>BUILD · {build.toUpperCase()}</div>
            </div>
          )}
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        {/* Topbar */}
        <header className="topbar">
          <div className="topbar-left">
            <div className="crumbs">
              <span className="crumb-sector">{sector.toUpperCase()}</span>
              <span className="sep">/</span>
              <span>{routeLabel}</span>
            </div>
            <form onSubmit={handleSearchSubmit} className="search-container">
              <Search size={18} className="search-icon" />
              <input
                type="text"
                placeholder="Search logs, deckies, IPs..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                onFocus={() => onOpenCmd?.()}
              />
              <span className="search-kbd">Alt+K</span>
            </form>
          </div>

          <div className="topbar-right">
            {showThreat && (
              <div className="threat-level" title={`Threat: ${threatLabel}`}>
                <span className="dot" />
                <ShieldAlert size={12} />
                <span>THREAT: {threatLabel}</span>
              </div>
            )}
            <div className="topbar-status">
              <span
                className="matrix-text"
                style={{ color: systemActive ? 'var(--text-color)' : 'var(--accent-color)' }}
              >
                SYSTEM: {systemActive ? 'ACTIVE' : 'INACTIVE'}
              </span>
            </div>
            <div className="topbar-clock">{clockTime}</div>
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
  indent?: boolean;
  badge?: number;
}

const NavItem: React.FC<NavItemProps> = ({ to, icon, label, open, indent, badge }) => (
  <NavLink
    to={to}
    className={({ isActive }) => `nav-item ${isActive ? 'active' : ''} ${indent ? 'nav-subitem' : ''}`}
    end={to === '/'}
    onMouseEnter={() => prefetchRoute(to)}
    onFocus={() => prefetchRoute(to)}
  >
    {icon}
    {open && <span className="nav-label">{label}</span>}
    {open && badge !== undefined && badge > 0 && (
      <span className="nav-badge">{badge > 99 ? '99+' : badge}</span>
    )}
  </NavLink>
);

interface NavGroupProps {
  label: string;
  icon: React.ReactNode;
  open: boolean;
  children: React.ReactNode;
}

const NavGroup: React.FC<NavGroupProps> = ({ label, icon, open, children }) => {
  const [expanded, setExpanded] = useState(true);
  return (
    <div className="nav-group">
      <button
        type="button"
        className="nav-item nav-group-toggle"
        onClick={() => setExpanded((v) => !v)}
      >
        {icon}
        {open && (
          <>
            <span className="nav-label">{label}</span>
            <span className="nav-group-chevron">
              {expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
            </span>
          </>
        )}
      </button>
      {expanded && <div className="nav-group-children">{children}</div>}
    </div>
  );
};

export default Layout;

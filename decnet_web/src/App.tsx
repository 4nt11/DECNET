import { lazy, Suspense, useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import Login from './components/Login';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';
import CommandPalette from './components/CommandPalette/CommandPalette';
import ShortcutsHelp from './components/ShortcutsHelp/ShortcutsHelp';
import { ToastProvider } from './components/Toasts/ToastProvider';
import { useToast } from './components/Toasts/useToast';
import { useGlobalHotkeys } from './hooks/useGlobalHotkeys';

// Page components are code-split per route. Each lands as its own
// chunk and only downloads when the user navigates to that path —
// initial page-load stays slim. Dashboard stays eager because it's
// the landing page: lazy-loading it would Suspense-flicker on every
// login for zero gain.
const DeckyFleet     = lazy(() => import('./components/DeckyFleet'));
const LiveLogs       = lazy(() => import('./components/LiveLogs'));
const Webhooks       = lazy(() => import('./components/Webhooks'));
const Attackers      = lazy(() => import('./components/Attackers'));
const AttackerDetail = lazy(() => import('./components/AttackerDetail'));
const Config         = lazy(() => import('./components/Config'));
const Bounty         = lazy(() => import('./components/Bounty'));
const RemoteUpdates  = lazy(() => import('./components/RemoteUpdates'));
const SwarmHosts     = lazy(() => import('./components/SwarmHosts'));
const MazeNET        = lazy(() => import('./components/MazeNET/MazeNET'));
const TopologyList   = lazy(() => import('./components/TopologyList/TopologyList'));

/* Minimal fallback rendered while a lazy-loaded route chunk is in
 * flight. Matches the house "dim mono" voice — no spinner library,
 * no new CSS. Visible for a few frames on first navigation to a
 * route; cached thereafter. */
const RouteFallback: React.FC = () => (
  <div
    style={{
      padding: '48px',
      textAlign: 'center',
      opacity: 0.5,
      fontSize: '0.82rem',
      letterSpacing: '1.5px',
      fontFamily: 'var(--font-mono)',
    }}
  >
    LOADING…
  </div>
);

/* Unified MazeNET entrypoint: no ?topology → topology selector,
 * ?topology=<id> → editor bound to that topology. */
function MazeNETRoute() {
  const qs = typeof window !== 'undefined' ? window.location.search : '';
  const hasId = new URLSearchParams(qs).get('topology');
  return hasId ? <MazeNET /> : <TopologyList />;
}

function isTokenValid(token: string): boolean {
  try {
    const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    return typeof payload.exp === 'number' && payload.exp * 1000 > Date.now();
  } catch {
    return false;
  }
}

function getValidToken(): string | null {
  const stored = localStorage.getItem('token');
  if (stored && isTokenValid(stored)) return stored;
  if (stored) localStorage.removeItem('token');
  return null;
}

const ACTION_LABELS: Record<string, string> = {
  'deploy': 'DEPLOY · OPENING WIZARD',
  'pause-logs': 'STREAM · TOGGLE QUEUED',
  'mutate-all': 'MUTATE ALL · QUEUED',
  'export-bounty': 'EXPORT BOUNTY · QUEUED',
};

interface AuthedShellProps {
  onLogout: () => void;
  onSearch: (q: string) => void;
  searchQuery: string;
}

const AuthedShell: React.FC<AuthedShellProps> = ({ onLogout, onSearch, searchQuery }) => {
  const navigate = useNavigate();
  const { push } = useToast();
  const [cmdOpen, setCmdOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);

  useGlobalHotkeys({ cmdOpen, setCmdOpen, helpOpen, setHelpOpen });

  const handleAction = (id: string) => {
    if (id === 'shortcuts-help') { setHelpOpen(true); return; }
    if (id === 'deploy') navigate('/fleet');
    window.dispatchEvent(new CustomEvent('decnet:cmd', { detail: { id } }));
    push({ text: ACTION_LABELS[id] ?? `${id.toUpperCase()} · QUEUED`, tone: 'violet', icon: 'terminal' });
  };

  return (
    <>
      <Layout onLogout={onLogout} onSearch={onSearch} onOpenCmd={() => setCmdOpen(true)}>
        <Suspense fallback={<RouteFallback />}>
          <Routes>
            <Route path="/" element={<Dashboard searchQuery={searchQuery} />} />
            <Route path="/fleet" element={<DeckyFleet searchQuery={searchQuery} />} />
            <Route path="/topologies" element={<Navigate to="/mazenet" replace />} />
            <Route path="/mazenet" element={<MazeNETRoute />} />
            <Route path="/live-logs" element={<LiveLogs />} />
            <Route path="/webhooks" element={<Webhooks />} />
            <Route path="/bounty" element={<Bounty />} />
            <Route path="/attackers" element={<Attackers />} />
            <Route path="/attackers/:id" element={<AttackerDetail />} />
            <Route path="/config" element={<Config />} />
            <Route path="/swarm-updates" element={<RemoteUpdates />} />
            <Route path="/swarm/hosts" element={<SwarmHosts />} />
            <Route path="/swarm/enroll" element={<Navigate to="/swarm/hosts" replace />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Suspense>
      </Layout>
      <CommandPalette
        open={cmdOpen}
        onClose={() => setCmdOpen(false)}
        onNav={navigate}
        onAction={handleAction}
      />
      <ShortcutsHelp open={helpOpen} onClose={() => setHelpOpen(false)} />
    </>
  );
};

function App() {
  const [token, setToken] = useState<string | null>(getValidToken);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    const onAuthLogout = () => setToken(null);
    window.addEventListener('auth:logout', onAuthLogout);
    return () => window.removeEventListener('auth:logout', onAuthLogout);
  }, []);

  useEffect(() => {
    let accent = 'matrix';
    try {
      const raw = localStorage.getItem('decnet_tweaks');
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed?.accent === 'matrix' || parsed?.accent === 'violet') accent = parsed.accent;
      }
    } catch { /* fall through to default */ }
    document.documentElement.setAttribute('data-accent', accent);
  }, []);

  const handleLogin = (newToken: string) => setToken(newToken);
  const handleLogout = () => { localStorage.removeItem('token'); setToken(null); };
  const handleSearch = (query: string) => setSearchQuery(query);

  if (!token) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <Router>
      <ToastProvider>
        <AuthedShell onLogout={handleLogout} onSearch={handleSearch} searchQuery={searchQuery} />
      </ToastProvider>
    </Router>
  );
}

export default App;

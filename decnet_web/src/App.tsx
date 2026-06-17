// SPDX-License-Identifier: AGPL-3.0-or-later
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
import { isDeveloperMode } from './lib/devGate';
import { proRoutes } from '@pro';

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
const Identities    = lazy(() => import('./components/Identities'));
const IdentityDetail = lazy(() => import('./components/IdentityDetail'));
const Campaigns     = lazy(() => import('./components/Campaigns'));
const CampaignDetail = lazy(() => import('./components/CampaignDetail'));
const Orchestrator   = lazy(() => import('./components/Orchestrator'));
const PersonaGeneration = lazy(() => import('./components/PersonaGeneration'));
const SyntheticFiles = lazy(() => import('./components/SyntheticFiles/SyntheticFiles'));
const RealismConfig = lazy(() => import('./components/RealismConfig/RealismConfig'));
const CanaryTokens   = lazy(() => import('./components/CanaryTokens'));
const TopologyPersonaGeneration = lazy(() =>
  import('./components/PersonaGeneration').then((m) => ({ default: m.TopologyPersonaGeneration })),
);
const Config         = lazy(() => import('./components/Config'));
const Bounty         = lazy(() => import('./components/Bounty'));
const Credentials    = lazy(() => import('./components/Credentials'));
const RemoteUpdates  = lazy(() => import('./components/RemoteUpdates'));
const SwarmHosts     = lazy(() => import('./components/SwarmHosts'));
const MazeNET        = lazy(() => import('./components/MazeNET/MazeNET'));
const TopologyList   = lazy(() => import('./components/TopologyList/TopologyList'));
/* Dev-gated route: when VITE_DECNET_DEVELOPER is unset at build time,
 * isDeveloperMode() collapses to `false` and Vite tree-shakes both
 * the import below and the conditional <Route> out of the bundle. */
const ThemeLab       = lazy(() => import('./components/ThemeLab/ThemeLab'));

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
            <Route path="/credentials" element={<Credentials />} />
            <Route path="/attackers" element={<Attackers />} />
            <Route path="/attackers/:id" element={<AttackerDetail />} />
            <Route path="/identities" element={<Identities />} />
            <Route path="/identities/:id" element={<IdentityDetail />} />
            <Route path="/campaigns" element={<Campaigns />} />
            <Route path="/campaigns/:id" element={<CampaignDetail />} />
            <Route path="/orchestrator" element={<Orchestrator />} />
            <Route path="/persona-generation" element={<PersonaGeneration />} />
            <Route path="/synthetic-files" element={<SyntheticFiles />} />
            <Route path="/realism-config" element={<RealismConfig />} />
            <Route path="/canary-tokens" element={<CanaryTokens />} />
            <Route path="/topologies/:id/personas" element={<TopologyPersonaGeneration />} />
            <Route path="/config" element={<Config />} />
            <Route path="/swarm-updates" element={<RemoteUpdates />} />
            <Route path="/swarm/hosts" element={<SwarmHosts />} />
            <Route path="/swarm/enroll" element={<Navigate to="/swarm/hosts" replace />} />
            {isDeveloperMode() && (
              <Route path="/theme-lab" element={<ThemeLab />} />
            )}
            {/* Professional-tier pages. Empty in the community build (@pro -> stub). */}
            {proRoutes.map((r) => (
              <Route key={r.path} path={r.path} element={r.element} />
            ))}
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

    /* Theme hydration order on boot:
     *   1. localStorage `decnet_theme` — the saved user preference
     *      from the topbar Sun/Moon toggle. Default = 'dark'.
     *   2. sessionStorage `decnet_theme_lab` — dev-mode lab override
     *      (set from /theme-lab). Tab-scoped, wins on top so devs
     *      can A/B without clobbering their saved preference. */
    let theme: 'dark' | 'light' = 'dark';
    try {
      const saved = localStorage.getItem('decnet_theme');
      if (saved === 'light' || saved === 'dark') theme = saved;
    } catch { /* ignore */ }
    try {
      const lab = sessionStorage.getItem('decnet_theme_lab');
      if (lab === 'light' || lab === 'dark') theme = lab;
    } catch { /* ignore */ }
    document.documentElement.setAttribute('data-theme', theme);
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

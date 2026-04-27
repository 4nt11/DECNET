/* Prefetch-on-intent for lazy-loaded routes.
 *
 * Each key is a route path; each value is the same dynamic import()
 * used by React.lazy() in App.tsx. The bundler dedups by specifier
 * string, so a hover-triggered import here warms the exact chunk
 * React.lazy resolves on click — no double fetch, no separate chunk.
 *
 * A Set of already-fired paths prevents redundant imports on repeat
 * hovers; the module cache would short-circuit anyway, but skipping
 * the call avoids a microtask and makes intent obvious in devtools. */

type Loader = () => Promise<unknown>;

const loaders: Record<string, Loader> = {
  '/fleet':          () => import('./components/DeckyFleet'),
  '/mazenet':        () => import('./components/MazeNET/MazeNET'),
  '/topologies':     () => import('./components/TopologyList/TopologyList'),
  '/live-logs':      () => import('./components/LiveLogs'),
  '/webhooks':       () => import('./components/Webhooks'),
  '/bounty':         () => import('./components/Bounty'),
  '/attackers':      () => import('./components/Attackers'),
  '/config':         () => import('./components/Config'),
  '/swarm-updates':  () => import('./components/RemoteUpdates'),
  '/swarm/hosts':    () => import('./components/SwarmHosts'),
  '/orchestrator':   () => import('./components/Orchestrator'),
};

const fired = new Set<string>();

export function prefetchRoute(path: string): void {
  const loader = loaders[path];
  if (!loader || fired.has(path)) return;
  fired.add(path);
  loader().catch(() => {
    // Network hiccup on a speculative prefetch is a non-event —
    // React.lazy will re-try on actual navigation and surface the
    // real error there if it persists.
    fired.delete(path);
  });
}

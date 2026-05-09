import React, { useEffect, useMemo, useRef, useState } from 'react';
import { PlusCircle, Server } from '../icons';
import api, { type ApiError } from '../utils/api';
import { ARCHETYPES as FALLBACK_ARCHETYPES } from './MazeNET/data';
import { useToast } from './Toasts/useToast';
import { useServiceRegistry } from '../hooks/useServiceRegistry';
import './DeckyFleet.css';
import type {
  Decky,
  SwarmDeckyRaw,
  Archetype,
  FilterKey,
} from './DeckyFleet/types';
import {
  archetypeIcon as _archetypeIcon,
  dotFor as _dotFor,
} from './DeckyFleet/helpers';
import { DeckyInspectPanel } from './DeckyFleet/DeckyInspectPanel';
import { DeckyCard } from './DeckyFleet/DeckyCard';
import { DeployWizard } from './DeckyFleet/DeployWizard';
import { IntervalEditor } from './DeckyFleet/IntervalEditor';

// ─── Fleet page ──────────────────────────────────────────────────────────

interface FleetProps {
  searchQuery?: string;
}

const DeckyFleet: React.FC<FleetProps> = ({ searchQuery = '' }) => {
  const { push } = useToast();
  const serviceRegistry = useServiceRegistry();
  const [deckies, setDeckies] = useState<Decky[]>([]);
  const [loading, setLoading] = useState(true);
  const [mutating, setMutating] = useState<string | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [deployMode, setDeployMode] = useState<{ mode: string; swarm_host_count: number } | null>(null);
  const [filter, setFilter] = useState<FilterKey>('all');
  const [showDeploy, setShowDeploy] = useState(false);
  const [armed, setArmed] = useState<string | null>(null);
  const [tearingDown, setTearingDown] = useState<Set<string>>(new Set());
  const [archetypes, setArchetypes] = useState<Archetype[]>(FALLBACK_ARCHETYPES);
  const [localSearch, setLocalSearch] = useState<string>('');
  const [intervalEditor, setIntervalEditor] = useState<{ name: string; current: number | null } | null>(null);
  const [selectedDecky, setSelectedDecky] = useState<Decky | null>(null);
  const cardRefs = useRef<Map<string, HTMLDivElement>>(new Map());

  const lastSearchPropRef = useRef<string>(searchQuery);
  if (lastSearchPropRef.current !== searchQuery) {
    lastSearchPropRef.current = searchQuery;
    // Mirror the topbar search into local state; filter-decky events can
    // override it in-session.
    if (localSearch !== searchQuery) setLocalSearch(searchQuery);
  }

  const arm = (key: string) => {
    setArmed(key);
    window.setTimeout(() => setArmed((p) => (p === key ? null : p)), 4000);
  };

  const fetchDeckies = async (mode?: string) => {
    try {
      if (mode === 'swarm') {
        const res = await api.get<SwarmDeckyRaw[]>('/swarm/deckies');
        const normalized: Decky[] = res.data.map((s) => ({
          name: s.decky_name,
          ip: s.decky_ip || '—',
          services: s.services || [],
          distro: s.distro || 'unknown',
          hostname: s.hostname || '—',
          archetype: s.archetype,
          service_config: s.service_config || {},
          mutate_interval: s.mutate_interval,
          last_mutated: s.last_mutated || 0,
          swarm: {
            host_uuid: s.host_uuid,
            host_name: s.host_name,
            host_address: s.host_address,
            host_status: s.host_status,
            state: s.state,
            last_error: s.last_error,
            last_seen: s.last_seen,
          },
        }));
        setDeckies(normalized);
      } else {
        const res = await api.get<Decky[]>('/deckies');
        setDeckies(res.data);
      }
    } catch (err) {
      console.error('Failed to fetch decky fleet', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchRole = async () => {
    try {
      const res = await api.get('/config');
      setIsAdmin(res.data.role === 'admin');
    } catch {
      setIsAdmin(false);
    }
  };

  const fetchDeployMode = async () => {
    try {
      const res = await api.get('/system/deployment-mode');
      setDeployMode({ mode: res.data.mode, swarm_host_count: res.data.swarm_host_count });
      return res.data.mode as string;
    } catch {
      setDeployMode(null);
      return undefined;
    }
  };

  const fetchArchetypes = async () => {
    try {
      const res = await api.get<{ archetypes: { slug: string; display_name: string; services: string[] }[] }>(
        '/topologies/archetypes',
      );
      const list: Archetype[] = res.data.archetypes.map((a) => ({
        slug: a.slug,
        name: a.display_name,
        services: a.services,
        icon: _archetypeIcon(a.slug),
      }));
      if (list.length) setArchetypes(list);
    } catch {
      // fall back to bundled list
    }
  };

  const handleMutate = async (name: string): Promise<boolean> => {
    setMutating(name);
    try {
      await api.post(`/deckies/${name}/mutate`, {}, { timeout: 120000 });
      await fetchDeckies(deployMode?.mode);
      push({ text: `MUTATED · ${name.toUpperCase()}`, tone: 'matrix', icon: 'refresh-cw' });
      return true;
    } catch (err: unknown) {
      console.error('Failed to mutate', err);
      const e = err as { code?: string };
      const msg = e.code === 'ECONNABORTED'
        ? `MUTATION TIMED OUT · ${name.toUpperCase()}`
        : `MUTATION FAILED · ${name.toUpperCase()}`;
      push({ text: msg, tone: 'alert', icon: 'alert-triangle' });
      return false;
    } finally {
      setMutating(null);
    }
  };

  const handleMutateAll = async () => {
    if (!isAdmin) {
      push({ text: 'ADMIN REQUIRED', tone: 'alert', icon: 'alert-triangle' });
      return;
    }
    const targets = deckies.filter(d => !d.swarm || d.swarm.state === 'running');
    if (targets.length === 0) {
      push({ text: 'NO DECKIES TO MUTATE', tone: 'violet', icon: 'info' });
      return;
    }
    push({ text: `MUTATING FLEET · ${targets.length} DECKIES`, tone: 'violet', icon: 'refresh-cw' });
    let failed = 0;
    for (const d of targets) {
      const ok = await handleMutate(d.name);
      if (!ok) failed++;
    }
    if (failed === 0) {
      push({ text: 'FLEET MUTATED', tone: 'matrix', icon: 'check-circle' });
    } else {
      push({ text: `FLEET MUTATED · ${failed} FAILED`, tone: 'alert', icon: 'alert-triangle' });
    }
  };

  const handleIntervalChange = (name: string, current: number | null) => {
    setIntervalEditor({ name, current });
  };

  const handleIntervalSave = async (minutes: number | null) => {
    if (!intervalEditor) return;
    const { name } = intervalEditor;
    try {
      await api.put(`/deckies/${name}/mutate-interval`, { mutate_interval: minutes });
      setIntervalEditor(null);
      fetchDeckies(deployMode?.mode);
      push({
        text: minutes === null
          ? `INTERVAL · ${name.toUpperCase()} · DISABLED`
          : `INTERVAL · ${name.toUpperCase()} · ${minutes}m`,
        tone: 'matrix',
        icon: 'refresh-cw',
      });
    } catch (err) {
      console.error('Failed to update interval', err);
      push({ text: `INTERVAL UPDATE FAILED · ${name.toUpperCase()}`, tone: 'alert', icon: 'alert-triangle' });
    }
  };

  const handleTeardown = async (d: Decky) => {
    if (!d.swarm) return;
    const key = `td:${d.swarm.host_uuid}:${d.name}`;
    if (armed !== key) { arm(key); return; }
    setArmed(null);
    setTearingDown((prev) => new Set(prev).add(d.name));
    try {
      await api.post(`/swarm/hosts/${d.swarm.host_uuid}/teardown`, { decky_id: d.name });
      await fetchDeckies(deployMode?.mode);
      push({ text: `TORN DOWN · ${d.name.toUpperCase()}`, tone: 'matrix', icon: 'check-circle' });
    } catch (err: unknown) {
      const e = err as ApiError;
      push({
        text: `TEARDOWN FAILED · ${e?.response?.data?.detail || d.name}`,
        tone: 'alert',
        icon: 'alert-triangle',
      });
    } finally {
      setTearingDown((prev) => {
        const next = new Set(prev);
        next.delete(d.name);
        return next;
      });
    }
  };

  const handleInspect = (d: Decky) => {
    setSelectedDecky(d);
  };

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const mode = await fetchDeployMode();
      if (cancelled) return;
      await Promise.all([fetchDeckies(mode), fetchRole(), fetchArchetypes()]);
    })();
    const interval = window.setInterval(() => {
      fetchDeployMode().then((m) => fetchDeckies(m));
    }, 10000);
    return () => { cancelled = true; window.clearInterval(interval); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Phase-2 decnet:cmd bus: deploy, mutate-all, filter-decky
  useEffect(() => {
    const onCmd = (e: Event) => {
      const detail = (e as CustomEvent).detail as { id?: string; payload?: string };
      if (!detail?.id) return;
      if (detail.id === 'deploy') {
        setShowDeploy(true);
        return;
      }
      if (detail.id === 'mutate-all') {
        void handleMutateAll();
        return;
      }
    };
    window.addEventListener('decnet:cmd', onCmd);
    return () => window.removeEventListener('decnet:cmd', onCmd);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deckies, isAdmin]);

  const counts = useMemo(() => {
    const c = { all: deckies.length, active: 0, hot: 0, idle: 0 } as Record<FilterKey, number>;
    for (const d of deckies) {
      const s = _dotFor(d);
      c[s] += 1;
    }
    return c;
  }, [deckies]);

  const visible = useMemo(() => {
    const base = filter === 'all' ? deckies : deckies.filter((d) => _dotFor(d) === filter);
    const q = localSearch.trim().toLowerCase();
    if (!q) return base;
    return base.filter((d) =>
      d.name.toLowerCase().includes(q)
      || (d.ip || '').toLowerCase().includes(q)
      || (d.hostname || '').toLowerCase().includes(q),
    );
  }, [deckies, filter, localSearch]);
  const isSwarm = deployMode?.mode === 'swarm';

  if (loading) {
    return (
      <div className="fleet-root">
        <div className="dim" style={{ padding: '40px', textAlign: 'center', letterSpacing: 2 }}>
          SCANNING NETWORK FOR DECOYS...
        </div>
      </div>
    );
  }

  return (
    <div className="fleet-root">
      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Server size={22} className="violet-accent" />
            <h1>DECOY FLEET</h1>
          </div>
          <span className="page-sub">
            {deckies.length} DECKIES DEPLOYED · {counts.active + counts.hot} ACTIVE · {counts.hot} UNDER SIEGE
            {deployMode && (
              <> · [{isSwarm ? `SWARM × ${deployMode.swarm_host_count}` : 'UNIHOST'}]</>
            )}
          </span>
        </div>
        <div className="actions">
          <div className="fleet-filter-group">
            {([['all', 'ALL'], ['active', 'ACTIVE'], ['hot', 'HOT'], ['idle', 'IDLE']] as [FilterKey, string][]).map(
              ([v, l]) => (
                <button
                  key={v}
                  onClick={() => setFilter(v)}
                  className={`fleet-filter-btn ${filter === v ? 'active' : ''}`}
                >
                  {l} {counts[v]}
                </button>
              ),
            )}
          </div>
          {isAdmin && (
            <button className="btn violet" onClick={() => setShowDeploy(true)}>
              <PlusCircle size={12} /> DEPLOY DECKIES
            </button>
          )}
        </div>
      </div>

      <div className="grid-fleet">
        {visible.length === 0 ? (
          <div className="fleet-empty">
            <Server size={32} className="dim" />
            <span className="dim">
              {deckies.length === 0
                ? 'NO DECOYS DEPLOYED IN THIS SECTOR'
                : 'NO DECOYS MATCH CURRENT FILTER'}
            </span>
            {isAdmin && deckies.length === 0 && (
              <button className="btn violet" onClick={() => setShowDeploy(true)}>
                <PlusCircle size={12} /> DEPLOY DECKIES
              </button>
            )}
          </div>
        ) : (
          visible.map((d) => (
            <DeckyCard
              key={d.name}
              decky={d}
              mutating={mutating === d.name}
              isAdmin={isAdmin}
              armed={armed}
              tdBusy={tearingDown.has(d.name) || d.swarm?.state === 'tearing_down'}
              onForce={(name) => { void handleMutate(name); }}
              onTeardown={handleTeardown}
              onIntervalChange={handleIntervalChange}
              onInspect={handleInspect}
              innerRef={(el: HTMLDivElement | null) => {
                if (el) cardRefs.current.set(d.name, el);
                else cardRefs.current.delete(d.name);
              }}
              availableServices={serviceRegistry.perDecky}
              onServicesChanged={(name, services) => {
                setDeckies((prev) => prev.map((row) =>
                  row.name === name ? { ...row, services } : row,
                ));
              }}
              onTarpitResult={(_name, ok, message) => {
                push({
                  text: message,
                  tone: ok ? 'matrix' : 'alert',
                  icon: ok ? 'shield' : 'alert-triangle',
                });
              }}
            />
          ))
        )}
      </div>

      <DeployWizard
        open={showDeploy}
        archetypes={archetypes}
        fleetSize={deckies.length}
        onClose={() => setShowDeploy(false)}
        onComplete={(count) => {
          setShowDeploy(false);
          fetchDeckies(deployMode?.mode);
          push({
            text: `DEPLOYED · ${count} DECK${count === 1 ? 'Y' : 'IES'}`,
            tone: 'matrix',
            icon: 'check-circle',
          });
        }}
      />

      <IntervalEditor
        key={intervalEditor?.name ?? 'closed'}
        open={intervalEditor !== null}
        deckyName={intervalEditor?.name ?? ''}
        current={intervalEditor?.current ?? null}
        onClose={() => setIntervalEditor(null)}
        onSave={handleIntervalSave}
      />

      {selectedDecky && (
        <DeckyInspectPanel
          decky={selectedDecky}
          onClose={() => setSelectedDecky(null)}
        />
      )}
    </div>
  );
};

export default DeckyFleet;

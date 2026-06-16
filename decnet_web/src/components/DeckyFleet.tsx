// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Server } from '../icons';
import { useToast } from './Toasts/useToast';
import { useServiceRegistry } from '../hooks/useServiceRegistry';
import './DeckyFleet.css';
import type { Decky, FilterKey } from './DeckyFleet/types';
import { dotFor } from './DeckyFleet/helpers';
import { useDeckyFleet } from './DeckyFleet/useDeckyFleet';
import { DeckyInspectPanel } from './DeckyFleet/DeckyInspectPanel';
import { DeckyCard } from './DeckyFleet/DeckyCard';
import { DeployWizard } from './DeckyFleet/DeployWizard';
import { IntervalEditor } from './DeckyFleet/IntervalEditor';
import { DeckyFilters } from './DeckyFleet/DeckyFilters';
import { DeckyGridEmpty } from './DeckyFleet/DeckyGridEmpty';

interface FleetProps {
  searchQuery?: string;
}

const DeckyFleet: React.FC<FleetProps> = ({ searchQuery = '' }) => {
  const { push } = useToast();
  const serviceRegistry = useServiceRegistry();
  const fleet = useDeckyFleet();
  const {
    deckies, loading, isAdmin, deployMode, archetypes, isSwarm,
    mutating, tearingDown,
    mutate, setMutateInterval, teardown, applyServicesChange, refresh,
  } = fleet;

  // Pure UI state (no data lifecycle).
  const [filter, setFilter] = useState<FilterKey>('all');
  const [showDeploy, setShowDeploy] = useState(false);
  const [armed, setArmed] = useState<string | null>(null);
  const [localSearch, setLocalSearch] = useState<string>('');
  const [intervalEditor, setIntervalEditor] = useState<{ name: string; current: number | null } | null>(null);
  const [selectedDecky, setSelectedDecky] = useState<Decky | null>(null);
  const cardRefs = useRef<Map<string, HTMLDivElement>>(new Map());

  // Mirror the topbar search prop into local state; filter-decky events
  // can override it in-session.
  const lastSearchPropRef = useRef<string>(searchQuery);
  if (lastSearchPropRef.current !== searchQuery) {
    lastSearchPropRef.current = searchQuery;
    if (localSearch !== searchQuery) setLocalSearch(searchQuery);
  }

  const arm = (key: string) => {
    setArmed(key);
    window.setTimeout(() => setArmed((p) => (p === key ? null : p)), 4000);
  };

  // Toast-wrapping handlers — the hook returns discriminated results,
  // and the page decides how to surface them in the toast lane.
  const handleMutate = async (name: string): Promise<boolean> => {
    const r = await mutate(name);
    if (r.ok) {
      push({ text: `MUTATED · ${name.toUpperCase()}`, tone: 'matrix', icon: 'refresh-cw' });
      return true;
    }
    const msg = r.reason === 'timeout'
      ? `MUTATION TIMED OUT · ${name.toUpperCase()}`
      : `MUTATION FAILED · ${name.toUpperCase()}`;
    push({ text: msg, tone: 'alert', icon: 'alert-triangle' });
    return false;
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
    const ok = await setMutateInterval(name, minutes);
    if (ok) {
      setIntervalEditor(null);
      push({
        text: minutes === null
          ? `INTERVAL · ${name.toUpperCase()} · DISABLED`
          : `INTERVAL · ${name.toUpperCase()} · ${minutes}m`,
        tone: 'matrix',
        icon: 'refresh-cw',
      });
    } else {
      push({ text: `INTERVAL UPDATE FAILED · ${name.toUpperCase()}`, tone: 'alert', icon: 'alert-triangle' });
    }
  };

  // Two-step teardown: first click arms the button, second click within
  // 4s actually fires the POST. Keeps swarm hosts safe from misclicks.
  const handleTeardown = async (d: Decky) => {
    const key = `td:${d.swarm?.host_uuid ?? 'local'}:${d.name}`;
    if (armed !== key) { arm(key); return; }
    setArmed(null);
    const r = await teardown(d);
    if (r.ok) {
      push({ text: `TORN DOWN · ${d.name.toUpperCase()}`, tone: 'matrix', icon: 'check-circle' });
    } else {
      push({ text: `TEARDOWN FAILED · ${r.reason}`, tone: 'alert', icon: 'alert-triangle' });
    }
  };

  // decnet:cmd bus: deploy + mutate-all are wired here because they
  // dispatch UI state and a toast-wrapped operation respectively.
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
      const s = dotFor(d);
      c[s] += 1;
    }
    return c;
  }, [deckies]);

  const visible = useMemo(() => {
    const base = filter === 'all' ? deckies : deckies.filter((d) => dotFor(d) === filter);
    const q = localSearch.trim().toLowerCase();
    if (!q) return base;
    return base.filter((d) =>
      d.name.toLowerCase().includes(q)
      || (d.ip || '').toLowerCase().includes(q)
      || (d.hostname || '').toLowerCase().includes(q),
    );
  }, [deckies, filter, localSearch]);

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
        <DeckyFilters
          filter={filter}
          setFilter={setFilter}
          counts={counts}
          isAdmin={isAdmin}
          onDeploy={() => setShowDeploy(true)}
        />
      </div>

      <div className="grid-fleet">
        {visible.length === 0 ? (
          <DeckyGridEmpty
            fleetEmpty={deckies.length === 0}
            isAdmin={isAdmin}
            onDeploy={() => setShowDeploy(true)}
          />
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
              onInspect={(decky) => setSelectedDecky(decky)}
              innerRef={(el: HTMLDivElement | null) => {
                if (el) cardRefs.current.set(d.name, el);
                else cardRefs.current.delete(d.name);
              }}
              availableServices={serviceRegistry.perDecky}
              onServicesChanged={applyServicesChange}
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

      {/* Mounted only while open so closing tears down the wizard's hooks
          (lifecycle polling, the auto-close effect). Leaving it permanently
          mounted kept those effects alive after close and, combined with the
          inline onComplete below, drove a runaway /deckies + toast loop. */}
      {showDeploy && (
        <DeployWizard
          open={showDeploy}
          archetypes={archetypes}
          fleetSize={deckies.length}
          onClose={() => setShowDeploy(false)}
          onComplete={(count) => {
            setShowDeploy(false);
            void refresh();
            push({
              text: `DEPLOYED · ${count} DECK${count === 1 ? 'Y' : 'IES'}`,
              tone: 'matrix',
              icon: 'check-circle',
            });
          }}
        />
      )}

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

// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  PanelRightOpen, PanelRightClose, PanelLeftOpen, PanelLeftClose,
  Maximize2, Minimize2, RotateCcw, UploadCloud, ArrowLeft,
  Server, Mail,
} from '../../icons';
import './MazeNET.css';
import axios from '../../utils/api';
import { useSwarmHosts } from '../../hooks/useSwarmHosts';
import Palette from './Palette';
import Canvas from './Canvas';
import Inspector from './Inspector';
import type { Selection } from './Inspector';
import ContextMenu from './ContextMenu';
import type { Net, MazeNode, DeckyNode } from './types';
import type { Archetype } from './data';
import { useMazeApi } from './useMazeApi';
import type { DeckyRow } from './useMazeApi';
import { useTopologyEditor } from './useTopologyEditor';
import { useMazeInteraction, type PaletteDrag } from './useMazeInteraction';
import { useLayoutPersistor } from './useMazeLayoutStore';
import { useFullscreenMode } from './useFullscreenMode';
import { useTopologyData } from './useTopologyData';
import { useMazeContextMenu } from './useMazeContextMenu';
import { useToast } from '../Toasts/useToast';
import { useServiceRegistry } from '../../hooks/useServiceRegistry';
import AddServiceConfigModal from '../AddServiceConfigModal';

/* Short unique suffix for default names — avoids the DB uniqueness
 * constraint regardless of delete/re-add sequencing on the client. */
const tempIdSuffix = (): string => {
  const r = typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID().replace(/-/g, '')
    : Math.random().toString(16).slice(2);
  return r.slice(0, 4);
};

const NET_GRID_W    = 300;
const NET_GRID_H    = 240;
const NET_GRID_GAP  = 40;
const NET_GRID_COLS = 3;

async function _dropNetwork(
  drag: PaletteDrag,
  topologyId: string,
  nets: Net[],
  api: ReturnType<typeof useMazeApi>,
  editor: ReturnType<typeof useTopologyEditor>,
  setNets: React.Dispatch<React.SetStateAction<Net[]>>,
  setNodes: React.Dispatch<React.SetStateAction<MazeNode[]>>,
  flashErr: (err: unknown, fallback: string) => void,
): Promise<void> {
  const isDmz = drag.kind === 'network-dmz';
  if (isDmz && nets.some((n) => n.kind === 'dmz')) {
    flashErr(null, 'topology already has a DMZ');
    return;
  }
  const i = nets.filter((n) => n.kind !== 'internet').length;
  const x = NET_GRID_GAP + (i % NET_GRID_COLS) * (NET_GRID_W + NET_GRID_GAP);
  const y = NET_GRID_GAP + Math.floor(i / NET_GRID_COLS) * (NET_GRID_H + NET_GRID_GAP);
  const name = isDmz ? `dmz-${tempIdSuffix()}` : `subnet-${tempIdSuffix()}`;
  try {
    const subnet = await api.getNextSubnet().catch(() => undefined);
    const lanRes = await editor.createLan(topologyId, { name, is_dmz: isDmz, x, y, ...(subnet ? { subnet } : {}) });
    if (lanRes.kind !== 'applied') {
      const tempId = `pending-lan-${name}`;
      setNets((p) => [...p, {
        id: tempId, name, label: name.toUpperCase(),
        cidr: subnet ?? '', kind: isDmz ? 'dmz' : 'subnet',
        x, y, w: NET_GRID_W, h: NET_GRID_H, pending: true,
      }]);
      return;
    }
    const lan = lanRes.data;
    setNets((p) => [...p, {
      id: lan.id, name: lan.name, label: lan.name.toUpperCase(), cidr: lan.subnet,
      kind: isDmz ? 'dmz' : 'subnet', x, y, w: NET_GRID_W, h: NET_GRID_H,
    }]);
    if (isDmz) {
      const gwName = `dmz-gateway-${tempIdSuffix()}`;
      const gwRes = await editor.addDeckyToLan(
        topologyId,
        { name: gwName, services: ['ssh'], x: 20, y: 40,
          decky_config: { archetype: 'deaddeck', forwards_l3: true } },
        lan.id, lan.name,
        { is_bridge: true, forwards_l3: true },
      );
      if (gwRes.kind !== 'applied') return;
      const gw = gwRes.data;
      setNodes((p) => [...p, {
        kind: 'decky', id: gw.uuid, netId: lan.id, name: gw.name,
        archetype: 'deaddeck', services: ['ssh'], status: 'idle',
        x: 20, y: 40, decky_config: { forwards_l3: true },
      } as DeckyNode]);
    }
  } catch (err) {
    flashErr(err, 'create network failed');
  }
}

async function _dropArchetype(
  drag: PaletteDrag,
  world: { x: number; y: number },
  overNetId: string,
  topologyId: string,
  nets: Net[],
  archetypes: Archetype[],
  editor: ReturnType<typeof useTopologyEditor>,
  setNodes: React.Dispatch<React.SetStateAction<MazeNode[]>>,
  flashErr: (err: unknown, fallback: string) => void,
): Promise<void> {
  const net = nets.find((n) => n.id === overNetId);
  if (!net) return;
  const arch = archetypes.find((a) => a.slug === drag.slug);
  const dServices = drag.services ?? arch?.services ?? [];
  const nx = Math.max(8, Math.round(world.x - net.x - 70));
  const ny = Math.max(28, Math.round(world.y - net.y - 24));
  const name = `decky-${tempIdSuffix()}`;
  try {
    const dRes = await editor.addDeckyToLan(
      topologyId,
      { name, services: dServices, x: nx, y: ny, decky_config: { archetype: drag.slug } },
      overNetId, net.name,
    );
    if (dRes.kind !== 'applied') return;
    const decky = dRes.data;
    setNodes((p) => [...p, {
      kind: 'decky', id: decky.uuid, netId: overNetId, name: decky.name,
      archetype: drag.slug, services: dServices, status: 'idle', x: nx, y: ny,
    } as DeckyNode]);
  } catch (err) {
    flashErr(err, 'create decky failed');
  }
}

async function _dropService(
  drag: PaletteDrag,
  overNodeId: string,
  topologyId: string,
  nodes: MazeNode[],
  topoStatus: string,
  requestAddService: (name: string, slug: string) => void,
  editor: ReturnType<typeof useTopologyEditor>,
  setNodes: React.Dispatch<React.SetStateAction<MazeNode[]>>,
  flashErr: (err: unknown, fallback: string) => void,
): Promise<void> {
  const target = nodes.find((n) => n.id === overNodeId);
  if (!target || target.kind !== 'decky') return;
  if (target.services.includes(drag.slug)) return;
  // Active/degraded topologies route through the live W3 endpoint — the
  // design-time mutator queue would silently enqueue and the chip would never
  // visibly land. Schema-driven services pop the config modal; empty-schema
  // services auto-confirm and short-circuit.
  if (topoStatus === 'active' || topoStatus === 'degraded') {
    requestAddService(target.name, drag.slug);
    return;
  }
  const nextServices = [...target.services, drag.slug];
  try {
    const r = await editor.updateDecky(topologyId, overNodeId, target.name, { services: nextServices });
    if (r.kind !== 'applied') return;
    setNodes((p) => p.map((n) => n.id === overNodeId && n.kind === 'decky'
      ? { ...n, services: nextServices }
      : n));
  } catch (err) {
    flashErr(err, 'update services failed');
  }
}

const MazeNET: React.FC = () => {
  const api = useMazeApi();
  const navigate = useNavigate();
  const { push: pushToast } = useToast();
  const [params] = useSearchParams();
  const topologyId = params.get('topology') ?? '';

  const { byUuid: hostsByUuid } = useSwarmHosts();
  const data = useTopologyData(api, topologyId);
  const {
    nets, setNets, nodes, setNodes, edges, setEdges,
    topoMeta, services, archetypes,
    loadErr, actionErr, flashErr,
    deploying, onDeploy,
    streamLive, lastEventAt, streamEnabled,
    refetch,
  } = data;
  const { status: topoStatus, name: topoName, version: topoVersion,
          targetHost: topoTargetHost, mode: topoMode } = topoMeta;
  const [selection, setSelection] = useState<Selection>(null);
  const [inspectorOpen, setInspectorOpen] = useState(true);
  const [paletteOpen, setPaletteOpen] = useState(true);
  const { fullscreen, toggle: toggleFullscreen } = useFullscreenMode();

  useLayoutPersistor(topologyId || null, nets, nodes);

  const canvasRef = useRef<HTMLDivElement>(null);

  const editor = useTopologyEditor({ api, topoStatus, topoVersion });

  /* ── Live service mutation (W3 endpoints) — hoisted above palette
     drop so onPaletteDrop's deps can reference it without hitting the
     const TDZ.  Optimistic local update; SSE forwarder reconciles
     cross-tab. */
  const serviceRegistry = useServiceRegistry();

  const liveAddService = useCallback(async (
    nodeName: string,
    slug: string,
    config: Record<string, unknown> = {},
  ) => {
    const { data } = await axios.post<{ services: string[] }>(
      `/topologies/${encodeURIComponent(topologyId)}/deckies/${encodeURIComponent(nodeName)}/services`,
      { name: slug, config },
    );
    setNodes((p) => p.map((x) => x.kind === 'decky' && x.name === nodeName
      ? { ...x, services: data.services } : x));
  }, [topologyId]);

  // Pending add for the schema-driven config modal — both the palette
  // drag-drop and the Inspector ADD SERVICE picker funnel through here so
  // operators get the same "configure on first up" flow either way.
  const [pendingAddSvc, setPendingAddSvc] = useState<{ deckyName: string; slug: string } | null>(null);

  const requestAddService = useCallback((nodeName: string, slug: string) => {
    setPendingAddSvc({ deckyName: nodeName, slug });
  }, []);

  const confirmAddService = useCallback(async (
    nodeName: string, slug: string, cfg: Record<string, unknown>,
  ) => {
    try {
      await liveAddService(nodeName, slug, cfg);
      setPendingAddSvc(null);
    } catch (err) {
      flashErr(err, 'add service failed');
      throw err;
    }
  }, [liveAddService, flashErr]);

  const liveRemoveService = useCallback(async (nodeName: string, slug: string) => {
    const { data } = await axios.delete<{ services: string[] }>(
      `/topologies/${encodeURIComponent(topologyId)}/deckies/${encodeURIComponent(nodeName)}/services/${encodeURIComponent(slug)}`,
    );
    setNodes((p) => p.map((x) => x.kind === 'decky' && x.name === nodeName
      ? { ...x, services: data.services } : x));
  }, [topologyId]);

  /* forwards_l3 toggle.  Active topologies require the destructive
     base-recreate path on the backend, gated by force: true; the
     Inspector is responsible for confirming with the user before this
     fires. */
  const toggleGateway = useCallback(async (nodeId: string, nextValue: boolean) => {
    const node = nodes.find((n) => n.id === nodeId);
    if (!node || node.kind !== 'decky') return;
    const live = topoStatus === 'active' || topoStatus === 'degraded';
    const r = await editor.updateDecky(
      topologyId, nodeId, node.name,
      { decky_config: { ...(node.decky_config ?? {}), forwards_l3: nextValue } } as Partial<DeckyRow>,
      live ? { force: true } : undefined,
    );
    // Optimistic local update — pending path returns 'applied'
    // synchronously; active path returns 'enqueued' and the
    // mutation.applied SSE will refetch shortly.  Either way, paint
    // the change immediately so the toggle feels responsive.
    setNodes((prev) => prev.map((n) =>
      n.id === nodeId && n.kind === 'decky'
        ? {
          ...n,
          decky_config: { ...(n.decky_config ?? {}), forwards_l3: nextValue },
        }
        : n,
    ));
    if (r.kind === 'enqueued') {
      pushToast({
        tone: 'violet',
        text: `Gateway ${nextValue ? 'promotion' : 'demotion'} queued — base recreate in flight.`,
      });
    }
  }, [editor, nodes, pushToast, topoStatus, topologyId]);

  /* ── Palette drop — create LANs / deckies / services via REST ─── */
  const onPaletteDrop = useCallback(
    async (drag: PaletteDrag, world: { x: number; y: number }, overNetId: string | null, overNodeId: string | null) => {
      if (!topologyId) return;
      if (drag.kind === 'network-subnet' || drag.kind === 'network-dmz') {
        await _dropNetwork(drag, topologyId, nets, api, editor, setNets, setNodes, flashErr);
      } else if (drag.kind === 'archetype' && overNetId) {
        await _dropArchetype(drag, world, overNetId, topologyId, nets, archetypes, editor, setNodes, flashErr);
      } else if (drag.kind === 'service' && overNodeId) {
        await _dropService(drag, overNodeId, topologyId, nodes, topoStatus, requestAddService, editor, setNodes, flashErr);
      }
    },
    [api, archetypes, editor, flashErr, nets, nodes, topologyId, topoStatus, requestAddService],
  );

  /* ── Cross-net reparent via node drag (detach + attach edge) ─── */
  const onReparent = useCallback(async (nodeId: string, fromNetId: string, toNetId: string) => {
    if (!topologyId) return;
    try {
      const { data: detail } = await axios.get(`/topologies/${topologyId}`);
      const existingEdge = (detail.edges ?? []).find(
        (e: { decky_uuid: string; lan_id: string; id: string }) =>
          e.decky_uuid === nodeId && e.lan_id === fromNetId,
      );
      const node = nodes.find((n) => n.id === nodeId);
      const fromNet = nets.find((n) => n.id === fromNetId);
      const toNet = nets.find((n) => n.id === toNetId);
      const nodeName = node?.kind === 'decky' ? node.name : '';
      if (existingEdge) {
        await editor.detachEdge(topologyId, existingEdge.id, nodeName, fromNet?.name ?? '');
      }
      await editor.attachEdge(topologyId, { decky_uuid: nodeId, lan_id: toNetId }, nodeName, toNet?.name ?? '');
    } catch (err) {
      flashErr(err, 'reparent failed');
    }
  }, [editor, flashErr, nets, nodes, topologyId]);

  /* Port→port edges:
   *   - Same-LAN: visual-only (no bridge to create).
   *   - Cross-LAN: promote the source decky to multi-home into the
   *     target LAN via attachEdge. The resulting viz edge carries a
   *     backendEdgeId so removeEdge can detach it later. Observed
   *     entities (attacker-pool) are read-only and never bridge. */
  const onAddEdge = useCallback(async (fromId: string, toId: string) => {
    const fromNode = nodes.find((n) => n.id === fromId);
    const toNode = nodes.find((n) => n.id === toId);
    if (!fromNode || !toNode) return;
    if (fromNode.kind === 'observed' || toNode.kind === 'observed') return;

    const dup = edges.some((e) =>
      (e.from === fromId && e.to === toId) || (e.from === toId && e.to === fromId),
    );
    if (dup) return;

    const sameLan = fromNode.netId === toNode.netId;
    if (sameLan || !topologyId) {
      const id = `viz-${fromId}-${toId}-${Date.now()}`;
      setEdges((prev) => [...prev, { id, from: fromId, to: toId, traffic: 'active' as const }]);
      return;
    }

    const targetNet = nets.find((n) => n.id === toNode.netId);
    if (!targetNet) return;
    const fromName = fromNode.kind === 'decky' ? fromNode.name : '';

    try {
      const res = await editor.attachEdge(
        topologyId,
        { decky_uuid: fromId, lan_id: toNode.netId, is_bridge: true },
        fromName,
        targetNet.name,
      );
      const backendEdgeId = res.kind === 'applied' ? res.data.id : `enqueued:${res.mutationId}`;
      const id = `viz-${fromId}-${toId}-${Date.now()}`;
      setEdges((prev) => [
        ...prev,
        { id, from: fromId, to: toId, traffic: 'active' as const, backendEdgeId },
      ]);
      pushToast({
        text: `BRIDGED ${fromName.toUpperCase()} → ${targetNet.label.toUpperCase()}`,
        tone: 'violet',
        icon: 'terminal',
      });
    } catch (err) {
      flashErr(err, 'bridge failed');
    }
  }, [edges, editor, flashErr, nets, nodes, pushToast, topologyId]);

  const interaction = useMazeInteraction({
    nets, nodes, setNets, setNodes, canvasRef,
    onPaletteDrop, onReparent, onAddEdge,
  });

  const removeNet = async (id: string) => {
    const net = nets.find((n) => n.id === id);
    if (!net || net.kind === 'internet') return;
    /* Cascade delete members first — backend will otherwise 400 on orphan risk. */
    const members = nodes.filter((n) => n.netId === id && n.kind === 'decky');
    try {
      for (const m of members) {
        const mName = m.kind === 'decky' ? m.name : '';
        await editor.deleteDecky(topologyId, m.id, mName);
      }
      await editor.deleteLan(topologyId, id, net.name);
      setNets((p) => p.filter((n) => n.id !== id));
      setNodes((p) => p.filter((n) => n.netId !== id));
      setEdges((p) => p.filter((e) => {
        const a = nodes.find((x) => x.id === e.from)?.netId;
        const b = nodes.find((x) => x.id === e.to)?.netId;
        return a !== id && b !== id;
      }));
      setSelection(null);
    } catch (err) {
      flashErr(err, 'delete network failed');
    }
  };

  const removeNode = async (id: string) => {
    const node = nodes.find((n) => n.id === id);
    if (!node || node.kind === 'observed') return;
    if (node.kind === 'decky' && node.decky_config?.forwards_l3) return;
    try {
      await editor.deleteDecky(topologyId, id, node.kind === 'decky' ? node.name : '');
      setNodes((p) => p.filter((n) => n.id !== id));
      setEdges((p) => p.filter((e) => e.from !== id && e.to !== id));
      setSelection(null);
    } catch (err) {
      flashErr(err, 'delete decky failed');
    }
  };

  const removeEdge = async (id: string) => {
    const edge = edges.find((e) => e.id === id);
    if (!edge) return;

    /* Viz-only edges (same-LAN, pre-bridge era, or attach still in
     * flight without a backing id) just drop from local state. */
    if (!edge.backendEdgeId || !topologyId) {
      setEdges((p) => p.filter((e) => e.id !== id));
      setSelection(null);
      return;
    }

    /* Cross-LAN bridge: detach the membership edge before removing
     * the viz edge. Look the names up from the endpoints so the live
     * mutation path has what it needs. */
    const fromNode = nodes.find((n) => n.id === edge.from);
    const toNode = nodes.find((n) => n.id === edge.to);
    const targetNet = toNode ? nets.find((n) => n.id === toNode.netId) : undefined;
    const fromName = fromNode?.kind === 'decky' ? fromNode.name : '';
    const lanName = targetNet?.name ?? '';
    try {
      await editor.detachEdge(topologyId, edge.backendEdgeId, fromName, lanName);
      setEdges((p) => p.filter((e) => e.id !== id));
      setSelection(null);
    } catch (err) {
      flashErr(err, 'unbridge failed');
    }
  };

  const duplicateNode = async (id: string) => {
    const n = nodes.find((x) => x.id === id);
    if (!n || n.kind !== 'decky') return;
    const name = `${n.name.replace(/-[0-9a-f]{4}$/, '')}-${tempIdSuffix()}`;
    try {
      const parentNet = nets.find((net) => net.id === n.netId);
      const dRes = await editor.addDeckyToLan(
        topologyId,
        { name, services: [...n.services], x: n.x + 24, y: n.y + 24,
          decky_config: { archetype: n.archetype } },
        n.netId, parentNet?.name ?? '',
      );
      if (dRes.kind !== 'applied') return;
      const decky = dRes.data;
      const copy: DeckyNode = {
        kind: 'decky', id: decky.uuid, netId: n.netId, name: decky.name,
        archetype: n.archetype, services: [...n.services], status: 'idle',
        x: n.x + 24, y: n.y + 24,
      };
      setNodes((p) => [...p, copy]);
    } catch (err) {
      flashErr(err, 'duplicate failed');
    }
  };

  const removeServiceFromNode = async (id: string, slug: string) => {
    const n = nodes.find((x) => x.id === id);
    if (!n || n.kind !== 'decky' || !n.services.includes(slug)) return;
    // Same routing rule as the palette drop: active/degraded topologies
    // hit the live W3 endpoint so the chip disappears immediately and
    // the container stops; pending topologies queue through the
    // design-time mutator.
    const live = topoStatus === 'active' || topoStatus === 'degraded';
    if (live) {
      try {
        await liveRemoveService(n.name, slug);
        setSelection(null);
      } catch (err) {
        flashErr(err, 'remove service failed');
      }
      return;
    }
    const nextServices = n.services.filter((s) => s !== slug);
    try {
      const r = await editor.updateDecky(topologyId, id, n.name, { services: nextServices });
      if (r.kind !== 'applied') return;
      setNodes((p) => p.map((x) => x.id === id && x.kind === 'decky'
        ? { ...x, services: nextServices } : x));
      setSelection(null);
    } catch (err) {
      flashErr(err, 'remove service failed');
    }
  };

  const addServiceToNode = async (id: string, slug: string) => {
    const n = nodes.find((x) => x.id === id);
    if (!n || n.kind !== 'decky' || n.services.includes(slug)) return;
    const nextServices = [...n.services, slug];
    try {
      const r = await editor.updateDecky(topologyId, id, n.name, { services: nextServices });
      if (r.kind !== 'applied') return;
      setNodes((p) => p.map((x) => x.id === id && x.kind === 'decky'
        ? { ...x, services: nextServices } : x));
    } catch (err) {
      flashErr(err, 'add service failed');
    }
  };

  // Load + SSE + deploy + flashErr live in useTopologyData (above).

  const ctx = useMazeContextMenu({
    nets, nodes, services, archetypes, topologyId,
    setSelection, setNodes,
    canvasRef, pan: interaction.pan,
    editor, flashErr, onPaletteDrop,
    removeNet, removeNode, removeEdge, duplicateNode, addServiceToNode,
  });
  const onNodeContextMenu = ctx.onNodeContextMenu;
  const onNetContextMenu = ctx.onNetContextMenu;
  const onEdgeContextMenu = ctx.onEdgeContextMenu;
  const onCanvasContextMenu = ctx.onCanvasContextMenu;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setSelection(null);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const canDeploy = topoStatus === 'pending' && nets.length > 0;
  const deckyNodes = nodes.filter((n) => n.kind === 'decky');
  const runningDeckies = deckyNodes.filter((n) => n.status === 'active').length;

  return (
    <div className="maze-page">
      <div className="maze-page-header">
        <div>
          <h1>MAZENET · {topoName || topologyId}</h1>
          <div className="maze-page-sub">
            NETWORK OF NETWORKS · {topoStatus.toUpperCase()} · v{topoVersion} ·{' '}
            HOST:{' '}
            {topoMode === 'agent' && topoTargetHost ? (
              <span title={topoTargetHost}>
                <Server size={11} style={{ marginRight: 3, verticalAlign: '-1px' }} />
                {hostsByUuid.get(topoTargetHost)?.name ?? topoTargetHost.slice(0, 8)}
              </span>
            ) : (
              <span>MASTER</span>
            )}
            {' · '}
            {nets.length} NETS · {nodes.length} NODES · {edges.length} PATHS ·{' '}
            {runningDeckies}/{deckyNodes.length} DECKIES RUNNING
            {streamEnabled && (
              <span className="alert-text" style={{ color: streamLive ? undefined : 'var(--fg-dim)' }}>
                {' '}· {streamLive ? 'LIVE' : 'CONNECTING…'}
              </span>
            )}
            {loadErr && <span className="alert-text"> · {loadErr}</span>}
            {actionErr && <span className="alert-text"> · {actionErr}</span>}
          </div>
        </div>
        <div className="maze-page-actions">
          <button type="button" className="maze-btn ghost" onClick={() => navigate('/mazenet')}>
            <ArrowLeft size={12} /> TOPOLOGIES
          </button>
          <button type="button" className="maze-btn ghost" onClick={() => setPaletteOpen((o) => !o)}>
            {paletteOpen ? <PanelLeftClose size={12} /> : <PanelLeftOpen size={12} />} SERVICE FLEET
          </button>
          <button type="button" className="maze-btn ghost" onClick={() => setInspectorOpen((o) => !o)}>
            {inspectorOpen ? <PanelRightClose size={12} /> : <PanelRightOpen size={12} />} INSPECTOR
          </button>
          <button
            type="button"
            className="maze-btn ghost"
            onClick={toggleFullscreen}
            title={fullscreen ? 'Exit fullscreen (Esc)' : 'Fullscreen canvas'}
          >
            {fullscreen ? <Minimize2 size={12} /> : <Maximize2 size={12} />}
            {fullscreen ? ' EXIT FULL' : ' FULLSCREEN'}
          </button>
          <button type="button" className="maze-btn ghost" onClick={refetch} title="Revert local state to server">
            <RotateCcw size={12} /> REFRESH
          </button>
          <button
            type="button"
            className="maze-btn ghost"
            onClick={() => navigate(`/topologies/${topologyId}/personas`)}
            disabled={!topologyId}
            title="Edit email personas for this topology"
          >
            <Mail size={12} /> PERSONAS
          </button>
          <button
            type="button"
            className="maze-btn"
            disabled={!canDeploy || deploying}
            onClick={onDeploy}
            title={canDeploy ? 'Deploy topology' : 'Deploy requires pending status + at least one network'}
          >
            <UploadCloud size={12} /> {deploying ? 'DEPLOYING…' : 'DEPLOY'}
          </button>
        </div>
      </div>

      <div
        className="maze-shell"
        style={{
          gridTemplateColumns: `${paletteOpen ? '240px' : '0px'} 1fr ${inspectorOpen ? '320px' : '0px'}`,
        }}
      >
        <Palette
          services={services}
          archetypes={archetypes}
          startPaletteDrag={interaction.startPaletteDrag}
          className={paletteOpen ? '' : 'collapsed'}
        />
        <Canvas
          ref={canvasRef}
          nets={nets}
          nodes={nodes}
          edges={edges}
          deployed={topoStatus === 'active' || topoStatus === 'degraded'}
          selection={selection}
          setSelection={setSelection}
          pan={interaction.pan}
          zoom={interaction.zoom}
          dropTargetId={interaction.dropTargetId}
          dragging={interaction.dragging}
          edgeDraw={interaction.edgeDraw}
          onCanvasMouseDown={interaction.onCanvasMouseDown}
          onNodeMouseDown={interaction.onNodeMouseDown}
          onNetMouseDown={interaction.onNetMouseDown}
          onNetResizeMouseDown={interaction.onNetResizeMouseDown}
          onPortMouseDown={interaction.onPortMouseDown}
          onNodeContextMenu={onNodeContextMenu}
          onNetContextMenu={onNetContextMenu}
          onEdgeContextMenu={onEdgeContextMenu}
          onCanvasContextMenu={onCanvasContextMenu}
          onResetView={interaction.resetPan}
          onAutoLayout={() => pushToast({ text: 'AUTO-LAYOUT COMING SOON', tone: 'violet', icon: 'info' })}
          onZoomIn={() => interaction.zoomBy(1.2)}
          onZoomOut={() => interaction.zoomBy(1 / 1.2)}
          sseConnected={streamLive}
          lastEventAt={lastEventAt}
          onSelectService={(nodeId, slug) => setSelection({ type: 'service', id: slug, nodeId })}
          panLayerRef={interaction.panLayerRef}
          gridPatternRef={interaction.gridPatternRef}
        />
        {ctx.ctxMenu && (
          <ContextMenu x={ctx.ctxMenu.x} y={ctx.ctxMenu.y} items={ctx.ctxMenu.items} onClose={ctx.closeMenu} />
        )}
        {interaction.paletteDrag && (
          <div
            className="palette-ghost"
            style={{ left: interaction.paletteDrag.clientX + 8, top: interaction.paletteDrag.clientY + 8 }}
          >
            {interaction.paletteDrag.label}
          </div>
        )}
        <Inspector
          selection={selection}
          setSelection={setSelection}
          nets={nets}
          nodes={nodes}
          edges={edges}
          topologyId={topologyId || undefined}
          topologyStatus={topoStatus}
          onClose={() => setInspectorOpen(false)}
          onDeleteNet={removeNet}
          onDeleteNode={removeNode}
          onDeleteEdge={removeEdge}
          onRemoveService={removeServiceFromNode}
          availableServices={serviceRegistry.perDecky}
          onLiveAddService={requestAddService}
          onLiveRemoveService={liveRemoveService}
          onToggleGateway={toggleGateway}
          onLiveTarpitEnable={async (nodeName, ports, delayMs) => {
            await axios.post(
              `/topologies/${encodeURIComponent(topologyId)}/deckies/${encodeURIComponent(nodeName)}/tarpit`,
              { ports, delay_ms: delayMs },
            );
            pushToast({ text: `TARPIT ON · ${nodeName.toUpperCase()} · ${ports.join(',')} / ${delayMs >= 1000 ? `${delayMs / 1000}s` : `${delayMs}ms`}`, tone: 'matrix', icon: 'shield' });
          }}
          onLiveTarpitDisable={async (nodeName) => {
            await axios.delete(
              `/topologies/${encodeURIComponent(topologyId)}/deckies/${encodeURIComponent(nodeName)}/tarpit`,
            );
            pushToast({ text: `TARPIT OFF · ${nodeName.toUpperCase()}`, tone: 'matrix', icon: 'shield' });
          }}
          onAddDecky={(netId) => {
            const net = nets.find((n) => n.id === netId);
            if (!net) return;
            onPaletteDrop(
              { kind: 'archetype', slug: archetypes[0]?.slug ?? 'deaddeck',
                services: archetypes[0]?.services.slice(0, 2) ?? [],
                label: archetypes[0]?.name ?? 'DECKY',
                clientX: 0, clientY: 0 },
              { x: net.x + 40, y: net.y + 60 }, netId, null,
            );
          }}
          className={inspectorOpen ? '' : 'collapsed'}
        />
      </div>
      <AddServiceConfigModal
        pending={pendingAddSvc}
        onCancel={() => setPendingAddSvc(null)}
        onConfirm={confirmAddService}
      />
    </div>
  );
};

export default MazeNET;

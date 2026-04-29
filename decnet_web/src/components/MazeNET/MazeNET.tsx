import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  PanelRightOpen, PanelRightClose, PanelLeftOpen, PanelLeftClose,
  Maximize2, Minimize2, RotateCcw, UploadCloud, ArrowLeft,
  Plus, Trash2, Zap, Copy, Eye, ShieldAlert, GitMerge, Server, Mail,
} from '../../icons';
import './MazeNET.css';
import axios from '../../utils/api';
import { useSwarmHosts } from '../../hooks/useSwarmHosts';
import Palette from './Palette';
import Canvas from './Canvas';
import Inspector from './Inspector';
import type { Selection } from './Inspector';
import ContextMenu, { type MenuItem } from './ContextMenu';
import { DEFAULT_SERVICES } from './data';
import type { Archetype, ServiceDef } from './data';
import type { Net, MazeNode, Edge, DeckyNode } from './types';
import { useMazeApi } from './useMazeApi';
import { useTopologyEditor } from './useTopologyEditor';
import { useMazeInteraction, type PaletteDrag } from './useMazeInteraction';
import { useLayoutPersistor } from './useMazeLayoutStore';
import { useTopologyStream, type TopologyStreamEvent } from './useTopologyStream';
import { ARCHETYPES as DEFAULT_ARCHETYPES } from './data';
import { useToast } from '../Toasts/useToast';
import { useServiceRegistry } from '../../hooks/useServiceRegistry';

/* Short unique suffix for default names — avoids the DB uniqueness
 * constraint regardless of delete/re-add sequencing on the client. */
const hex4 = (): string => {
  const r = typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID().replace(/-/g, '')
    : Math.random().toString(16).slice(2);
  return r.slice(0, 4);
};

const MazeNET: React.FC = () => {
  const api = useMazeApi();
  const navigate = useNavigate();
  const { push: pushToast } = useToast();
  const [params] = useSearchParams();
  const topologyId = params.get('topology') ?? '';

  const { byUuid: hostsByUuid } = useSwarmHosts();
  const [nets,  setNets]  = useState<Net[]>([]);
  const [nodes, setNodes] = useState<MazeNode[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [topoStatus, setTopoStatus] = useState<string>('pending');
  const [topoName, setTopoName] = useState<string>('');
  const [topoVersion, setTopoVersion] = useState<number>(0);
  const [topoTargetHost, setTopoTargetHost] = useState<string | null>(null);
  const [topoMode, setTopoMode] = useState<string>('unihost');
  const [selection, setSelection] = useState<Selection>(null);
  const [inspectorOpen, setInspectorOpen] = useState(true);
  const [paletteOpen, setPaletteOpen] = useState(true);
  const [fullscreen, setFullscreen] = useState(false);

  useEffect(() => {
    const cls = 'maze-fullscreen';
    if (fullscreen) document.body.classList.add(cls);
    else document.body.classList.remove(cls);
    return () => document.body.classList.remove(cls);
  }, [fullscreen]);

  // Request/exit browser fullscreen alongside the in-app chrome hide.
  // Ignore failures (fullscreen requires a user gesture; the chrome-only
  // mode still works if the API rejects).
  useEffect(() => {
    if (fullscreen && !document.fullscreenElement) {
      document.documentElement.requestFullscreen?.().catch(() => {});
    } else if (!fullscreen && document.fullscreenElement) {
      document.exitFullscreen?.().catch(() => {});
    }
  }, [fullscreen]);

  // Sync state if the user presses F11/Esc to leave fullscreen from
  // outside our button.
  useEffect(() => {
    const onFsChange = () => {
      if (!document.fullscreenElement) setFullscreen(false);
    };
    document.addEventListener('fullscreenchange', onFsChange);
    return () => document.removeEventListener('fullscreenchange', onFsChange);
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && fullscreen) setFullscreen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [fullscreen]);
  const [services, setServices] = useState<ServiceDef[]>(DEFAULT_SERVICES);
  const [archetypes, setArchetypes] = useState<Archetype[]>(DEFAULT_ARCHETYPES);

  useLayoutPersistor(topologyId || null, nets, nodes);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [actionErr, setActionErr] = useState<string | null>(null);
  const [deploying, setDeploying] = useState(false);

  const canvasRef = useRef<HTMLDivElement>(null);

  const editor = useTopologyEditor({ api, topoStatus, topoVersion });

  const flashErr = useCallback((err: unknown, fallback: string) => {
    const msg = (err as { response?: { data?: { detail?: string } }; message?: string })
      ?.response?.data?.detail ?? (err as Error)?.message ?? fallback;
    setActionErr(msg);
    setTimeout(() => setActionErr(null), 4000);
  }, []);

  /* ── Palette drop — create LANs / deckies / services via REST ─── */
  const onPaletteDrop = useCallback(
    async (drag: PaletteDrag, world: { x: number; y: number }, overNetId: string | null, overNodeId: string | null) => {
      if (!topologyId) return;

      if (drag.kind === 'network-subnet' || drag.kind === 'network-dmz') {
        const isDmz = drag.kind === 'network-dmz';
        if (isDmz && nets.some((n) => n.kind === 'dmz')) {
          flashErr(null, 'topology already has a DMZ');
          return;
        }
        // Append to the 3-col grid matching adaptTopology. Counting
        // existing nets PLUS any pending placeholders (live-topology
        // enqueued mutations that haven't echoed through SSE yet)
        // keeps successive drops from stacking on the same cell.
        const w = 300, h = 240;
        const GAP = 40, COLS = 3;
        const i = nets.filter((n) => n.kind !== 'internet').length;
        const x = GAP + (i % COLS) * (w + GAP);
        const y = GAP + Math.floor(i / COLS) * (h + GAP);
        const name = isDmz ? `dmz-${hex4()}` : `subnet-${hex4()}`;
        try {
          const subnet = await api.getNextSubnet().catch(() => undefined);
          const lanRes = await editor.createLan(topologyId, { name, is_dmz: isDmz, x, y, ...(subnet ? { subnet } : {}) });
          if (lanRes.kind !== 'applied') {
            // Live topology: mutator will materialise the LAN. Drop
            // a placeholder net so the grid index advances and the
            // user gets an immediate visual ack. Real LAN arriving
            // via SSE replaces the placeholder by id when its
            // canonical id lands; until then, the temp id is unique.
            const tempId = `pending-lan-${name}`;
            setNets((p) => [...p, {
              id: tempId, name, label: name.toUpperCase(),
              cidr: subnet ?? '', kind: isDmz ? 'dmz' : 'subnet',
              x, y, w, h, pending: true,
            }]);
            return;
          }
          const lan = lanRes.data;
          const net: Net = {
            id: lan.id, name: lan.name, label: lan.name.toUpperCase(), cidr: lan.subnet,
            kind: isDmz ? 'dmz' : 'subnet', x, y, w, h,
          };
          setNets((p) => [...p, net]);

          if (isDmz) {
            const gwName = `dmz-gateway-${hex4()}`;
            const gwRes = await editor.addDeckyToLan(
              topologyId,
              { name: gwName, services: ['ssh'], x: 20, y: 40,
                decky_config: { archetype: 'deaddeck', forwards_l3: true } },
              lan.id, lan.name,
              { is_bridge: true, forwards_l3: true },
            );
            if (gwRes.kind !== 'applied') return;
            const gw = gwRes.data;
            const gwNode: DeckyNode = {
              kind: 'decky', id: gw.uuid, netId: lan.id, name: gw.name,
              archetype: 'deaddeck', services: ['ssh'], status: 'idle',
              x: 20, y: 40, decky_config: { forwards_l3: true },
            };
            setNodes((p) => [...p, gwNode]);
          }
        } catch (err) {
          flashErr(err, 'create network failed');
        }
        return;
      }

      if (drag.kind === 'archetype') {
        if (!overNetId) return;
        const net = nets.find((n) => n.id === overNetId);
        if (!net) return;
        const arch = archetypes.find((a) => a.slug === drag.slug);
        const archSlug = drag.slug;
        const dServices = drag.services ?? arch?.services ?? [];
        const nx = Math.max(8, Math.round(world.x - net.x - 70));
        const ny = Math.max(28, Math.round(world.y - net.y - 24));
        const name = `decky-${hex4()}`;
        try {
          const dRes = await editor.addDeckyToLan(
            topologyId,
            { name, services: dServices, x: nx, y: ny,
              decky_config: { archetype: archSlug } },
            overNetId, net.name,
          );
          if (dRes.kind !== 'applied') return;
          const decky = dRes.data;
          const node: DeckyNode = {
            kind: 'decky', id: decky.uuid, netId: overNetId, name: decky.name,
            archetype: archSlug, services: dServices, status: 'idle', x: nx, y: ny,
          };
          setNodes((p) => [...p, node]);
        } catch (err) {
          flashErr(err, 'create decky failed');
        }
        return;
      }

      if (drag.kind === 'service') {
        if (!overNodeId) return;
        const target = nodes.find((n) => n.id === overNodeId);
        if (!target || target.kind !== 'decky') return;
        if (target.services.includes(drag.slug)) return;
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
    },
    [api, archetypes, editor, flashErr, nets, nodes, topologyId],
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

  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number; items: MenuItem[] } | null>(null);

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
    const name = `${n.name.replace(/-[0-9a-f]{4}$/, '')}-${hex4()}`;
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

  /* Live service add/remove — talks to the W3 endpoints directly,
     bypassing the design-time mutation queue.  Used when topology
     status is active/degraded; the Inspector switches between this
     and the design-time path based on the topologyStatus prop.

     Optimistic local update is fine: the W3 endpoint returns the
     post-mutation services list, and the SSE forwarder (commit C-sse)
     reconciles cross-tab. */
  const serviceRegistry = useServiceRegistry();

  const liveAddService = useCallback(async (nodeName: string, slug: string) => {
    const { data } = await axios.post<{ services: string[] }>(
      `/topologies/${encodeURIComponent(topologyId)}/deckies/${encodeURIComponent(nodeName)}/services`,
      { name: slug },
    );
    setNodes((p) => p.map((x) => x.kind === 'decky' && x.name === nodeName
      ? { ...x, services: data.services } : x));
  }, [topologyId]);

  const liveRemoveService = useCallback(async (nodeName: string, slug: string) => {
    const { data } = await axios.delete<{ services: string[] }>(
      `/topologies/${encodeURIComponent(topologyId)}/deckies/${encodeURIComponent(nodeName)}/services/${encodeURIComponent(slug)}`,
    );
    setNodes((p) => p.map((x) => x.kind === 'decky' && x.name === nodeName
      ? { ...x, services: data.services } : x));
  }, [topologyId]);

  /* Force-mutate is a no-op against a pending topology (no live containers).
   * Keep the menu item disabled for now; real hook lands with live-editing polish. */
  const forceMutate = (_id: string) => {
    flashErr(null, 'force-mutate only applies to deployed topologies');
  };

  const onNodeContextMenu = (id: string) => (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const node = nodes.find((n) => n.id === id);
    if (!node) return;
    setSelection({ type: 'node', id });
    const isObs = node.kind === 'observed';
    const isGateway = node.kind === 'decky' && !!node.decky_config?.forwards_l3;
    const locked = isObs || isGateway;
    const lockedTitle = isObs
      ? 'observed entity — not a deployed decky'
      : isGateway ? 'DMZ gateway — pinned to its DMZ network' : undefined;
    const usedServices = node.kind === 'decky' ? new Set(node.services) : new Set<string>();
    const serviceSubmenu: MenuItem[] = services
      .filter((s) => !usedServices.has(s.slug))
      .slice(0, 16)
      .map((s) => ({
        label: `${s.name} · ${s.proto.toUpperCase()}:${s.port}`,
        disabled: isObs,
        onClick: () => addServiceToNode(id, s.slug),
      }));
    if (serviceSubmenu.length === 0) {
      serviceSubmenu.push({ label: '(no free services)', disabled: true });
    }

    setCtxMenu({
      x: e.clientX, y: e.clientY,
      items: [
        { label: 'Add service…', icon: <Plus size={12} />, disabled: isObs,
          title: isObs ? 'observed entity — services fixed' : undefined,
          submenu: serviceSubmenu },
        { label: 'Force mutate', icon: <Zap size={12} />, disabled: isObs,
          onClick: () => forceMutate(id) },
        { label: 'Duplicate decky', icon: <Copy size={12} />, disabled: locked,
          title: lockedTitle, onClick: () => duplicateNode(id) },
        { separator: true, label: '' },
        { label: 'Delete decky', icon: <Trash2 size={12} />, danger: true,
          disabled: locked, title: lockedTitle,
          onClick: () => removeNode(id) },
      ],
    });
  };

  const onNetContextMenu = (id: string) => (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const net = nets.find((n) => n.id === id);
    if (!net) return;
    setSelection({ type: 'net', id });
    const archetypeSubmenu: MenuItem[] = archetypes.map((a) => ({
      label: a.name, icon: <Server size={12} />,
      onClick: async () => {
        const name = `decky-${hex4()}`;
        try {
          const dRes = await editor.addDeckyToLan(
            topologyId,
            { name, services: [...a.services], x: 20, y: 40,
              decky_config: { archetype: a.slug } },
            id, net.name,
          );
          if (dRes.kind !== 'applied') return;
          const decky = dRes.data;
          const node: DeckyNode = {
            kind: 'decky', id: decky.uuid, netId: id, name: decky.name,
            archetype: a.slug, services: [...a.services], status: 'idle',
            x: 20, y: 40,
          };
          setNodes((p) => [...p, node]);
        } catch (err) {
          flashErr(err, 'create decky failed');
        }
      },
    }));

    setCtxMenu({
      x: e.clientX, y: e.clientY,
      items: [
        { label: 'Add decky…', icon: <Plus size={12} />, submenu: archetypeSubmenu },
        { label: 'Inspect',    icon: <Eye size={12} />,  onClick: () => setSelection({ type: 'net', id }) },
        { separator: true, label: '' },
        { label: net.kind === 'dmz' ? 'Delete DMZ' : 'Delete network',
          icon: <Trash2 size={12} />, danger: true,
          disabled: net.kind === 'internet',
          title: net.kind === 'internet' ? 'internet zone cannot be removed' : undefined,
          onClick: () => removeNet(id) },
      ],
    });
  };

  const onEdgeContextMenu = (id: string) => (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setSelection({ type: 'edge', id });
    setCtxMenu({
      x: e.clientX, y: e.clientY,
      items: [
        { label: 'Remove edge', icon: <Trash2 size={12} />, danger: true, onClick: () => removeEdge(id) },
      ],
    });
  };

  const onCanvasContextMenu = (e: React.MouseEvent) => {
    e.preventDefault();
    setCtxMenu({
      x: e.clientX, y: e.clientY,
      items: [
        { label: 'Add subnet here', icon: <GitMerge size={12} />,
          onClick: () => {
            const rect = canvasRef.current?.getBoundingClientRect();
            const wx = e.clientX - (rect?.left ?? 0) - interaction.pan.x;
            const wy = e.clientY - (rect?.top  ?? 0) - interaction.pan.y;
            onPaletteDrop(
              { kind: 'network-subnet', slug: 'subnet', label: 'SUBNET', clientX: e.clientX, clientY: e.clientY },
              { x: wx, y: wy }, null, null,
            );
          },
        },
        { label: 'Add DMZ here', icon: <ShieldAlert size={12} />,
          onClick: () => {
            const rect = canvasRef.current?.getBoundingClientRect();
            const wx = e.clientX - (rect?.left ?? 0) - interaction.pan.x;
            const wy = e.clientY - (rect?.top  ?? 0) - interaction.pan.y;
            onPaletteDrop(
              { kind: 'network-dmz', slug: 'dmz', label: 'DMZ', clientX: e.clientX, clientY: e.clientY },
              { x: wx, y: wy }, null, null,
            );
          },
        },
      ],
    });
  };

  /* Load catalogs. */
  useEffect(() => {
    let cancelled = false;
    api.getServices().then((s) => { if (!cancelled) setServices(s); }).catch(() => {});
    api.getArchetypes().then((a) => { if (!cancelled) setArchetypes(a); }).catch(() => {});
    return () => { cancelled = true; };
  }, [api]);

  /* Hydrate topology. Route guard in App.tsx ensures topologyId is set;
   * if the id is bogus, surface a friendly error. */
  const refetch = useCallback(async () => {
    if (!topologyId) return;
    try {
      const h = await api.getTopology(topologyId);
      setNets(h.nets); setNodes(h.nodes); setEdges(h.edges);
      setTopoStatus(h.topology.status);
      setTopoName(h.topology.name);
      setTopoVersion(h.topology.version);
      setTopoMode(h.topology.mode ?? 'unihost');
      setTopoTargetHost(h.topology.target_host_uuid ?? null);
      setLoadErr(null);
    } catch (err) {
      setLoadErr((err as Error)?.message ?? 'topology load failed');
    }
  }, [api, topologyId]);

  useEffect(() => { refetch(); }, [refetch]);

  /* Live topology stream. Open only when the topology is deployed —
   * pending topologies have no mutator loop and would just idle on
   * keepalives.  On any state-transition event we refetch; DB is the
   * source of truth and the bus is at-most-once. */
  const [streamLive, setStreamLive] = useState(false);
  const [lastEventAt, setLastEventAt] = useState<Date | null>(null);
  const streamEnabled = topoStatus === 'active' || topoStatus === 'degraded';
  const onStreamEvent = useCallback((event: TopologyStreamEvent) => {
    // Flip LIVE only on named, purposeful events — not incidental keepalives.
    if (event.name === 'snapshot'
      || event.name.startsWith('mutation.')
      || event.name === 'status') {
      setStreamLive(true);
      setLastEventAt(new Date());
    }
    if (event.name === 'mutation.failed') {
      const p = event.payload ?? {};
      const reason = typeof p.reason === 'string' ? p.reason
        : typeof p.error === 'string' ? p.error
        : 'mutation failed — check mutator logs';
      setActionErr(`mutation failed: ${reason}`);
      setTimeout(() => setActionErr(null), 6000);
    }
    if (event.name === 'mutation.applied'
      || event.name === 'mutation.failed'
      || event.name === 'status') {
      refetch();
    }
  }, [refetch]);
  const onStreamError = useCallback(() => { setStreamLive(false); }, []);
  useTopologyStream({
    topologyId: streamEnabled ? topologyId : null,
    enabled: streamEnabled,
    onEvent: onStreamEvent,
    onError: onStreamError,
  });
  useEffect(() => { if (!streamEnabled) setStreamLive(false); }, [streamEnabled]);

  const onDeploy = async () => {
    if (!topologyId) return;
    setDeploying(true);
    try {
      await api.deployTopology(topologyId);
      await refetch();
    } catch (err) {
      flashErr(err, 'deploy failed');
    } finally {
      setDeploying(false);
    }
  };

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
            onClick={() => setFullscreen((f) => !f)}
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
        {ctxMenu && (
          <ContextMenu x={ctxMenu.x} y={ctxMenu.y} items={ctxMenu.items} onClose={() => setCtxMenu(null)} />
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
          topologyStatus={topoStatus}
          onClose={() => setInspectorOpen(false)}
          onDeleteNet={removeNet}
          onDeleteNode={removeNode}
          onDeleteEdge={removeEdge}
          onRemoveService={removeServiceFromNode}
          availableServices={serviceRegistry.perDecky}
          onLiveAddService={liveAddService}
          onLiveRemoveService={liveRemoveService}
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
    </div>
  );
};

export default MazeNET;

import React, { useState } from 'react';
import {
  Copy, Eye, GitMerge, Plus, Server, ShieldAlert, Trash2, Zap,
} from '../../icons';
import type { Selection } from './Inspector';
import type { MenuItem } from './ContextMenu';
import type { Net, MazeNode, DeckyNode } from './types';
import type { Archetype, ServiceDef } from './data';
import type { UseTopologyEditor } from './useTopologyEditor';
import type { PaletteDrag } from './useMazeInteraction';

type CtxMenuState = { x: number; y: number; items: MenuItem[] } | null;

interface PanLike { x: number; y: number }

interface Args {
  nets: Net[];
  nodes: MazeNode[];
  services: ServiceDef[];
  archetypes: Archetype[];
  topologyId: string;
  setSelection: (s: Selection) => void;
  setNodes: React.Dispatch<React.SetStateAction<MazeNode[]>>;
  canvasRef: React.RefObject<HTMLDivElement | null>;
  pan: PanLike;
  editor: UseTopologyEditor;
  flashErr: (err: unknown, fallback: string) => void;
  onPaletteDrop: (
    drag: PaletteDrag,
    world: { x: number; y: number },
    overNetId: string | null,
    overNodeId: string | null,
  ) => void | Promise<void>;
  removeNet: (id: string) => void | Promise<void>;
  removeNode: (id: string) => void | Promise<void>;
  removeEdge: (id: string) => void | Promise<void>;
  duplicateNode: (id: string) => void | Promise<void>;
  addServiceToNode: (id: string, slug: string) => void | Promise<void>;
}

const tempIdSuffix = (): string =>
  Math.random().toString(36).slice(2, 6);

export interface UseMazeContextMenuResult {
  ctxMenu: CtxMenuState;
  closeMenu: () => void;
  onNodeContextMenu: (id: string) => (e: React.MouseEvent) => void;
  onNetContextMenu: (id: string) => (e: React.MouseEvent) => void;
  onEdgeContextMenu: (id: string) => (e: React.MouseEvent) => void;
  onCanvasContextMenu: (e: React.MouseEvent) => void;
}

/** Pure UI logic for the canvas context menu. Owns the menu's
 *  open/close state and exposes one builder per surface (node /
 *  net / edge / canvas). The actual operations come in as
 *  callbacks so the hook is testable in isolation and the
 *  page shell can keep its own optimistic-patch logic. */
export function useMazeContextMenu(args: Args): UseMazeContextMenuResult {
  const {
    nets, nodes, services, archetypes, topologyId,
    setSelection, setNodes, canvasRef, pan,
    editor, flashErr, onPaletteDrop,
    removeNet, removeNode, removeEdge, duplicateNode, addServiceToNode,
  } = args;

  const [ctxMenu, setCtxMenu] = useState<CtxMenuState>(null);
  const closeMenu = () => setCtxMenu(null);

  // Force-mutate is a no-op against a pending topology (no live containers).
  // Keep the menu item disabled for now; real hook lands with live-editing polish.
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
        const name = `decky-${tempIdSuffix()}`;
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
            const wx = e.clientX - (rect?.left ?? 0) - pan.x;
            const wy = e.clientY - (rect?.top  ?? 0) - pan.y;
            void onPaletteDrop(
              { kind: 'network-subnet', slug: 'subnet', label: 'SUBNET', clientX: e.clientX, clientY: e.clientY },
              { x: wx, y: wy }, null, null,
            );
          },
        },
        { label: 'Add DMZ here', icon: <ShieldAlert size={12} />,
          onClick: () => {
            const rect = canvasRef.current?.getBoundingClientRect();
            const wx = e.clientX - (rect?.left ?? 0) - pan.x;
            const wy = e.clientY - (rect?.top  ?? 0) - pan.y;
            void onPaletteDrop(
              { kind: 'network-dmz', slug: 'dmz', label: 'DMZ', clientX: e.clientX, clientY: e.clientY },
              { x: wx, y: wy }, null, null,
            );
          },
        },
      ],
    });
  };

  return {
    ctxMenu,
    closeMenu,
    onNodeContextMenu,
    onNetContextMenu,
    onEdgeContextMenu,
    onCanvasContextMenu,
  };
}

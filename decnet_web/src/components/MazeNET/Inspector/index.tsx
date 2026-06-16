// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useMemo } from 'react';
import { Crosshair, MousePointer2, X } from '../../../icons';
import type { Edge, MazeNode, Net } from '../types';
import EdgeInspector from './EdgeInspector';
import NetInspector from './NetInspector';
import NodeInspector from './NodeInspector';
import ServiceInspector from './ServiceInspector';
import type { Selection } from './types';

export type { Selection };

interface Props {
  selection: Selection;
  nets: Net[];
  nodes: MazeNode[];
  edges: Edge[];
  /** Topology ID (MazeNET-only) — required for the schema-driven service
   *  config form to hit the per-topology REST path. Omit for fleet. */
  topologyId?: string;
  topologyStatus?: string;
  onClose?: () => void;
  onDeleteNet?: (id: string) => void;
  onDeleteNode?: (id: string) => void;
  onDeleteEdge?: (id: string) => void;
  onRemoveService?: (nodeId: string, slug: string) => void;
  /** Live (post-deploy) service mutation, hitting W3 endpoints directly.
   *  Distinct from onRemoveService which queues a design-time graph
   *  mutation. Both can coexist; the inspector picks based on
   *  topologyStatus (active/degraded → live, pending/anything else →
   *  design-time only). Wiring these props from MazeNET.tsx is the
   *  single switch that turns chips into live controls. */
  onLiveAddService?: (nodeName: string, slug: string) => void;
  onLiveRemoveService?: (nodeName: string, slug: string) => Promise<void>;
  /** Per-decky-eligible service slugs, fetched via useServiceRegistry. */
  availableServices?: string[];
  /** Toggle ``forwards_l3`` (gateway) on the selected decky. When the
   *  topology is active/degraded the caller is responsible for the
   *  destructive-recreate confirm dialog and the ``force: true`` submit
   *  — this prop just relays the user's intent. */
  onToggleGateway?: (nodeId: string, nextValue: boolean) => Promise<void>;
  /** Tarpit controls — only shown when topology is active/degraded and node is a deployed decky. */
  onLiveTarpitEnable?: (nodeName: string, ports: number[], delayMs: number) => Promise<void>;
  onLiveTarpitDisable?: (nodeName: string) => Promise<void>;
  onAddDecky?: (netId: string) => void;
  setSelection?: (sel: Selection) => void;
  pendingChanges?: number;
  className?: string;
}

const Inspector: React.FC<Props> = ({
  selection, nets, nodes, edges, topologyId, topologyStatus, onClose,
  onDeleteNet, onDeleteNode, onDeleteEdge, onRemoveService,
  onLiveAddService, onLiveRemoveService, availableServices,
  onToggleGateway, onLiveTarpitEnable, onLiveTarpitDisable,
  onAddDecky, setSelection,
  pendingChanges = 0,
  className = '',
}) => {
  const net  = selection?.type === 'net'  ? nets.find((n) => n.id === selection.id)  : undefined;
  const node = selection?.type === 'node' ? nodes.find((n) => n.id === selection.id) : undefined;
  const edge = selection?.type === 'edge' ? edges.find((e) => e.id === selection.id) : undefined;
  const serviceSel = selection?.type === 'service' ? selection : undefined;

  const activeNetIds = useMemo(() => {
    const s = new Set<string>();
    edges.forEach((e) => {
      const f = nodes.find((n) => n.id === e.from);
      const t = nodes.find((n) => n.id === e.to);
      if (f) s.add(f.netId);
      if (t) s.add(t.netId);
    });
    return s;
  }, [edges, nodes]);

  const typeLabel = selection ? selection.type.toUpperCase() : 'IDLE';
  const selectionKey = selection?.type === 'node' ? selection.id : undefined;

  return (
    <aside className={`maze-inspector ${className}`}>
      <div className="maze-inspector-title">
        <Crosshair size={12} className="violet-accent" />
        <span>INSPECTOR</span>
        <span className="dim inspector-type-label">{typeLabel}</span>
        {onClose && (
          <button
            type="button"
            className="inspector-close-btn"
            onClick={onClose}
            title="Hide inspector"
          >
            <X size={12} />
          </button>
        )}
      </div>

      <div className="maze-inspector-body">
        {!selection && (
          <div className="inspector-empty">
            <MousePointer2 size={22} style={{ opacity: 0.4, marginBottom: 10 }} />
            <div>SELECT A NODE, NETWORK, OR EDGE</div>
            <div style={{ marginTop: 10, fontSize: '0.6rem', opacity: 0.5 }}>
              Right-click for actions
            </div>
          </div>
        )}

        {node && (
          <NodeInspector
            node={node}
            nodes={nodes}
            nets={nets}
            edges={edges}
            topologyStatus={topologyStatus}
            availableServices={availableServices}
            onDeleteNode={onDeleteNode}
            onLiveAddService={onLiveAddService}
            onLiveRemoveService={onLiveRemoveService}
            onToggleGateway={onToggleGateway}
            onLiveTarpitEnable={onLiveTarpitEnable}
            onLiveTarpitDisable={onLiveTarpitDisable}
            selectionKey={selectionKey}
          />
        )}

        {net && (
          <NetInspector
            net={net}
            nodes={nodes}
            activeNetIds={activeNetIds}
            setSelection={setSelection}
            onAddDecky={onAddDecky}
            onDeleteNet={onDeleteNet}
          />
        )}

        {edge && <EdgeInspector edge={edge} nodes={nodes} onDeleteEdge={onDeleteEdge} />}

        {serviceSel && (
          <ServiceInspector
            serviceSel={serviceSel}
            nodes={nodes}
            nets={nets}
            topologyId={topologyId}
            topologyStatus={topologyStatus}
            onRemoveService={onRemoveService}
          />
        )}

        {pendingChanges > 0 && (
          <div className="inspector-diff-block">
            <div className="type-label inspector-section-label">PENDING DIFF</div>
            <div className="maze-diff">
              <span className="ctx">  +{pendingChanges} graph mutation(s)</span>{'\n'}
              <span className="ctx">  networks: {nets.length}</span>{'\n'}
              <span className="ctx">  deckies:  {nodes.length}</span>{'\n'}
              <span className="ctx">  paths:    {edges.length}</span>
            </div>
          </div>
        )}

        {topologyStatus && !selection && (
          <div className="kvs inspector-status-block">
            <div className="k">TOPOLOGY</div>
            <div className="v">{topologyStatus.toUpperCase()}</div>
          </div>
        )}
      </div>
    </aside>
  );
};

export default Inspector;

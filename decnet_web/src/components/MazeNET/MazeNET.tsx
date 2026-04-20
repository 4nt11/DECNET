import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { PanelRightOpen, PanelRightClose, RotateCcw, UploadCloud } from 'lucide-react';
import './MazeNET.css';
import Palette from './Palette';
import Canvas from './Canvas';
import Inspector from './Inspector';
import type { Selection } from './Inspector';
import { DEFAULT_SERVICES, DEMO_NETS, DEMO_NODES, DEMO_EDGES } from './data';
import type { ServiceDef } from './data';
import type { Net, MazeNode, Edge, PendingChange } from './types';
import { useMazeApi } from './useMazeApi';
import { useMazeInteraction } from './useMazeInteraction';

const MazeNET: React.FC = () => {
  const api = useMazeApi();
  const [params] = useSearchParams();
  const topologyId = params.get('topology');

  const [nets,  setNets]  = useState<Net[]>(DEMO_NETS);
  const [nodes, setNodes] = useState<MazeNode[]>(DEMO_NODES);
  const [edges, setEdges] = useState<Edge[]>(DEMO_EDGES);
  const [pending, setPending] = useState<PendingChange[]>([]);
  const [selection, setSelection] = useState<Selection>(null);
  const [inspectorOpen, setInspectorOpen] = useState(true);
  const [services, setServices] = useState<ServiceDef[]>(DEFAULT_SERVICES);
  const [loadErr, setLoadErr] = useState<string | null>(null);

  const canvasRef = useRef<HTMLDivElement>(null);
  const applyChange = useCallback((pc: PendingChange) => {
    setPending((p) => [...p, pc]);
  }, []);
  const interaction = useMazeInteraction({ nets, nodes, setNets, setNodes, applyChange, canvasRef });

  /* Load service catalog from API (fall back to defaults if 401/offline). */
  useEffect(() => {
    let cancelled = false;
    api.getServices().then((s) => { if (!cancelled) setServices(s); }).catch(() => {});
    return () => { cancelled = true; };
  }, [api]);

  /* If ?topology=<id> is present, hydrate from the real backend. */
  useEffect(() => {
    if (!topologyId) return;
    let cancelled = false;
    api.getTopology(topologyId)
      .then((h) => {
        if (cancelled) return;
        setNets(h.nets); setNodes(h.nodes); setEdges(h.edges);
        setSelection(null);
        setLoadErr(null);
      })
      .catch((err) => {
        if (!cancelled) setLoadErr(err?.message ?? 'topology load failed');
      });
    return () => { cancelled = true; };
  }, [api, topologyId]);

  const onReset = () => {
    if (topologyId) {
      api.getTopology(topologyId).then((h) => {
        setNets(h.nets); setNodes(h.nodes); setEdges(h.edges);
      }).catch(() => {});
    } else {
      setNets(DEMO_NETS); setNodes(DEMO_NODES); setEdges(DEMO_EDGES);
    }
    setSelection(null);
    setPending([]);
    interaction.resetPan();
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setSelection(null);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <div className="maze-page">
      <div className="maze-page-header">
        <div>
          <h1>MAZENET</h1>
          <div className="maze-page-sub">
            {topologyId ? `TOPOLOGY ${topologyId} · ` : 'DEMO · '}
            {nets.length} NETS · {nodes.length} NODES · {edges.length} PATHS ·{' '}
            {pending.length > 0 ? `${pending.length} UNCOMMITTED` : 'LIVE'}
            {loadErr && <span className="alert-text"> · {loadErr}</span>}
          </div>
        </div>
        <div className="maze-page-actions">
          <button
            type="button"
            className="maze-btn ghost"
            onClick={() => setInspectorOpen((o) => !o)}
            title={inspectorOpen ? 'Hide inspector' : 'Show inspector'}
          >
            {inspectorOpen ? <PanelRightClose size={12} /> : <PanelRightOpen size={12} />}
            INSPECTOR
          </button>
          <button type="button" className="maze-btn ghost" onClick={onReset}>
            <RotateCcw size={12} /> RESET
          </button>
          <button
            type="button"
            className="maze-btn"
            disabled={pending.length === 0}
            onClick={() => api.commit(topologyId ?? '', pending)}
          >
            <UploadCloud size={12} /> COMMIT {pending.length > 0 ? `(${pending.length})` : ''}
          </button>
        </div>
      </div>

      <div
        className="maze-shell"
        style={{ gridTemplateColumns: inspectorOpen ? '240px 1fr 320px' : '240px 1fr' }}
      >
        <Palette services={services} />
        <Canvas
          ref={canvasRef}
          nets={nets}
          nodes={nodes}
          edges={edges}
          selection={selection}
          setSelection={setSelection}
          pan={interaction.pan}
          dropTargetId={interaction.dropTargetId}
          dragging={interaction.dragging}
          onCanvasMouseDown={interaction.onCanvasMouseDown}
          onNodeMouseDown={interaction.onNodeMouseDown}
          onNetMouseDown={interaction.onNetMouseDown}
          onNetResizeMouseDown={interaction.onNetResizeMouseDown}
        />
        {inspectorOpen && (
          <Inspector
            selection={selection}
            nets={nets}
            nodes={nodes}
            edges={edges}
            pending={pending}
            onClose={() => setInspectorOpen(false)}
          />
        )}
      </div>
    </div>
  );
};

export default MazeNET;

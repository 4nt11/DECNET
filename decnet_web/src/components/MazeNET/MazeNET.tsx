import React, { useEffect, useState } from 'react';
import { PanelRightOpen, PanelRightClose, RotateCcw, UploadCloud } from 'lucide-react';
import './MazeNET.css';
import Palette from './Palette';
import Inspector from './Inspector';
import type { Selection } from './Inspector';
import { DEFAULT_SERVICES, DEMO_NETS, DEMO_NODES, DEMO_EDGES } from './data';
import type { ServiceDef } from './data';
import type { Net, MazeNode, Edge, PendingChange } from './types';
import { useMazeApi } from './useMazeApi';

const MazeNET: React.FC = () => {
  const api = useMazeApi();

  const [nets,  setNets]  = useState<Net[]>(DEMO_NETS);
  const [nodes, setNodes] = useState<MazeNode[]>(DEMO_NODES);
  const [edges, setEdges] = useState<Edge[]>(DEMO_EDGES);
  const [pending] = useState<PendingChange[]>([]);
  const [selection, setSelection] = useState<Selection>(null);
  const [inspectorOpen, setInspectorOpen] = useState(true);
  const [services, setServices] = useState<ServiceDef[]>(DEFAULT_SERVICES);

  useEffect(() => {
    let cancelled = false;
    api.getServices().then((s) => { if (!cancelled) setServices(s); }).catch(() => {});
    return () => { cancelled = true; };
  }, [api]);

  const onReset = () => {
    setNets(DEMO_NETS); setNodes(DEMO_NODES); setEdges(DEMO_EDGES);
    setSelection(null);
  };

  return (
    <div className="maze-page">
      <div className="maze-page-header">
        <div>
          <h1>MAZENET</h1>
          <div className="maze-page-sub">
            NETWORK OF NETWORKS · {nets.length} NETS · {nodes.length} NODES · {edges.length} PATHS ·{' '}
            {pending.length > 0 ? `${pending.length} UNCOMMITTED` : 'LIVE'}
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
            onClick={() => api.commit('', pending)}
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

        <div className="maze-canvas-wrap">
          <div className="maze-grid-bg">
            <svg xmlns="http://www.w3.org/2000/svg">
              <defs>
                <pattern id="maze-grid-pat" x={0} y={0} width="40" height="40" patternUnits="userSpaceOnUse">
                  <path d="M 40 0 L 0 0 0 40" fill="none" stroke="var(--grid-line)" strokeWidth="1" />
                </pattern>
              </defs>
              <rect width="100%" height="100%" fill="url(#maze-grid-pat)" />
            </svg>
          </div>
          <div className="maze-empty-hint">CANVAS COMES ONLINE IN STEP 4</div>
        </div>

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

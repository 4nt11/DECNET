// SPDX-License-Identifier: AGPL-3.0-or-later
import React from 'react';
import { Server, Trash2 } from '../../../icons';
import type { Edge, MazeNode } from '../types';

interface Props {
  edge: Edge;
  nodes: MazeNode[];
  onDeleteEdge?: (id: string) => void;
}

const EdgeInspector: React.FC<Props> = ({ edge, nodes, onDeleteEdge }) => (
  <>
    <div className="inspector-head">
      <Server size={14} className="violet-accent" />
      <span className="inspector-head-title">EDGE · {edge.id.slice(0, 8)}</span>
    </div>
    <div className="kvs">
      <div className="k">FROM</div>
      <div className="v">{nodes.find((n) => n.id === edge.from)?.name ?? edge.from}</div>
      <div className="k">TO</div>
      <div className="v">{nodes.find((n) => n.id === edge.to)?.name ?? edge.to}</div>
      <div className="k">TRAFFIC</div>
      <div className="v">{edge.traffic.toUpperCase()}</div>
      {edge.label && (
        <>
          <div className="k">LABEL</div>
          <div className="v">{edge.label}</div>
        </>
      )}
    </div>
    {onDeleteEdge && (
      <button
        type="button"
        className="maze-btn alert small"
        onClick={() => onDeleteEdge(edge.id)}
      >
        <Trash2 size={10} /> CUT EDGE
      </button>
    )}
  </>
);

export default EdgeInspector;

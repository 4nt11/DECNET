import React from 'react';
import type { MazeNode } from './types';

interface Props {
  node: MazeNode;
  absX: number;
  absY: number;
  selected: boolean;
  dragging?: boolean;
  onSelect?: (id: string) => void;
  onMouseDown?: (id: string) => (e: React.MouseEvent) => void;
  onPortMouseDown?: (id: string) => (e: React.MouseEvent) => void;
  onContextMenu?: (id: string) => (e: React.MouseEvent) => void;
}

const NodeCard: React.FC<Props> = ({ node, absX, absY, selected, dragging, onSelect, onMouseDown, onPortMouseDown, onContextMenu }) => {
  const classes = [
    'maze-node',
    node.kind === 'observed' ? 'observed' : '',
    node.status === 'hot' ? 'hot' : '',
    selected ? 'selected' : '',
    dragging ? 'dragging' : '',
  ].filter(Boolean).join(' ');

  const handleDown = (e: React.MouseEvent) => {
    onSelect?.(node.id);
    onMouseDown?.(node.id)(e);
  };

  return (
    <div
      className={classes}
      style={{ left: absX, top: absY }}
      onMouseDown={handleDown}
      onContextMenu={onContextMenu?.(node.id)}
    >
      <div className="mn-head">{node.name}</div>
      <div className="mn-sub">{node.archetype.toUpperCase()}</div>
      {node.services.length > 0 && (
        <div className="mn-services">
          {node.services.map((s) => (
            <span key={s} className={`service-tag ${node.status === 'hot' ? 'hot' : ''}`}>
              {s}
            </span>
          ))}
        </div>
      )}
      {node.kind === 'decky' && <>
        <span className="mn-port in" />
        <span className="mn-port out" onMouseDown={onPortMouseDown?.(node.id)} />
      </>}
      {node.kind === 'observed' && (
        <span className="mn-port out" onMouseDown={onPortMouseDown?.(node.id)} />
      )}
    </div>
  );
};

export default NodeCard;

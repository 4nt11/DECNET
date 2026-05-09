import React from 'react';
import { GitMerge, Globe, Plus, Trash2 } from '../../../icons';
import type { MazeNode, Net } from '../types';
import type { Selection } from './types';

interface Props {
  net: Net;
  nodes: MazeNode[];
  /** Set of net ids that have at least one edge — drives the
   *  INACTIVE chip on subnets with no live traffic. */
  activeNetIds: Set<string>;
  setSelection?: (sel: Selection) => void;
  onAddDecky?: (netId: string) => void;
  onDeleteNet?: (id: string) => void;
}

const NetInspector: React.FC<Props> = ({
  net, nodes, activeNetIds, setSelection, onAddDecky, onDeleteNet,
}) => {
  const members = nodes.filter((n) => n.netId === net.id);
  return (
    <>
      <div className="inspector-head">
        {net.kind === 'internet'
          ? <Globe size={14} className="violet-accent" />
          : <GitMerge size={14} className="violet-accent" />}
        <span className="inspector-head-title">{net.label}</span>
        {net.kind !== 'internet' && !activeNetIds.has(net.id) && (
          <span className="chip-mini inspector-head-chip">INACTIVE</span>
        )}
      </div>
      <div className="kvs">
        <div className="k">KIND</div><div className="v">{net.kind.toUpperCase()}</div>
        <div className="k">CIDR</div><div className="v">{net.cidr}</div>
        <div className="k">DECKIES</div>
        <div className="v" style={{ fontWeight: 700 }}>{members.length}</div>
      </div>
      <div>
        <div className="type-label inspector-section-label">MEMBERS</div>
        {members.map((n) => (
          <div
            key={n.id}
            className="inspector-member-row"
            onClick={() => setSelection?.({ type: 'node', id: n.id })}
          >
            <span className={`status-dot ${n.status}`} />
            <span>{n.name}</span>
            <span className="dim inspector-member-arch">{n.archetype}</span>
          </div>
        ))}
        {members.length === 0 && (
          <div className="dim inspector-empty-line">NO MEMBERS</div>
        )}
      </div>
      {net.kind !== 'internet' && onAddDecky && (
        <button type="button" className="maze-btn small" onClick={() => onAddDecky(net.id)}>
          <Plus size={10} /> ADD DECKY
        </button>
      )}
      {net.kind !== 'internet' && onDeleteNet && (
        <button
          type="button"
          className="maze-btn alert small"
          onClick={() => onDeleteNet(net.id)}
        >
          <Trash2 size={10} /> REMOVE NETWORK
        </button>
      )}
    </>
  );
};

export default NetInspector;

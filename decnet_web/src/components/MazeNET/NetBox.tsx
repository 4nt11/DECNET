import React from 'react';
import { Globe, GitMerge } from 'lucide-react';
import type { Net } from './types';

interface Props {
  net: Net;
  selected: boolean;
  dropTarget: boolean;
  inactive: boolean;
  onSelect?: (id: string) => void;
  children?: React.ReactNode;
}

const NetBox: React.FC<Props> = ({ net, selected, dropTarget, inactive, onSelect, children }) => {
  const classes = [
    'maze-net-box',
    net.kind === 'internet' ? 'internet' : '',
    selected ? 'selected' : '',
    dropTarget ? 'drop-target' : '',
    inactive ? 'inactive' : '',
  ].filter(Boolean).join(' ');

  const Icon = net.kind === 'internet' ? Globe : GitMerge;
  const resizable = net.kind !== 'internet';

  return (
    <div
      className={classes}
      style={{ left: net.x, top: net.y, width: net.w, height: net.h }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) { e.stopPropagation(); onSelect?.(net.id); }
      }}
    >
      <div
        className="maze-net-box-head"
        onMouseDown={(e) => { e.stopPropagation(); onSelect?.(net.id); }}
      >
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <Icon size={10} />
          <span>{net.label}</span>
          {inactive && (
            <span
              className="chip-mini"
              style={{ marginLeft: 4, borderColor: 'var(--border)', color: 'rgba(255,255,255,0.45)' }}
            >
              INACTIVE
            </span>
          )}
        </div>
        <span className="cidr">{net.cidr}</span>
      </div>
      {resizable && (
        <>
          <div className="net-resize net-resize-e" />
          <div className="net-resize net-resize-w" />
          <div className="net-resize net-resize-s" />
          <div className="net-resize net-resize-n" />
          <div className="net-resize net-resize-se" />
          <div className="net-resize net-resize-sw" />
          <div className="net-resize net-resize-ne" />
          <div className="net-resize net-resize-nw" />
        </>
      )}
      {children}
    </div>
  );
};

export default NetBox;

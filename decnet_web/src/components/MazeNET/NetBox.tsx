import React from 'react';
import { Globe, GitMerge, ShieldAlert } from '../../icons';
import type { Net } from './types';
import type { ResizeHandle } from './useMazeInteraction';

interface Props {
  net: Net;
  selected: boolean;
  dropTarget: boolean;
  inactive: boolean;
  deployed?: boolean;
  onSelect?: (id: string) => void;
  onHeaderMouseDown?: (id: string) => (e: React.MouseEvent) => void;
  onResizeMouseDown?: (id: string, handle: ResizeHandle) => (e: React.MouseEvent) => void;
  onContextMenu?: (e: React.MouseEvent) => void;
  children?: React.ReactNode;
}

const NetBox: React.FC<Props> = ({
  net, selected, dropTarget, inactive, deployed, onSelect, onHeaderMouseDown, onResizeMouseDown, onContextMenu, children,
}) => {
  const classes = [
    'maze-net-box',
    net.kind === 'internet' ? 'internet' : '',
    net.kind === 'dmz' ? 'dmz' : '',
    selected ? 'selected' : '',
    dropTarget ? 'drop-target' : '',
    inactive ? 'inactive' : '',
    deployed ? 'deployed' : '',
    net.pending ? 'pending' : '',
  ].filter(Boolean).join(' ');

  const Icon = net.kind === 'internet' ? Globe : net.kind === 'dmz' ? ShieldAlert : GitMerge;
  const resizable = net.kind !== 'internet';

  const handleBoxDown = (e: React.MouseEvent) => {
    if (e.target !== e.currentTarget) return;
    onSelect?.(net.id);
  };

  const handleHeadDown = (e: React.MouseEvent) => {
    onSelect?.(net.id);
    onHeaderMouseDown?.(net.id)(e);
  };

  return (
    <div
      className={classes}
      style={{ left: net.x, top: net.y, width: net.w, height: net.h }}
      onMouseDown={handleBoxDown}
      onContextMenu={onContextMenu}
    >
      <div className="maze-net-box-head" onMouseDown={handleHeadDown}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <Icon size={10} />
          <span>{net.label}</span>
          {inactive && !net.pending && (
            <span className="chip-mini"
                  style={{ marginLeft: 4, borderColor: 'var(--border)', color: 'var(--fg-4)' }}>
              INACTIVE
            </span>
          )}
          {net.pending && (
            <span className="chip-mini"
                  style={{ marginLeft: 4,
                           borderColor: 'var(--warn, #e0a040)',
                           color: 'var(--warn, #e0a040)' }}>
              PENDING
            </span>
          )}
        </div>
        <span className="cidr">{net.cidr}</span>
      </div>
      {resizable && onResizeMouseDown && (
        <>
          <div className="net-resize net-resize-e"  onMouseDown={onResizeMouseDown(net.id, 'e')} />
          <div className="net-resize net-resize-w"  onMouseDown={onResizeMouseDown(net.id, 'w')} />
          <div className="net-resize net-resize-s"  onMouseDown={onResizeMouseDown(net.id, 's')} />
          <div className="net-resize net-resize-n"  onMouseDown={onResizeMouseDown(net.id, 'n')} />
          <div className="net-resize net-resize-se" onMouseDown={onResizeMouseDown(net.id, 'se')} />
          <div className="net-resize net-resize-sw" onMouseDown={onResizeMouseDown(net.id, 'sw')} />
          <div className="net-resize net-resize-ne" onMouseDown={onResizeMouseDown(net.id, 'ne')} />
          <div className="net-resize net-resize-nw" onMouseDown={onResizeMouseDown(net.id, 'nw')} />
        </>
      )}
      {children}
    </div>
  );
};

export default React.memo(NetBox);

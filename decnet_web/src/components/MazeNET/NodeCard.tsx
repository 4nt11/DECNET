// SPDX-License-Identifier: AGPL-3.0-or-later
import React from 'react';
import {
  Server, Monitor, Shield, Database, Cpu, Globe, Users, HardDrive, Eye,
  type LucideIcon,
} from '../../icons';
import type { MazeNode } from './types';
import { DEFAULT_SERVICES } from './data';

const ARCHETYPE_ICONS: Record<string, LucideIcon> = {
  'linux-server': Server,
  'windows-workstation': Monitor,
  'domain-controller': Shield,
  'database-server': Database,
  'iot-device': Cpu,
  'web-application': Globe,
  'deaddeck': HardDrive,
  'attacker-pool': Eye,
  'directory-services': Users,
};

interface Props {
  node: MazeNode;
  absX: number;
  absY: number;
  selected: boolean;
  dragging?: boolean;
  deployed?: boolean;
  selectedServiceSlug?: string | null;
  onSelect?: (id: string) => void;
  onSelectService?: (nodeId: string, slug: string) => void;
  onMouseDown?: (id: string) => (e: React.MouseEvent) => void;
  onPortMouseDown?: (id: string) => (e: React.MouseEvent) => void;
  onContextMenu?: (id: string) => (e: React.MouseEvent) => void;
}

const NodeCard: React.FC<Props> = ({ node, absX, absY, selected, dragging, deployed, selectedServiceSlug, onSelect, onSelectService, onMouseDown, onPortMouseDown, onContextMenu }) => {
  const isDmzGateway = !!(node as { decky_config?: { forwards_l3?: boolean } }).decky_config?.forwards_l3;
  const classes = [
    'maze-node',
    node.kind === 'observed' ? 'observed' : '',
    node.status === 'hot' ? 'hot' : '',
    selected ? 'selected' : '',
    dragging ? 'dragging' : '',
    deployed ? 'deployed' : '',
    deployed && isDmzGateway ? 'dmz-gateway' : '',
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
      <div className="mn-head">
        <span className={`status-dot ${node.status}`} />
        {(() => {
          const Icon = ARCHETYPE_ICONS[node.archetype] ?? Server;
          return <Icon size={10} className="mn-head-icon" />;
        })()}
        <span className="mn-head-name">{node.name}</span>
      </div>
      <div className="mn-sub">{node.archetype.toUpperCase()}</div>
      {node.services.length > 0 && (
        <div className="mn-services">
          {node.services.map((s) => {
            const meta = DEFAULT_SERVICES.find((x) => x.slug === s);
            const isHigh = meta?.risk === 'high' || node.status === 'hot';
            const isSel = selectedServiceSlug === s;
            return (
              <span
                key={s}
                className={`service-tag ${isHigh ? 'hot' : ''} ${isSel ? 'service-selected' : ''}`}
                title={meta ? `${meta.name} · ${meta.proto.toUpperCase()}:${meta.port}` : s}
                onMouseDown={(e) => {
                  if (!onSelectService) return;
                  e.stopPropagation();
                  onSelectService(node.id, s);
                }}
              >
                {s}
              </span>
            );
          })}
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

export default React.memo(NodeCard);

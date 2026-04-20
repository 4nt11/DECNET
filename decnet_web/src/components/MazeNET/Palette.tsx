import React from 'react';
import { GitMerge, Server, Monitor, Shield, Database, Cpu, Globe,
         Terminal, Lock, Folder, HardDrive, Users, KeyRound,
         Radio, Zap, Wifi, Circle } from 'lucide-react';
import { ARCHETYPES } from './data';
import type { ServiceDef, Archetype } from './data';

const ICON: Record<string, React.ComponentType<{ size?: number; className?: string }>> = {
  'git-merge': GitMerge, server: Server, monitor: Monitor, shield: Shield,
  database: Database, cpu: Cpu, globe: Globe, terminal: Terminal, lock: Lock,
  folder: Folder, 'hard-drive': HardDrive, users: Users, 'key-round': KeyRound,
  radio: Radio, zap: Zap, wifi: Wifi, circle: Circle,
};

function Icon({ name, size = 14, className }: { name: string; size?: number; className?: string }) {
  const C = ICON[name] ?? Circle;
  return <C size={size} className={className} />;
}

interface Props {
  services: ServiceDef[];
  onPaletteDragStart?: (kind: 'network' | 'archetype' | 'service', slug: string, label: string) => void;
}

const Palette: React.FC<Props> = ({ services, onPaletteDragStart }) => {
  const start = (kind: 'network' | 'archetype' | 'service', slug: string, label: string) =>
    (e: React.MouseEvent) => { e.preventDefault(); onPaletteDragStart?.(kind, slug, label); };

  return (
    <div className="maze-palette">
      <div className="palette-group">
        <label>① NETWORKS</label>
        <div className="palette-item" onMouseDown={start('network', 'subnet', 'SUBNET')}>
          <Icon name="git-merge" className="violet-accent" />
          <span>Subnet</span>
          <span className="chip-mini">VLAN</span>
        </div>
      </div>

      <div className="palette-group">
        <label>② ARCHETYPES</label>
        {ARCHETYPES.map((a: Archetype) => (
          <div key={a.slug} className="palette-item" onMouseDown={start('archetype', a.slug, a.name)}>
            <Icon name={a.icon} className="violet-accent" />
            <span>{a.name}</span>
            <span className="chip-mini">{a.services.length}</span>
          </div>
        ))}
      </div>

      <div className="palette-group">
        <label>③ SERVICES</label>
        {services.map((s) => (
          <div key={s.slug} className="palette-item" onMouseDown={start('service', s.slug, s.name)}>
            <Icon
              name={s.icon}
              size={12}
              className={s.risk === 'high' ? 'alert-text' : s.risk === 'med' ? 'violet-accent' : 'matrix-text'}
            />
            <span>{s.name}</span>
            <span className="chip-mini">{s.proto.toUpperCase()}:{s.port}</span>
          </div>
        ))}
      </div>

      <div className="palette-group">
        <label>HINT</label>
        <div className="palette-hint">
          Drag empty canvas to pan. Right-click anything for a menu. Subnets
          must be wired to something or they go inactive.
        </div>
      </div>
    </div>
  );
};

export default Palette;

import React from 'react';
import { GitMerge, ShieldAlert, Server, Monitor, Shield, Database, Cpu, Globe,
         Terminal, Lock, Folder, HardDrive, Users, KeyRound,
         Radio, Zap, Wifi, Circle, Mail, Phone, Activity, Box } from '../../icons';
import type { ServiceDef, Archetype, ServiceGroup } from './data';
import { SERVICE_GROUP_ORDER } from './data';
import type { PaletteDrag } from './useMazeInteraction';

const ICON: Record<string, React.ComponentType<{ size?: number; className?: string }>> = {
  'git-merge': GitMerge, 'shield-alert': ShieldAlert,
  server: Server, monitor: Monitor, shield: Shield,
  database: Database, cpu: Cpu, globe: Globe, terminal: Terminal, lock: Lock,
  folder: Folder, 'hard-drive': HardDrive, users: Users, 'key-round': KeyRound,
  radio: Radio, zap: Zap, wifi: Wifi, circle: Circle,
  mail: Mail, phone: Phone, activity: Activity, box: Box,
};

function Icon({ name, size = 14, className }: { name: string; size?: number; className?: string }) {
  const C = ICON[name] ?? Circle;
  return <C size={size} className={className} />;
}

interface Props {
  services: ServiceDef[];
  archetypes: Archetype[];
  startPaletteDrag: (d: Omit<PaletteDrag, 'clientX' | 'clientY'>, e: React.MouseEvent) => void;
  className?: string;
}

const Palette: React.FC<Props> = ({ services, archetypes, startPaletteDrag, className = '' }) => {
  const start = (d: Omit<PaletteDrag, 'clientX' | 'clientY'>) =>
    (e: React.MouseEvent) => {
      if (e.button !== 0) return;
      e.preventDefault();
      startPaletteDrag(d, e);
    };

  return (
    <div className={`maze-palette ${className}`}>
      <div className="palette-group">
        <label>① NETWORKS</label>
        <div className="palette-item" onMouseDown={start({ kind: 'network-subnet', slug: 'subnet', label: 'SUBNET' })}>
          <Icon name="git-merge" className="violet-accent" />
          <span>Subnet</span>
          <span className="chip-mini">VLAN</span>
        </div>
        <div className="palette-item" onMouseDown={start({ kind: 'network-dmz', slug: 'dmz', label: 'DMZ' })}>
          <Icon name="shield-alert" className="alert-text" />
          <span>DMZ</span>
          <span className="chip-mini">HOST</span>
        </div>
      </div>

      <div className="palette-group">
        <label>② ARCHETYPES</label>
        {archetypes.map((a: Archetype) => (
          <div
            key={a.slug}
            className="palette-item"
            onMouseDown={start({ kind: 'archetype', slug: a.slug, label: a.name, services: a.services })}
          >
            <Icon name={a.icon} className="violet-accent" />
            <span>{a.name}</span>
            <span className="chip-mini">{a.services.length}</span>
          </div>
        ))}
      </div>

      <div className="palette-group">
        <label>③ SERVICES</label>
        {(() => {
          const byGroup = new Map<ServiceGroup, ServiceDef[]>();
          for (const s of services) {
            const g = (s.group ?? 'Miscellaneous') as ServiceGroup;
            const list = byGroup.get(g) ?? [];
            list.push(s);
            byGroup.set(g, list);
          }
          const extras = [...byGroup.keys()].filter((g) => !SERVICE_GROUP_ORDER.includes(g));
          const order = [...SERVICE_GROUP_ORDER, ...extras];
          return order
            .filter((g) => byGroup.has(g))
            .map((g) => (
              <div key={g} className="palette-subgroup">
                <div className="palette-subgroup-label">{g.toUpperCase()}</div>
                {byGroup.get(g)!.map((s) => (
                  <div
                    key={s.slug}
                    className="palette-item"
                    onMouseDown={start({ kind: 'service', slug: s.slug, label: s.name })}
                  >
                    <Icon
                      name={s.icon}
                      size={12}
                      className={s.risk === 'high' ? 'alert-text' : s.risk === 'med' ? 'violet-accent' : 'matrix-text'}
                    />
                    <span>{s.name}</span>
                    <span className="chip-mini">{s.proto.toUpperCase()}/{s.port}</span>
                  </div>
                ))}
              </div>
            ));
        })()}
      </div>

      <div className="palette-group">
        <label>HINT</label>
        <div className="palette-hint">
          Drag a network onto the canvas, or an archetype onto a network,
          or a service onto a decky. Right-click for menus.
        </div>
      </div>
    </div>
  );
};

export default Palette;

import type { Net, MazeNode, Edge } from './types';

export interface Archetype {
  slug: string;
  name: string;
  services: string[];
  icon: string;
}

export interface ServiceDef {
  slug: string;
  name: string;
  port: number;
  proto: 'tcp' | 'udp';
  icon: string;
  risk: 'low' | 'med' | 'high';
}

export const ARCHETYPES: Archetype[] = [
  { slug: 'linux-server',        name: 'Linux Server',        services: ['ssh', 'http'],                             icon: 'server' },
  { slug: 'windows-workstation', name: 'Windows Workstation', services: ['smb', 'rdp'],                              icon: 'monitor' },
  { slug: 'domain-controller',   name: 'Domain Controller',   services: ['smb', 'rdp', 'ldap', 'llmnr', 'kerberos'], icon: 'shield' },
  { slug: 'database-server',     name: 'Database Server',     services: ['mysql', 'postgres', 'redis'],              icon: 'database' },
  { slug: 'iot-device',          name: 'IoT / OT Device',     services: ['modbus', 'mqtt', 'coap'],                  icon: 'cpu' },
  { slug: 'web-application',     name: 'Web Application',     services: ['http', 'https'],                           icon: 'globe' },
];

export const DEFAULT_SERVICES: ServiceDef[] = [
  { slug: 'ssh',      name: 'SSH',      port: 22,   proto: 'tcp', icon: 'terminal',   risk: 'high' },
  { slug: 'http',     name: 'HTTP',     port: 80,   proto: 'tcp', icon: 'globe',      risk: 'med' },
  { slug: 'https',    name: 'HTTPS',    port: 443,  proto: 'tcp', icon: 'lock',       risk: 'med' },
  { slug: 'ftp',      name: 'FTP',      port: 21,   proto: 'tcp', icon: 'folder',     risk: 'high' },
  { slug: 'smb',      name: 'SMB',      port: 445,  proto: 'tcp', icon: 'hard-drive', risk: 'high' },
  { slug: 'rdp',      name: 'RDP',      port: 3389, proto: 'tcp', icon: 'monitor',    risk: 'high' },
  { slug: 'ldap',     name: 'LDAP',     port: 389,  proto: 'tcp', icon: 'users',      risk: 'med' },
  { slug: 'kerberos', name: 'Kerberos', port: 88,   proto: 'tcp', icon: 'key-round',  risk: 'med' },
  { slug: 'llmnr',    name: 'LLMNR',    port: 5355, proto: 'udp', icon: 'radio',      risk: 'low' },
  { slug: 'mysql',    name: 'MySQL',    port: 3306, proto: 'tcp', icon: 'database',   risk: 'high' },
  { slug: 'postgres', name: 'Postgres', port: 5432, proto: 'tcp', icon: 'database',   risk: 'high' },
  { slug: 'redis',    name: 'Redis',    port: 6379, proto: 'tcp', icon: 'zap',        risk: 'med' },
  { slug: 'mqtt',     name: 'MQTT',     port: 1883, proto: 'tcp', icon: 'wifi',       risk: 'low' },
  { slug: 'modbus',   name: 'Modbus',   port: 502,  proto: 'tcp', icon: 'cpu',        risk: 'med' },
  { slug: 'coap',     name: 'CoAP',     port: 5683, proto: 'udp', icon: 'wifi',       risk: 'low' },
];

/* Demo seed mirroring design-handoff/.../MazeNET.jsx INITIAL_* */
export const DEMO_NETS: Net[] = [
  { id: 'net-internet', label: 'INTERNET', cidr: '0.0.0.0/0',    kind: 'internet', x: 40,  y: 40,  w: 240, h: 220 },
  { id: 'net-dmz',      label: 'DMZ',      cidr: '10.4.2.0/24',  kind: 'subnet',   x: 340, y: 40,  w: 340, h: 260 },
  { id: 'net-corp',     label: 'CORP-LAN', cidr: '10.20.0.0/16', kind: 'subnet',   x: 340, y: 340, w: 340, h: 240 },
  { id: 'net-vault',    label: 'DB-VAULT', cidr: '10.88.1.0/24', kind: 'subnet',   x: 740, y: 200, w: 260, h: 220 },
];

export const DEMO_NODES: MazeNode[] = [
  { id: 'n-scan', kind: 'observed', netId: 'net-internet', name: 'SCANNERS',  archetype: 'attacker-pool',       services: ['*'],              status: 'hot',    x: 60,  y: 80 },
  { id: 'n-edge', kind: 'decky',    netId: 'net-dmz',      name: 'decky-01',  archetype: 'linux-server',        services: ['ssh', 'http'],    status: 'active', x: 20,  y: 60 },
  { id: 'n-jump', kind: 'decky',    netId: 'net-dmz',      name: 'decky-03',  archetype: 'linux-server',        services: ['ssh'],            status: 'hot',    x: 180, y: 60 },
  { id: 'n-web',  kind: 'decky',    netId: 'net-dmz',      name: 'decky-07',  archetype: 'web-application',     services: ['http'],           status: 'active', x: 20,  y: 160 },
  { id: 'n-ws',   kind: 'decky',    netId: 'net-corp',     name: 'decky-02',  archetype: 'windows-workstation', services: ['smb', 'rdp'],     status: 'active', x: 20,  y: 60 },
  { id: 'n-dc',   kind: 'decky',    netId: 'net-corp',     name: 'decky-05',  archetype: 'domain-controller',   services: ['ldap', 'smb'],    status: 'active', x: 180, y: 60 },
  { id: 'n-db',   kind: 'decky',    netId: 'net-vault',    name: 'decky-12',  archetype: 'database-server',     services: ['mysql', 'postgres'], status: 'active', x: 50, y: 80 },
];

export const DEMO_EDGES: Edge[] = [
  { id: 'e1', from: 'n-scan', to: 'n-edge', traffic: 'hot',    label: 'TCP 443' },
  { id: 'e2', from: 'n-scan', to: 'n-jump', traffic: 'hot',    label: 'TCP 22' },
  { id: 'e3', from: 'n-edge', to: 'n-ws',   traffic: 'active', label: '' },
  { id: 'e4', from: 'n-jump', to: 'n-dc',   traffic: 'hot',    label: 'LAT-MOV' },
  { id: 'e5', from: 'n-dc',   to: 'n-db',   traffic: 'active', label: '' },
  { id: 'e6', from: 'n-web',  to: 'n-db',   traffic: 'active', label: 'SQL' },
];

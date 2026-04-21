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


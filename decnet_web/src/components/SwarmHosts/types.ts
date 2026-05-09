export interface SwarmHost {
  uuid: string;
  name: string;
  address: string;
  agent_port: number;
  status: string;
  last_heartbeat: string | null;
  client_cert_fingerprint: string;
  updater_cert_fingerprint: string | null;
  enrolled_at: string;
  notes: string | null;
}

export interface BundleResult {
  token: string;
  host_uuid: string;
  command: string;
  expires_at: string;
}

export interface BundleRequest {
  master_host: string;
  agent_name: string;
  with_updater: boolean;
  use_ipvlan: boolean;
  services_ini: string | null;
}

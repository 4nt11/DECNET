/** Wire + UI types for the CanaryTokens page surface. */

export interface BlobRow {
  uuid: string;
  sha256: string;
  filename: string;
  content_type: string;
  size_bytes: number;
  uploaded_by: string;
  uploaded_at: string;
  token_count: number;
}

export interface DeckyOption {
  name: string;
  ip?: string;
}

export interface TopologyOption {
  id: string;
  name: string;
  status: string;
}

export type Scope = 'fleet' | 'topology';

export const KNOWN_GENERATORS = [
  'git_config', 'env_file', 'ssh_key', 'aws_creds',
  'honeydoc', 'honeydoc_docx', 'honeydoc_pdf',
] as const;

export type GeneratorName = typeof KNOWN_GENERATORS[number];

export const KIND_OPTIONS: Array<{ value: 'http' | 'dns' | 'aws_passive'; label: string }> = [
  { value: 'http', label: 'HTTP callback' },
  { value: 'dns', label: 'DNS callback' },
  { value: 'aws_passive', label: 'AWS passive (no callback)' },
];

export const STATE_COLOR: Record<'planted' | 'revoked' | 'failed', string> = {
  planted: '#00ff88',
  revoked: 'var(--dim-color)',
  failed: '#ff5555',
};

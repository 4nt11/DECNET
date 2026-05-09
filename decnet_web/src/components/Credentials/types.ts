export type { CredentialEntry } from '../CredentialsInspector';
export type { CredentialReuseRow } from '../CredentialReuseInspector';

export type Tab = 'creds' | 'reuse';

export interface ReuseMapEntry {
  id: string;
  target_count: number;
}

export type SortDir = 'asc' | 'desc';

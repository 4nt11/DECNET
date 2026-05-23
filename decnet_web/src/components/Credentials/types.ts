// SPDX-License-Identifier: AGPL-3.0-or-later
export type { CredentialEntry } from '../CredentialsInspector';
export type { CredentialReuseRow } from '../CredentialReuseInspector';

export type Tab = 'creds' | 'reuse';

export interface ReuseMapEntry {
  id: string;
  target_count: number;
}

export type SortDir = 'asc' | 'desc';

// SPDX-License-Identifier: AGPL-3.0-or-later
/** Wire + UI types for the Config page surface. */

export interface UserEntry {
  uuid: string;
  username: string;
  role: string;
  must_change_password: boolean;
}

export interface ConfigData {
  role: string;
  deployment_limit: number;
  global_mutation_interval: string;
  users?: UserEntry[];
  developer_mode?: boolean;
}

/** Inline success/error chip surfaced under each form section. */
export type FormMsg = { type: 'success' | 'error'; text: string };

export type ConfigTab =
  | 'limits'
  | 'users'
  | 'globals'
  | 'appearance'
  | 'workers'
  | 'ttp'
  | 'llm';

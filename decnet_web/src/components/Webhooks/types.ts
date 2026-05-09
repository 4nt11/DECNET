export type SimpleEvent = 'AttackerDetail' | 'DeckyStatus' | 'SystemStatus';

export interface WebhookRow {
  uuid: string;
  name: string;
  url: string;
  topic_patterns: string[];
  enabled: boolean;
  consecutive_failures: number;
  last_success_at: string | null;
  last_failure_at: string | null;
  last_error: string | null;
  auto_disabled_at: string | null;
  created_at: string;
  updated_at: string;
  warnings: string[];
}

export interface FormState {
  name: string;
  url: string;
  /** blank = server auto-generates (create) / keep existing (edit) */
  secret: string;
  simple_events: SimpleEvent[];
  /** textarea: one per line */
  topic_patterns: string;
  enabled: boolean;
}

export interface WebhookSavePayload {
  name: string;
  url: string;
  secret?: string;
  simple_events: SimpleEvent[];
  topic_patterns: string[];
  enabled: boolean;
}

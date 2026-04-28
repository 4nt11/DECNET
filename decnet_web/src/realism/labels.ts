/* Human-readable labels for realism content classes.
 *
 * Source of truth for the enum values is decnet/realism/taxonomy.py.
 * This module is the only place display text lives — every UI surface
 * that renders a content_class should call ``contentClassLabel(value)``
 * so the label vocabulary stays consistent across the dashboard. */

const LABELS: Record<string, string> = {
  // User classes — files written by personas during work hours.
  note: 'Note',
  todo: 'TODO List',
  draft: 'Draft Document',
  script: 'Shell / Python Script',

  // System classes — plausible OS-side filler.
  log_cron: 'Cron Log',
  log_daemon: 'Daemon Log',
  cache_tmp: 'Cache / Temp File',

  // Canary classes — callback-bearing artifacts.
  canary_aws_creds: 'Canary · AWS Credentials',
  canary_env_file: 'Canary · .env File',
  canary_git_config: 'Canary · git config',
  canary_ssh_key: 'Canary · SSH Private Key',
  canary_honeydoc: 'Canary · HTML Honeydoc',
  canary_honeydoc_docx: 'Canary · DOCX Honeydoc',
  canary_honeydoc_pdf: 'Canary · PDF Honeydoc',
  canary_mysql_dump: 'Canary · MySQL Dump',
};

export function contentClassLabel(value: string): string {
  return LABELS[value] ?? value;
}

/* Returns true when the value is a canary class. Used to style canary
 * rows differently in tables (subtle red accent, etc). */
export function isCanaryClass(value: string): boolean {
  return value.startsWith('canary_');
}

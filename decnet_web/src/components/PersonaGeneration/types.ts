export type Tone = 'formal' | 'direct' | 'casual' | 'technical' | 'custom';
export type ReplyLatency = 'fast' | 'normal' | 'slow';

export interface EmailPersona {
  name: string;
  email: string;
  role: string;
  tone: Tone;
  tone_custom: string | null;
  mannerisms: string[];
  language: string | null;
  signature: string | null;
  active_hours: string;
  reply_latency: ReplyLatency;
  uses_llms_heavily: boolean;
}

export interface PersonasResponse {
  path?: string;
  topology_name?: string;
  language_default?: string;
  personas: EmailPersona[];
}

export type FilterKey = 'all' | Tone;

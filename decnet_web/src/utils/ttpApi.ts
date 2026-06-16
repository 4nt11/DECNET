// SPDX-License-Identifier: AGPL-3.0-or-later
import api from './api';
import type { GroupRef, TechniqueRow, TTPTagDetailRow } from '../types/ttp';

export type TTPScope = 'identity' | 'attacker' | 'session';

export async function fetchTechniques(scope: TTPScope, uuid: string): Promise<TechniqueRow[]> {
  const res = await api.get(`/ttp/by-${scope}/${uuid}`);
  return Array.isArray(res.data) ? res.data : [];
}

export async function fetchTagsForTechnique(
  scope: TTPScope,
  uuid: string,
  techniqueId: string,
  subTechniqueId?: string | null,
): Promise<TTPTagDetailRow[]> {
  const params: Record<string, string> = {};
  if (subTechniqueId) params.sub_technique_id = subTechniqueId;
  const res = await api.get(`/ttp/tags/by-${scope}/${uuid}/${techniqueId}`, { params });
  return Array.isArray(res.data) ? res.data : [];
}

export async function fetchGroupsForTechnique(techniqueId: string): Promise<GroupRef[]> {
  const res = await api.get(`/ttp/techniques/${techniqueId}/groups`);
  return Array.isArray(res.data) ? res.data : [];
}

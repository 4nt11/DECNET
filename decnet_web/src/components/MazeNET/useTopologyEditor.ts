/**
 * Status-aware topology editor — wraps {@link useMazeApi} so the MazeNET
 * editor can call one set of primitives regardless of whether the
 * topology is ``pending`` (direct CRUD) or ``active|degraded`` (mutation
 * queue via :func:`enqueueMutation`).
 *
 * Primitives return a tagged {@link PrimitiveResult}:
 *   ``{ kind: 'applied', data }``   — backend wrote synchronously; the
 *                                     caller may update local state.
 *   ``{ kind: 'enqueued', mutationId }`` — mutator will apply async;
 *                                     caller must NOT touch local state,
 *                                     SSE ``mutation.applied`` drives refetch.
 *
 * Name arguments (``deckyName``, ``lanName``) are required on every
 * primitive because mutation ops are name-keyed while direct CRUD is
 * uuid-keyed. Callers plumb both.
 */
import { useMemo } from 'react';
import type {
  CreateDeckyBody,
  CreateLanBody,
  DeckyRow,
  EdgeRow,
  LANRow,
  UseMazeApi,
} from './useMazeApi';

export interface UseTopologyEditorOptions {
  api: UseMazeApi;
  /** Current topology status from :func:`getTopology`. */
  topoStatus: string;
  /** Last-known topology version for optimistic concurrency. */
  topoVersion: number;
}

export type PrimitiveResult<T> =
  | { kind: 'applied'; data: T }
  | { kind: 'enqueued'; mutationId: string };

export interface UseTopologyEditor {
  createLan(topologyId: string, body: CreateLanBody): Promise<PrimitiveResult<LANRow>>;
  updateLan(
    topologyId: string,
    lanId: string,
    lanName: string,
    patch: Partial<LANRow>,
  ): Promise<PrimitiveResult<LANRow>>;
  deleteLan(
    topologyId: string,
    lanId: string,
    lanName: string,
  ): Promise<PrimitiveResult<void>>;

  createDecky(topologyId: string, body: CreateDeckyBody): Promise<PrimitiveResult<DeckyRow>>;
  updateDecky(
    topologyId: string,
    uuid: string,
    deckyName: string,
    patch: Partial<DeckyRow>,
  ): Promise<PrimitiveResult<DeckyRow>>;
  deleteDecky(
    topologyId: string,
    uuid: string,
    deckyName: string,
  ): Promise<PrimitiveResult<void>>;

  attachEdge(
    topologyId: string,
    body: { decky_uuid: string; lan_id: string; is_bridge?: boolean; forwards_l3?: boolean },
    deckyName: string,
    lanName: string,
  ): Promise<PrimitiveResult<EdgeRow>>;
  detachEdge(
    topologyId: string,
    edgeId: string,
    deckyName: string,
    lanName: string,
  ): Promise<PrimitiveResult<void>>;
}

export function useTopologyEditor(
  opts: UseTopologyEditorOptions,
): UseTopologyEditor {
  const { api, topoStatus, topoVersion } = opts;
  const live = topoStatus === 'active' || topoStatus === 'degraded';

  return useMemo<UseTopologyEditor>(() => ({
    // ── LAN ────────────────────────────────────────────────────────────
    async createLan(topologyId, body) {
      if (!live) {
        const data = await api.createLan(topologyId, body);
        return { kind: 'applied', data };
      }
      // add_lan payload: {name, subnet?, is_dmz?, x?, y?}
      const payload: Record<string, unknown> = { name: body.name };
      if (body.subnet !== undefined) payload.subnet = body.subnet;
      if (body.is_dmz !== undefined) payload.is_dmz = body.is_dmz;
      if (body.x !== undefined) payload.x = body.x;
      if (body.y !== undefined) payload.y = body.y;
      const res = await api.enqueueMutation(topologyId, 'add_lan', payload, topoVersion);
      return { kind: 'enqueued', mutationId: res.mutation_id };
    },
    async updateLan(topologyId, lanId, lanName, patch) {
      if (!live) {
        const data = await api.updateLan(topologyId, lanId, patch);
        return { kind: 'applied', data };
      }
      const payload: Record<string, unknown> = { name: lanName };
      const patchFields: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(patch)) {
        if (k === 'x' || k === 'y') payload[k] = v;
        else patchFields[k] = v;
      }
      if (Object.keys(patchFields).length > 0) payload.patch = patchFields;
      const res = await api.enqueueMutation(topologyId, 'update_lan', payload, topoVersion);
      return { kind: 'enqueued', mutationId: res.mutation_id };
    },
    async deleteLan(topologyId, lanId, lanName) {
      if (!live) {
        await api.deleteLan(topologyId, lanId);
        return { kind: 'applied', data: undefined };
      }
      const res = await api.enqueueMutation(
        topologyId, 'remove_lan', { name: lanName }, topoVersion,
      );
      return { kind: 'enqueued', mutationId: res.mutation_id };
    },

    // ── Decky ──────────────────────────────────────────────────────────
    async createDecky(topologyId, body) {
      // No add_decky mutation op — decky creation on active topologies
      // is a composite (attach_decky with the create implicit). Phase B
      // step 3 handles that; for now creation stays direct-CRUD so the
      // pending path keeps working.  On active this will 409 today until
      // step 3 lands a combined flow.
      const data = await api.createDecky(topologyId, body);
      return { kind: 'applied', data };
    },
    async updateDecky(topologyId, uuid, deckyName, patch) {
      if (!live) {
        const data = await api.updateDecky(topologyId, uuid, patch);
        return { kind: 'applied', data };
      }
      const payload: Record<string, unknown> = { decky: deckyName };
      const patchFields: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(patch)) {
        if (k === 'services' || k === 'x' || k === 'y') payload[k] = v;
        else patchFields[k] = v;
      }
      if (Object.keys(patchFields).length > 0) payload.patch = patchFields;
      const res = await api.enqueueMutation(topologyId, 'update_decky', payload, topoVersion);
      return { kind: 'enqueued', mutationId: res.mutation_id };
    },
    async deleteDecky(topologyId, uuid, deckyName) {
      if (!live) {
        await api.deleteDecky(topologyId, uuid);
        return { kind: 'applied', data: undefined };
      }
      const res = await api.enqueueMutation(
        topologyId, 'remove_decky', { decky: deckyName }, topoVersion,
      );
      return { kind: 'enqueued', mutationId: res.mutation_id };
    },

    // ── Edges ──────────────────────────────────────────────────────────
    async attachEdge(topologyId, body, deckyName, lanName) {
      if (!live) {
        const data = await api.attachEdge(topologyId, body);
        return { kind: 'applied', data };
      }
      const payload: Record<string, unknown> = { decky: deckyName, lan: lanName };
      if (body.forwards_l3 !== undefined) payload.forwards_l3 = body.forwards_l3;
      const res = await api.enqueueMutation(topologyId, 'attach_decky', payload, topoVersion);
      return { kind: 'enqueued', mutationId: res.mutation_id };
    },
    async detachEdge(topologyId, edgeId, deckyName, lanName) {
      if (!live) {
        await api.detachEdge(topologyId, edgeId);
        return { kind: 'applied', data: undefined };
      }
      const res = await api.enqueueMutation(
        topologyId, 'detach_decky', { decky: deckyName, lan: lanName }, topoVersion,
      );
      return { kind: 'enqueued', mutationId: res.mutation_id };
    },
  }), [api, live, topoVersion]);
}

/**
 * Status-aware topology editor — wraps {@link useMazeApi} so the MazeNET
 * editor can call one set of primitives regardless of whether the
 * topology is ``pending`` (direct CRUD) or ``active|degraded`` (mutation
 * queue via :func:`enqueueMutation`).
 *
 * Phase B scaffolding — for now every primitive is a pass-through to
 * the direct-CRUD method on ``useMazeApi``.  Behavior is unchanged from
 * calling ``api.*`` directly.  Status branching lands one primitive at
 * a time in the follow-up commits so each change is small and
 * reviewable.
 *
 * The ``*Name`` arguments (``deckyName``, ``lanName``, …) are unused in
 * this pass — they're captured on the call site now so the signatures
 * don't change when the enqueue branches are added: mutation ops are
 * name-keyed while direct CRUD is uuid-keyed, and forcing the caller
 * to plumb both through the editor hook up-front avoids a
 * signature-churn commit later.
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

/**
 * Tagged result for every primitive.  ``applied`` = backend wrote the
 * row synchronously (pending path) and the caller can update local
 * state with ``data``.  ``enqueued`` = the mutator will apply the
 * change asynchronously; the caller must NOT touch local state and
 * should wait for the SSE ``mutation.applied`` refetch to reflect
 * truth.
 */
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
  const { api } = opts;
  // topoStatus / topoVersion intentionally unused this pass — see module
  // docstring. They'll drive the enqueue branch in the next commits.

  return useMemo<UseTopologyEditor>(() => ({
    async createLan(topologyId, body) {
      const data = await api.createLan(topologyId, body);
      return { kind: 'applied', data };
    },
    async updateLan(topologyId, lanId, _lanName, patch) {
      const data = await api.updateLan(topologyId, lanId, patch);
      return { kind: 'applied', data };
    },
    async deleteLan(topologyId, lanId, _lanName) {
      await api.deleteLan(topologyId, lanId);
      return { kind: 'applied', data: undefined };
    },
    async createDecky(topologyId, body) {
      const data = await api.createDecky(topologyId, body);
      return { kind: 'applied', data };
    },
    async updateDecky(topologyId, uuid, _deckyName, patch) {
      const data = await api.updateDecky(topologyId, uuid, patch);
      return { kind: 'applied', data };
    },
    async deleteDecky(topologyId, uuid, _deckyName) {
      await api.deleteDecky(topologyId, uuid);
      return { kind: 'applied', data: undefined };
    },
    async attachEdge(topologyId, body, _deckyName, _lanName) {
      const data = await api.attachEdge(topologyId, body);
      return { kind: 'applied', data };
    },
    async detachEdge(topologyId, edgeId, _deckyName, _lanName) {
      await api.detachEdge(topologyId, edgeId);
      return { kind: 'applied', data: undefined };
    },
  }), [api]);
}

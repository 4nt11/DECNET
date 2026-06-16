// SPDX-License-Identifier: AGPL-3.0-or-later
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
import { useCallback, useEffect, useMemo, useRef } from 'react';
import type {
  CreateDeckyBody,
  CreateLanBody,
  DeckyRow,
  EdgeRow,
  LANRow,
  MazeApi,
  MutationOp,
} from './useMazeApi';

/** Thrown by a live primitive when its mutation settles as ``failed``.
 *  Carries the op + backend reason so the page can surface a loud,
 *  persistent error instead of a transient toast. */
export class MutationFailedError extends Error {
  readonly op: string;
  readonly reason: string;
  constructor(op: string, reason: string) {
    super(`mutation ${op} failed: ${reason}`);
    this.name = 'MutationFailedError';
    this.op = op;
    this.reason = reason;
  }
}

export interface UseTopologyEditorOptions {
  api: MazeApi;
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
  /** Composite: create a decky and attach it to its home LAN. On pending
   *  this is two CRUD calls; on active it's one ``add_decky`` enqueue.
   *  Callers should prefer this over ``createDecky`` + ``attachEdge`` so
   *  the active path doesn't 409 on the CRUD half. */
  addDeckyToLan(
    topologyId: string,
    body: CreateDeckyBody,
    lanId: string,
    lanName: string,
    opts?: { is_bridge?: boolean; forwards_l3?: boolean },
  ): Promise<PrimitiveResult<DeckyRow>>;
  updateDecky(
    topologyId: string,
    uuid: string,
    deckyName: string,
    patch: Partial<DeckyRow>,
    /** Extra top-level flags for the queued mutation payload — currently
     *  only ``force`` (opts in to destructive recreates like the
     *  forwards_l3 flip on a live topology).  Ignored on the pending
     *  CRUD path since pending edits never need force. */
    extras?: { force?: boolean },
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

  // Serialised mutation submission. Two problems this solves, both
  // proven against the live backend:
  //   1. expected_version is bumped at ENQUEUE (not at apply), so two
  //      ops fired back-to-back race: whichever HTTP request the server
  //      sees second carries a stale version and 409s.  We chain submits
  //      so only one enqueue is ever in flight, in submission order.
  //   2. A failed mutation silently degrades the topology.  We await each
  //      mutation to a terminal state and throw MutationFailedError on
  //      'failed' so the caller can surface it loudly.
  const chainRef = useRef<Promise<unknown>>(Promise.resolve());
  // Optimistic expected_version cursor. enqueue bumps the server version
  // by exactly 1, so we advance locally rather than waiting for a refetch
  // between queued ops (onReparent fires detach + attach in one handler).
  const cursorRef = useRef<number>(topoVersion);
  useEffect(() => {
    // Adopt a higher server version (a refetch landed, or another editor
    // advanced it) but never walk the cursor backwards under an in-flight
    // batch that has already advanced past the last-seen server version.
    if (topoVersion > cursorRef.current) cursorRef.current = topoVersion;
  }, [topoVersion]);

  const submit = useCallback(
    (topologyId: string, op: MutationOp, payload: Record<string, unknown>): Promise<string> => {
      const task = chainRef.current.then(async () => {
        const expected = cursorRef.current;
        const res = await api.enqueueMutation(topologyId, op, payload, expected);
        cursorRef.current = expected + 1;
        const row = await api.waitForMutation(topologyId, res.mutation_id);
        if (row.state === 'failed') {
          throw new MutationFailedError(op, row.reason ?? 'unknown reason');
        }
        return res.mutation_id;
      });
      // Keep the chain alive after a rejection so one failed op doesn't
      // wedge every subsequent submit.
      chainRef.current = task.then(() => undefined, () => undefined);
      return task;
    },
    [api],
  );

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
      const mutationId = await submit(topologyId, 'add_lan', payload);
      return { kind: 'enqueued', mutationId };
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
      const mutationId = await submit(topologyId, 'update_lan', payload);
      return { kind: 'enqueued', mutationId };
    },
    async deleteLan(topologyId, lanId, lanName) {
      if (!live) {
        await api.deleteLan(topologyId, lanId);
        return { kind: 'applied', data: undefined };
      }
      const mutationId = await submit(topologyId, 'remove_lan', { name: lanName });
      return { kind: 'enqueued', mutationId };
    },

    // ── Decky ──────────────────────────────────────────────────────────
    async createDecky(topologyId, body) {
      // Bare create — only valid on pending. On active callers should use
      // addDeckyToLan() instead; the backend guard will 409 here.
      const data = await api.createDecky(topologyId, body);
      return { kind: 'applied', data };
    },
    async addDeckyToLan(topologyId, body, lanId, lanName, opts) {
      if (!live) {
        const data = await api.createDecky(topologyId, body);
        await api.attachEdge(topologyId, {
          decky_uuid: data.uuid,
          lan_id: lanId,
          is_bridge: opts?.is_bridge,
          forwards_l3: opts?.forwards_l3,
        });
        return { kind: 'applied', data };
      }
      const payload: Record<string, unknown> = {
        name: body.name,
        lan: lanName,
        services: body.services,
      };
      const cfg = body.decky_config ?? {};
      if (cfg.archetype !== undefined) payload.archetype = cfg.archetype;
      const fwd = opts?.forwards_l3 ?? cfg.forwards_l3;
      if (fwd !== undefined) payload.forwards_l3 = fwd;
      if (body.x !== undefined) payload.x = body.x;
      if (body.y !== undefined) payload.y = body.y;
      const mutationId = await submit(topologyId, 'add_decky', payload);
      return { kind: 'enqueued', mutationId };
    },
    async updateDecky(topologyId, uuid, deckyName, patch, extras) {
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
      if (extras?.force) payload.force = true;
      const mutationId = await submit(topologyId, 'update_decky', payload);
      return { kind: 'enqueued', mutationId };
    },
    async deleteDecky(topologyId, uuid, deckyName) {
      if (!live) {
        await api.deleteDecky(topologyId, uuid);
        return { kind: 'applied', data: undefined };
      }
      const mutationId = await submit(topologyId, 'remove_decky', { decky: deckyName });
      return { kind: 'enqueued', mutationId };
    },

    // ── Edges ──────────────────────────────────────────────────────────
    async attachEdge(topologyId, body, deckyName, lanName) {
      if (!live) {
        const data = await api.attachEdge(topologyId, body);
        return { kind: 'applied', data };
      }
      const payload: Record<string, unknown> = { decky: deckyName, lan: lanName };
      if (body.forwards_l3 !== undefined) payload.forwards_l3 = body.forwards_l3;
      const mutationId = await submit(topologyId, 'attach_decky', payload);
      return { kind: 'enqueued', mutationId };
    },
    async detachEdge(topologyId, edgeId, deckyName, lanName) {
      if (!live) {
        await api.detachEdge(topologyId, edgeId);
        return { kind: 'applied', data: undefined };
      }
      const mutationId = await submit(topologyId, 'detach_decky', { decky: deckyName, lan: lanName });
      return { kind: 'enqueued', mutationId };
    },
  }), [api, live, submit]);
}

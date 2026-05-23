// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from 'react';
import api from '../../utils/api';
import { useIdentityStream } from '../useIdentityStream';
import {
  useAttackerStream,
  type ObservationFrame,
  type AttributionStateChangedFrame,
  type AttributionMultiActorFrame,
} from '../useAttackerStream';
import type {
  AttackerData,
  BehaviouralObservation,
  AttributionPrimitiveState,
  ArtifactLog,
  SessionLog,
  SmtpTargetRow,
  MailLog,
  CommandRow,
} from './types';

export const COMMAND_PAGE_SIZE = 50;

export interface UseAttackerDetailResult {
  attacker: AttackerData | null;
  observations: BehaviouralObservation[];
  attribution: Map<string, AttributionPrimitiveState>;
  loading: boolean;
  error: string | null;

  // Commands paging
  commands: CommandRow[];
  cmdTotal: number;
  cmdPage: number;
  setCmdPage: (n: number) => void;
  serviceFilter: string | null;
  setServiceFilter: (s: string | null) => void;
  cmdLimit: number;

  // Auxiliary feeds
  artifacts: ArtifactLog[];
  smtpTargets: SmtpTargetRow[];
  mail: MailLog[];
  mailForbidden: boolean;
  sessions: SessionLog[];
}

interface ApiErrorLike {
  response?: { status?: number };
}

const isApiError = (e: unknown): e is ApiErrorLike =>
  typeof e === 'object' && e !== null && 'response' in e;

/** Owns every read-side data flow for the AttackerDetail page —
 *  REST fetches plus the per-attacker and per-identity SSE streams.
 *  Section components consume the returned values; none of them
 *  open their own connections. */
export function useAttackerDetail(id: string | undefined): UseAttackerDetailResult {
  const [attacker, setAttacker] = useState<AttackerData | null>(null);
  const [observations, setObservations] = useState<BehaviouralObservation[]>([]);
  const [attribution, setAttribution] = useState<Map<string, AttributionPrimitiveState>>(
    () => new Map(),
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [serviceFilter, setServiceFilter] = useState<string | null>(null);
  const [commands, setCommands] = useState<CommandRow[]>([]);
  const [cmdTotal, setCmdTotal] = useState(0);
  const [cmdPage, setCmdPage] = useState(1);
  const cmdLimit = COMMAND_PAGE_SIZE;

  const [artifacts, setArtifacts] = useState<ArtifactLog[]>([]);
  const [smtpTargets, setSmtpTargets] = useState<SmtpTargetRow[]>([]);
  const [mail, setMail] = useState<MailLog[]>([]);
  const [mailForbidden, setMailForbidden] = useState(false);
  const [sessions, setSessions] = useState<SessionLog[]>([]);

  // Primary attacker fetch.
  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    setLoading(true);
    (async () => {
      try {
        const res = await api.get(`/attackers/${id}`);
        if (cancelled) return;
        setAttacker(res.data);
        setObservations(res.data?.observations ?? []);
        setError(null);
      } catch (err: unknown) {
        if (cancelled) return;
        if (isApiError(err) && err.response?.status === 404) {
          setError('ATTACKER NOT FOUND');
        } else {
          setError('FAILED TO LOAD ATTACKER PROFILE');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [id]);

  // Attribution table; tolerated 404/network failure (worker may be off).
  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    (async () => {
      try {
        const res = await api.get(`/attackers/${id}/attribution`);
        if (cancelled) return;
        const next = new Map<string, AttributionPrimitiveState>();
        const primitives = (res.data?.primitives ?? []) as AttributionPrimitiveState[];
        for (const row of primitives) next.set(row.primitive, row);
        setAttribution(next);
      } catch {
        // optional endpoint
      }
    })();
    return () => { cancelled = true; };
  }, [id]);

  // Identity-event refresh: re-fetch attacker row when an identity
  // event references either this attacker uuid or its bound identity.
  useIdentityStream({
    enabled: !!id,
    onEvent: (ev) => {
      if (!id) return;
      const payload = ev.payload || {};
      const refs = new Set<string>();
      const addUuid = (v: unknown) => {
        if (typeof v === 'string') refs.add(v);
      };
      addUuid(payload.observation_uuid);
      const obsList = payload.observation_uuids;
      if (Array.isArray(obsList)) obsList.forEach(addUuid);
      addUuid(payload.identity_uuid);
      addUuid(payload.winner_uuid);
      addUuid(payload.loser_uuid);
      addUuid(payload.resurrected_uuid);
      addUuid(payload.former_winner_uuid);

      const myIdentity = attacker?.identity_id;
      if (refs.has(id) || (myIdentity && refs.has(myIdentity))) {
        api.get(`/attackers/${id}`)
          .then((res) => setAttacker(res.data))
          .catch(() => {});
      }
    },
  });

  // Per-attacker live behaviour + attribution updates.
  useAttackerStream({
    attackerUuid: id ?? '',
    enabled: !!id,
    onSnapshot: (data) => {
      setObservations(data.observations ?? []);
    },
    onObservation: (frame: ObservationFrame) => {
      setObservations((prev) => {
        const filtered = prev.filter((o) => o.primitive !== frame.primitive);
        return [
          ...filtered,
          {
            primitive: frame.primitive,
            value: frame.value,
            confidence: frame.confidence,
            ts: frame.ts,
            source: frame.source,
          },
        ];
      });
    },
    onAttributionStateChanged: (frame: AttributionStateChangedFrame) => {
      setAttribution((prev) => {
        const next = new Map(prev);
        const prior = next.get(frame.primitive);
        next.set(frame.primitive, {
          primitive: frame.primitive,
          current_value: frame.current_value,
          state: frame.new_state,
          confidence: frame.confidence,
          observation_count: frame.observation_count,
          last_change_ts: frame.ts,
          last_observation_ts: frame.ts,
          ...(prior && prior.state === frame.new_state
            ? { last_change_ts: prior.last_change_ts }
            : {}),
        });
        return next;
      });
    },
    onMultiActorSuspected: (_frame: AttributionMultiActorFrame) => {
      // Cross-primitive escalation is a SIEM-channel signal.
      // Listener is wired so a future banner has a live source.
    },
  });

  // Paged command list — re-fetches on page or filter change.
  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    (async () => {
      try {
        const offset = (cmdPage - 1) * cmdLimit;
        let url = `/attackers/${id}/commands?limit=${cmdLimit}&offset=${offset}`;
        if (serviceFilter) url += `&service=${encodeURIComponent(serviceFilter)}`;
        const res = await api.get(url);
        if (cancelled) return;
        setCommands(res.data.data);
        setCmdTotal(res.data.total);
      } catch (err: unknown) {
        if (cancelled) return;
        if (isApiError(err) && err.response?.status === 422) {
          // Backend gate hit a malformed filter; surface loudly so a
          // user typo (e.g. unknown service) is visible immediately.
          alert('Fuck off.');
        }
        setCommands([]);
        setCmdTotal(0);
      }
    })();
    return () => { cancelled = true; };
  }, [id, cmdPage, serviceFilter, cmdLimit]);

  // Reset to page 1 whenever filter flips.
  useEffect(() => {
    setCmdPage(1);
  }, [serviceFilter]);

  // Static auxiliary feeds — single-shot per id.
  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    (async () => {
      try {
        const res = await api.get(`/attackers/${id}/artifacts`);
        if (!cancelled) setArtifacts(res.data.data ?? []);
      } catch {
        if (!cancelled) setArtifacts([]);
      }
    })();
    return () => { cancelled = true; };
  }, [id]);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    (async () => {
      try {
        const res = await api.get(`/attackers/${id}/smtp-targets`);
        if (!cancelled) setSmtpTargets(res.data.data ?? []);
      } catch {
        if (!cancelled) setSmtpTargets([]);
      }
    })();
    return () => { cancelled = true; };
  }, [id]);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    (async () => {
      try {
        const res = await api.get(`/attackers/${id}/mail`);
        if (cancelled) return;
        setMail(res.data.data ?? []);
        setMailForbidden(false);
      } catch (err: unknown) {
        if (cancelled) return;
        setMail([]);
        setMailForbidden(isApiError(err) && err.response?.status === 403);
      }
    })();
    return () => { cancelled = true; };
  }, [id]);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    (async () => {
      try {
        const res = await api.get(`/attackers/${id}/transcripts`);
        if (!cancelled) setSessions(res.data.data ?? []);
      } catch {
        if (!cancelled) setSessions([]);
      }
    })();
    return () => { cancelled = true; };
  }, [id]);

  return {
    attacker,
    observations,
    attribution,
    loading,
    error,
    commands,
    cmdTotal,
    cmdPage,
    setCmdPage,
    serviceFilter,
    setServiceFilter,
    cmdLimit,
    artifacts,
    smtpTargets,
    mail,
    mailForbidden,
    sessions,
  };
}

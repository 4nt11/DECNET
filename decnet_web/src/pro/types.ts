// SPDX-License-Identifier: AGPL-3.0-or-later
// Contract for Professional-tier UI pages. The pro build aliases `@pro` to the
// real registry in decnet/pro/web/; the community build resolves it to ./stub.
import type { ComponentType, ReactElement, ReactNode } from 'react';

export interface ProRoute {
  /** Router path, e.g. "/pro/intel". Convention: prefix pro routes with /pro. */
  path: string;
  /** Sidebar label. */
  label: string;
  /** Sidebar icon (lucide-react element), optional. */
  icon?: ReactNode;
  /** Page element rendered at `path`. May be a lazy component (App wraps Suspense). */
  element: ReactElement;
}

/** Created-topology summary handed back to the wizard. Mirrors the wizard's own
 *  TopologySummary (and GET /topologies rows) structurally so the wizard's
 *  onCreated handler is assignable without a cross-tree type import. */
export interface ProTopologySummary {
  id: string;
  name: string;
  mode: string;
  target_host_uuid: string | null;
  status: string;
  version: number;
  needs_resync?: boolean;
  created_at: string;
  status_changed_at: string | null;
}

/** Props the CreateTopologyWizard passes to the pro scan-import panel. The pro
 *  build owns the entire scan→topology flow (file pick, parse, preview, create)
 *  and signals completion through `onCreated`; the community build never sees
 *  this surface. Kept structural — the pro tree implements the shape without
 *  importing it, mirroring how `ProRoute` crosses the trust boundary. */
export interface ProScanImportProps {
  /** "unihost" | "agent" — chosen in the wizard's TARGET step. */
  mode: string;
  /** Agent host UUID, or null for local. */
  targetHostUuid: string | null;
  /** Fires with the created topology summary; the wizard closes and navigates. */
  onCreated: (row: ProTopologySummary) => void;
}

/** `null` in the community build (no scan import); a component in the pro build. */
export type ProScanImport = ComponentType<ProScanImportProps> | null;

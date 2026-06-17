// SPDX-License-Identifier: AGPL-3.0-or-later
// Contract for Professional-tier UI pages. The pro build aliases `@pro` to the
// real registry in decnet/pro/web/; the community build resolves it to ./stub.
import type { ReactElement, ReactNode } from 'react';

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

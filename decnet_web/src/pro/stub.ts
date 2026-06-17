// SPDX-License-Identifier: AGPL-3.0-or-later
// Community build: no Professional pages. `@pro` resolves here unless the build
// sets VITE_DECNET_PRO=1 with decnet/pro/web/ present, in which case Vite
// aliases `@pro` to the real registry. proRoutes being empty lets the router
// and nav tree-shake the pro surface out of the community bundle.
import type { ProRoute } from './types';

export const proRoutes: ProRoute[] = [];

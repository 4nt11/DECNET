// SPDX-License-Identifier: AGPL-3.0-or-later
import { proRoutes } from '@pro';

// In the community build, `@pro` resolves to the stub: no Professional pages,
// so App's route map and Layout's nav group both tree-shake to nothing.
describe('pro tier — community build', () => {
  it('ships no pro routes', () => {
    expect(proRoutes).toEqual([]);
  });
});

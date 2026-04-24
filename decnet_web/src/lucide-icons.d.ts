/* Ambient typings for lucide-react's per-icon module paths.
 *
 * lucide-react ships .d.ts only for the barrel entry point; the
 * per-icon files (dist/esm/icons/<name>.js) have no sibling .d.ts.
 * We import each icon from its own file to keep the dep-optimiser
 * from pre-bundling the whole barrel, so the compiler needs a
 * declaration that covers the wildcard path.
 *
 * Every icon exposes the same default-exported component shape,
 * so one module wildcard is enough. */

declare module 'lucide-react/dist/esm/icons/*' {
  import type { LucideIcon } from 'lucide-react';
  const icon: LucideIcon;
  export default icon;
}

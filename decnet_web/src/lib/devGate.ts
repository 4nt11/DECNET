/* Dev-only feature gate.
 *
 * Reads VITE_DECNET_DEVELOPER at build time. Vite inlines the value
 * at compile, so a prod build with the flag unset becomes a constant
 * `false` and the route guard plus its lazy import are tree-shaken
 * out of the bundle entirely.
 *
 * Set in .env.development:  VITE_DECNET_DEVELOPER=1
 */
export function isDeveloperMode(): boolean {
  return import.meta.env.VITE_DECNET_DEVELOPER === '1';
}

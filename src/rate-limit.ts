/** Per-IP browser rate limits: one IP cannot burn a route's shared budget.
 *
 * Limits are per rolling minute window, keyed by route + hashed IP + endpoint.
 * Raw IPs are never stored; only their route-scoped SHA-256 is persisted.
 * Session mints are rare (one per 30-minute visitor session plus 10-minute
 * refreshes), so the mint budget is tight; echo carries live chat volume.
 * WebSocket upgrades are rarer still (one per page session, then frames ride
 * the socket), so they share the tight mint budget.
 */
export const BROWSER_IP_LIMITS = {'/session': 20, '/echo': 120, '/sync': 120, '/ws': 20} as const;

/** Minute bucket for a timestamp. */
export function rateMinute(now: number): number {
  return Math.floor(now / 60000);
}

/** Per-IP limit for a browser endpoint, or null when the endpoint is unknown. */
export function ipLimitForEndpoint(path: string): number | null {
  if (path === '/session') return BROWSER_IP_LIMITS['/session'];
  if (path === '/echo') return BROWSER_IP_LIMITS['/echo'];
  if (path === '/sync') return BROWSER_IP_LIMITS['/sync'];
  if (path === '/ws') return BROWSER_IP_LIMITS['/ws'];
  return null;
}

/** Normalize CF-Connecting-IP into a bucketable value. Returns null when the
 * header is absent or unusable, in which case the caller falls back to the
 * shared route budget instead of blocking. */
export function normalizeClientIp(value: string | null): string | null {
  if (typeof value !== 'string') return null;
  const ip = value.trim();
  if (!ip || ip.length > 64) return null;
  return ip;
}

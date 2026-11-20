import {describe, expect, it} from 'bun:test';
import {BROWSER_IP_LIMITS, ipLimitForEndpoint, normalizeClientIp, rateMinute} from './rate-limit';

describe('browser per-ip rate limits', () => {
  it('splits session mint and echo budgets', () => {
    expect(ipLimitForEndpoint('/session')).toBe(BROWSER_IP_LIMITS['/session']);
    expect(ipLimitForEndpoint('/echo')).toBe(BROWSER_IP_LIMITS['/echo']);
    expect(BROWSER_IP_LIMITS['/session']).toBeLessThan(BROWSER_IP_LIMITS['/echo']);
  });
  it('gates websocket upgrades tightly like session mints', () => {
    expect(ipLimitForEndpoint('/ws')).toBe(BROWSER_IP_LIMITS['/ws']);
    expect(BROWSER_IP_LIMITS['/ws']).toBe(BROWSER_IP_LIMITS['/session']);
  });
  it('rejects unknown endpoints', () => {
    expect(ipLimitForEndpoint('/admin')).toBeNull();
    expect(ipLimitForEndpoint('')).toBeNull();
  });
  it('buckets whole minutes', () => {
    expect(rateMinute(60000)).toBe(1);
    expect(rateMinute(119999)).toBe(1);
    expect(rateMinute(120000)).toBe(2);
  });
  it('normalizes client ips and fails open on garbage', () => {
    expect(normalizeClientIp('203.0.113.7')).toBe('203.0.113.7');
    expect(normalizeClientIp('  2001:db8::1  ')).toBe('2001:db8::1');
    expect(normalizeClientIp(null)).toBeNull();
    expect(normalizeClientIp('')).toBeNull();
    expect(normalizeClientIp('   ')).toBeNull();
    expect(normalizeClientIp('x'.repeat(65))).toBeNull();
  });
});

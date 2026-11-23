import { describe, expect, it } from 'vitest';
import { canResolveSos, isActiveSos, sosCreatedAt, sosMapUrl } from './sosAlerts.js';

describe('SOS API contract', () => {
  it('uses backend lifecycle states for manager actions', () => {
    expect(isActiveSos({ status: 'active' })).toBe(true);
    expect(isActiveSos({ status: 'triggered' })).toBe(false);
    expect(canResolveSos({ status: 'active' })).toBe(true);
    expect(canResolveSos({ status: 'acknowledged' })).toBe(true);
    expect(canResolveSos({ status: 'resolved' })).toBe(false);
  });

  it('uses the backend creation timestamp', () => {
    expect(sosCreatedAt({ created_at: '2026-11-23T10:00:00Z' })).toBe('2026-11-23T10:00:00Z');
    expect(sosCreatedAt({ triggered_at: 'legacy' })).toBeNull();
  });

  it('only creates a map link for real coordinates', () => {
    expect(sosMapUrl({ latitude: 43.65, longitude: -79.38 })).toBe('https://maps.google.com/?q=43.65,-79.38');
    expect(sosMapUrl({ latitude: null, longitude: null })).toBeNull();
    expect(sosMapUrl({ latitude: 43.65, longitude: null })).toBeNull();
  });
});

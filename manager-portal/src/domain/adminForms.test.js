import { describe, expect, it } from 'vitest';
import { announcementPayload, openShiftPayload, sitePayload } from './adminForms.js';

describe('manager form API contracts', () => {
  it('maps site geofence fields to the backend contract', () => {
    expect(sitePayload({
      name: 'HQ', address: '1 Main St', latitude: '43.1', longitude: '-79.2',
      geofence_radius_m: '250', client_name: '', city: '',
    })).toMatchObject({ latitude: 43.1, longitude: -79.2, geofence_radius_m: 250 });
  });

  it('preserves the backend open-shift capacity field', () => {
    const payload = openShiftPayload({ pay_rate: '27.50', spots_available: '3', urgent: true });
    expect(payload).toMatchObject({ pay_rate: 27.5, spots_available: 3, urgent: true });
    expect(payload).not.toHaveProperty('slots');
  });

  it('uses severity and omits an empty announcement target', () => {
    const payload = announcementPayload({ title: 'Notice', body: 'Message', severity: 'critical', site_id: '' });
    expect(payload.severity).toBe('critical');
    expect(payload.site_id).toBeUndefined();
    expect(payload).not.toHaveProperty('priority');
  });
});

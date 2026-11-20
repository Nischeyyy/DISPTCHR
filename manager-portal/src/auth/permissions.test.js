import { describe, expect, it } from 'vitest';
import { firstAllowedManagerPath, hasManagerPermission, MANAGER_PERMISSIONS } from './permissions.js';

describe('manager access controls', () => {
  it('fails closed when permissions are absent or malformed', () => {
    expect(hasManagerPermission({}, MANAGER_PERMISSIONS.dashboard)).toBe(false);
    expect(hasManagerPermission({ manager_permissions: null }, MANAGER_PERMISSIONS.dashboard)).toBe(false);
    expect(hasManagerPermission({ manager_permissions: 'dashboard.view' }, MANAGER_PERMISSIONS.dashboard)).toBe(false);
  });

  it('grants only explicitly assigned permissions', () => {
    const user = { manager_permissions: [MANAGER_PERMISSIONS.payroll] };
    expect(hasManagerPermission(user, MANAGER_PERMISSIONS.payroll)).toBe(true);
    expect(hasManagerPermission(user, MANAGER_PERMISSIONS.guards)).toBe(false);
    expect(firstAllowedManagerPath(user)).toBe('/payroll');
  });

  it('keeps a no-access manager on the dashboard boundary', () => {
    expect(firstAllowedManagerPath({ manager_permissions: [] })).toBe('/dashboard');
  });
});

export const MANAGER_PERMISSIONS = {
  dashboard: 'dashboard.view',
  sos: 'sos.manage',
  live: 'locations.view',
  guards: 'guards.manage',
  sites: 'sites.manage',
  shifts: 'scheduling.manage',
  'open-shifts': 'scheduling.manage',
  swaps: 'scheduling.manage',
  timeclock: 'timeclock.manage',
  incidents: 'incidents.manage',
  payroll: 'payroll.manage',
  announcements: 'announcements.manage',
  compliance: 'compliance.view',
};

export function hasManagerPermission(user, permission) {
  const assigned = user?.manager_permissions;
  // Existing manager records created before access controls retain their current
  // access until a director saves an explicit permission set.
  return !Array.isArray(assigned) || assigned.includes(permission);
}

export function firstAllowedManagerPath(user) {
  const firstEntry = Object.entries(MANAGER_PERMISSIONS).find(([, permission]) =>
    hasManagerPermission(user, permission)
  );
  return firstEntry ? `/${firstEntry[0]}` : '/dashboard';
}

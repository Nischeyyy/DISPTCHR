export function isActiveSos(alert) {
  return alert?.status === 'active';
}

export function canResolveSos(alert) {
  return alert?.status === 'active' || alert?.status === 'acknowledged';
}

export function sosCreatedAt(alert) {
  return alert?.created_at || null;
}

export function sosMapUrl(alert) {
  if (!Number.isFinite(alert?.latitude) || !Number.isFinite(alert?.longitude)) return null;
  return `https://maps.google.com/?q=${alert.latitude},${alert.longitude}`;
}

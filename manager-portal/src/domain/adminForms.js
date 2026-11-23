export function sitePayload(form) {
  return {
    ...form,
    latitude: Number(form.latitude),
    longitude: Number(form.longitude),
    geofence_radius_m: Number(form.geofence_radius_m),
    client_name: form.client_name || undefined,
    city: form.city || undefined,
  };
}

export function openShiftPayload(form) {
  return {
    ...form,
    pay_rate: form.pay_rate ? Number(form.pay_rate) : undefined,
    spots_available: Number(form.spots_available),
  };
}

export function announcementPayload(form) {
  return { ...form, site_id: form.site_id || undefined };
}

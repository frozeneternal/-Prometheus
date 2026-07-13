export function resourceAckDays(config) {
  const raw = Number(config?.monitoring?.resourceAckMaxDays || 7);
  const maxDays = Number.isFinite(raw) ? Math.floor(raw) : 7;
  return Math.max(1, Math.min(7, maxDays));
}

export function resourceAckLabel(config) {
  return `确认 ${resourceAckDays(config)} 天`;
}

export function resourceAcknowledgedUntil(config, now = Date.now()) {
  return new Date(now + resourceAckDays(config) * 86400 * 1000).toISOString();
}

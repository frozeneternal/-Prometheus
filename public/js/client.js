import { getJson } from "./api.js";

const JSON_HEADERS = { "Content-Type": "application/json" };

function postJson(url, body) {
  return getJson(url, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  });
}

export function fetchConfig() {
  return getJson("/api/config");
}

export function fetchDashboard() {
  return getJson("/api/dashboard");
}

export function fetchMetricSeries({ serverId, metric, minutes = 60 }) {
  const params = new URLSearchParams({
    serverId,
    metric,
    minutes: String(minutes),
  });
  return getJson(`/api/series?${params.toString()}`);
}

export function fetchSession(sessionToken) {
  return postJson("/api/auth/session", { sessionToken });
}

export function loginUser({ username, password }) {
  return postJson("/api/auth/login", { username, password });
}

export function logoutSession(sessionToken) {
  return postJson("/api/auth/logout", { sessionToken });
}

export function fetchAccountLockouts(sessionToken) {
  return postJson("/api/auth/lockouts", { sessionToken });
}

export function fetchAccountAudit(sessionToken) {
  return postJson("/api/auth/audit", { sessionToken });
}

export function unlockAccount({ username, auth }) {
  return postJson("/api/auth/unlock", { username, ...auth });
}

export function updateAutoRecovery({ targetType, targetId, enabled, auth }) {
  return postJson("/api/settings/auto-recovery", { targetType, targetId, enabled, ...auth });
}

export function updateAutoBackup({ serverId, enabled, auth }) {
  return postJson("/api/settings/auto-backup", { serverId, enabled, ...auth });
}

export function updateCertRenewal({ websiteId, enabled, auth }) {
  return postJson("/api/settings/cert-renewal", { websiteId, enabled, ...auth });
}

export function acknowledgeResourceExpiryRisk({ resourceId, acknowledgedUntil, auth }) {
  return postJson("/api/settings/resource-ack", { resourceId, acknowledgedUntil, ...auth });
}

export function runServerAction(payload) {
  return postJson("/api/actions/run", payload);
}

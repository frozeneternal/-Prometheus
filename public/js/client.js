import { getJson } from "./api.js";

const JSON_HEADERS = { "Content-Type": "application/json" };

function postJson(url, body, headers = {}) {
  return getJson(url, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...headers },
    body: JSON.stringify(body),
  });
}

export function fetchConfig() {
  return getJson("/api/config");
}

export function fetchDashboard() {
  return getJson("/api/dashboard");
}

export function fetchResourceDetails(headers) {
  return getJson("/api/resources", { headers });
}

export function fetchPrometheusAlerts() {
  return getJson("/api/prometheus/alerts");
}

export function fetchPrometheusRules() {
  return getJson("/api/prometheus/rules");
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

export function changeOwnPassword({ sessionToken, currentPassword, newPassword }) {
  return postJson("/api/auth/password", { sessionToken, currentPassword, newPassword });
}

export function fetchAccountLockouts(sessionToken) {
  return postJson("/api/auth/lockouts", { sessionToken });
}

export function fetchAccountAudit(sessionToken, { limit = 50, offset = 0 } = {}) {
  return postJson("/api/auth/audit", { sessionToken, limit, offset });
}

export function fetchAccountUsers(sessionToken) {
  return postJson("/api/auth/users", { sessionToken });
}

export function saveAccountUser({ user, auth }) {
  return postJson("/api/auth/users/upsert", { ...user, ...auth });
}

export function removeAccountUser({ username, auth }) {
  return postJson("/api/auth/users/delete", { username, ...auth });
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

export function acknowledgeResourceExpiryRisk({ resourceId, acknowledgedUntil, headers }) {
  return postJson("/api/settings/resource-ack", { resourceId, acknowledgedUntil }, headers);
}

export function upsertResourceExpiryRecord({ resource, headers }) {
  return postJson("/api/settings/resource-upsert", { resource }, headers);
}

export function removeResourceExpiryRecord({ resourceId, headers }) {
  return postJson("/api/settings/resource-delete", { resourceId }, headers);
}

export function runServerAction(payload) {
  return postJson("/api/actions/run", payload);
}

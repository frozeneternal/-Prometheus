import { authPayload } from "./accounts.js";
import {
  acknowledgeResourceExpiryRisk,
  removeResourceExpiryRecord,
  runServerAction,
  upsertResourceExpiryRecord,
  updateAutoBackup,
  updateAutoRecovery,
  updateCertRenewal,
} from "./client.js";
import { $ } from "./dom.js";
import { purgeResourceDetails, resourceAuthHeaders } from "./resource-access.js";
import { resourceAcknowledgedUntil } from "./resource-expiry.js";
import { state } from "./state.js";

const runtime = {
  loadConfig: async () => {},
  refreshDashboard: async () => {},
  render: () => {},
};

export function configureActionRuntime(dependencies) {
  Object.assign(runtime, dependencies);
}

export function openActionDialog(serverId, actionId, meta = {}) {
  const server = state.config.servers.find((item) => item.id === serverId);
  const action = server.actions.find((item) => item.id === actionId);
  state.currentAction = { server, action, meta };

  $("#dialogTitle").textContent = meta.dialogTitle || action.name || action.id;
  $("#dialogMeta").textContent = meta.dialogMeta || server.name || server.id;
  $("#confirmInput").value = "";
  $("#confirmWrap").classList.toggle("hidden", !action.confirm);
  $("#confirmInput").placeholder = action.confirm || "";
  $("#actionOutput").classList.add("hidden");
  $("#actionOutput").textContent = "";
  $("#actionDialog").showModal();
}

export function openManualRecoveryDialog(targetType, targetId) {
  if (targetType === "server") {
    const server = state.config.servers.find((item) => item.id === targetId);
    const manualRecovery = server?.manualRecovery;
    if (!server || !manualRecovery?.available) return;
    openActionDialog(manualRecovery.actionServerId, manualRecovery.actionId, {
      targetType: "server",
      targetId: server.id,
      targetName: server.name || server.id,
      invocation: "manual-recovery",
      reason: "手动恢复",
    });
    return;
  }

  if (targetType === "website") {
    const website = state.config.websites.find((item) => item.id === targetId);
    const manualRecovery = website?.manualRecovery;
    if (!website || !manualRecovery?.available) return;
    openActionDialog(manualRecovery.actionServerId, manualRecovery.actionId, {
      targetType: "website",
      targetId: website.id,
      targetName: website.name || website.id,
      invocation: "manual-recovery",
      reason: "手动恢复网站",
      dialogMeta: website.name || website.id,
    });
  }
}

export function openManualCertRenewalDialog(websiteId) {
  const website = state.config.websites.find((item) => item.id === websiteId);
  const manualCertRenewal = website?.manualCertRenewal;
  if (!website || !manualCertRenewal?.available) return;
  openActionDialog(manualCertRenewal.actionServerId, manualCertRenewal.actionId, {
    targetType: "website-cert",
    targetId: website.id,
    targetName: `${website.name || website.id} 证书`,
    invocation: "manual-cert",
    reason: "手动续期",
    dialogTitle: manualCertRenewal.label || "手动续期",
    dialogMeta: website.name || website.id,
  });
}

export function openManualBackupDialog(serverId) {
  const server = state.config.servers.find((item) => item.id === serverId);
  const manualBackup = server?.manualBackup;
  if (!server || !manualBackup?.available) return;
  openActionDialog(manualBackup.actionServerId, manualBackup.actionId, {
    targetType: "server-backup",
    targetId: server.id,
    targetName: `${server.name || server.id} 备份`,
    invocation: "manual-backup",
    reason: "手动备份",
    dialogTitle: manualBackup.label || "立即备份",
    dialogMeta: server.name || server.id,
  });
}

export async function toggleAutoRecovery(targetType, targetId, enabled) {
  try {
    const payload = await updateAutoRecovery({ targetType, targetId, enabled, auth: authPayload() });
    state.dashboard = payload;
    state.dashboard.ok = true;
    await runtime.loadConfig();
    runtime.render();
  } catch (error) {
    await runtime.refreshDashboard();
  }
}

export async function toggleAutoBackup(serverId, enabled) {
  try {
    const payload = await updateAutoBackup({ serverId, enabled, auth: authPayload() });
    state.dashboard = payload;
    state.dashboard.ok = true;
    await runtime.loadConfig();
    runtime.render();
  } catch (error) {
    await runtime.refreshDashboard();
  }
}

export async function toggleCertRenewal(websiteId, enabled) {
  try {
    const payload = await updateCertRenewal({ websiteId, enabled, auth: authPayload() });
    state.dashboard = payload;
    state.dashboard.ok = true;
    await runtime.loadConfig();
    runtime.render();
  } catch (error) {
    await runtime.refreshDashboard();
  }
}

export async function acknowledgeResourceExpiry(resourceId) {
  const acknowledgedUntil = resourceAcknowledgedUntil(state.config);
  try {
    await acknowledgeResourceExpiryRisk({
      resourceId,
      acknowledgedUntil,
      headers: resourceAuthHeaders(),
    });
    await runtime.refreshDashboard();
  } catch (error) {
    if ([401, 403].includes(error.status)) purgeResourceDetails(error.message);
    await runtime.refreshDashboard();
  }
}

export async function saveResourceExpiryRecord(resource) {
  try {
    const payload = await upsertResourceExpiryRecord({
      resource,
      headers: resourceAuthHeaders(),
    });
    await runtime.refreshDashboard();
    return payload;
  } catch (error) {
    if ([401, 403].includes(error.status)) purgeResourceDetails(error.message);
    await runtime.refreshDashboard();
    throw error;
  }
}

export async function deleteResourceExpiryRecord(resourceId) {
  if (!resourceId || !window.confirm("确认删除这条资源到期记录？")) return null;
  try {
    const payload = await removeResourceExpiryRecord({
      resourceId,
      headers: resourceAuthHeaders(),
    });
    await runtime.refreshDashboard();
    return payload;
  } catch (error) {
    if ([401, 403].includes(error.status)) purgeResourceDetails(error.message);
    await runtime.refreshDashboard();
    throw error;
  }
}

export async function runCurrentAction() {
  const { server, action, meta = {} } = state.currentAction;
  const button = $("#runActionButton");
  button.disabled = true;
  button.textContent = "执行中";
  try {
    const payload = await runServerAction({
      serverId: server.id,
      actionId: action.id,
      ...authPayload(),
      confirm: $("#confirmInput").value,
      targetType: meta.targetType || "server",
      targetId: meta.targetId || server.id,
      targetName: meta.targetName || server.name || server.id,
      invocation: meta.invocation || "manual",
      reason: meta.reason || "手动执行",
    });
    const output = actionOutput(payload);
    $("#actionOutput").textContent = output;
    $("#actionOutput").classList.remove("hidden");
  } catch (error) {
    const output = actionOutput(error.payload || {}, error.message);
    $("#actionOutput").textContent = output || error.message;
    $("#actionOutput").classList.remove("hidden");
  } finally {
    await runtime.refreshDashboard();
    button.disabled = false;
    button.textContent = "执行";
  }
}

function actionOutput(payload, fallbackMessage = "") {
  return [
    payload.message || fallbackMessage,
    payload.logId ? `日志ID: ${payload.logId}` : "",
    `退出码: ${payload.returnCode ?? "-"}`,
    `耗时: ${payload.durationSeconds ?? "-"}s`,
    "",
    payload.stdout ? `STDOUT\n${payload.stdout}` : "",
    payload.stderr ? `STDERR\n${payload.stderr}` : "",
  ].filter(Boolean).join("\n");
}

import { $, escapeHtml } from "./dom.js";

const readinessStatuses = ["ready", "attention", "blocked"];
const readinessAreaOrder = [
  "resources",
  "certificates",
  "accounts",
  "backups",
  "recovery",
  "collection",
  "platform",
  "emergency",
];
const statusLabels = {
  ready: "已就绪",
  attention: "需关注",
  blocked: "有阻断",
};
const statusRanks = {
  ready: 0,
  attention: 1,
  blocked: 2,
};
const countDefinitions = [
  ["ready", "已就绪"],
  ["attention", "需关注"],
  ["blocked", "阻断"],
];

function safeReadinessStatus(value, fallback = "blocked") {
  return readinessStatuses.includes(value) ? value : fallback;
}

function isValidCount(value) {
  return Number.isFinite(value) && value >= 0 && Number.isInteger(value);
}

function renderCounts(counts) {
  $("#platformReadinessCounts").innerHTML = countDefinitions
    .map(([key, label]) => `<span class="${key}"><b>${counts[key]}</b>${label}</span>`)
    .join("");
}

export function isConsistentReadiness(readiness) {
  if (!readiness
      || !Array.isArray(readiness.areas)
      || !Array.isArray(readiness.actions)
      || readiness.areas.length !== readinessAreaOrder.length) {
    return false;
  }

  const actions = readiness.actions;
  const computedCounts = { ready: 0, attention: 0, blocked: 0 };
  const expectedActions = [];
  let overallStatus = "ready";

  for (let index = 0; index < readinessAreaOrder.length; index += 1) {
    const area = readiness.areas[index];
    if (!area || typeof area !== "object") {
      return false;
    }
    if (area.id !== readinessAreaOrder[index] || !readinessStatuses.includes(area.status)) {
      return false;
    }

    computedCounts[area.status] += 1;
    if (statusRanks[area.status] > statusRanks[overallStatus]) {
      overallStatus = area.status;
    }
    if (area.status !== "ready") {
      expectedActions.push(area);
    }
  }

  if (!readiness.counts || typeof readiness.counts !== "object") {
    return false;
  }
  for (const status of readinessStatuses) {
    const value = readiness.counts[status];
    if (!isValidCount(value) || value !== computedCounts[status]) {
      return false;
    }
  }
  if (readiness.status !== overallStatus) {
    return false;
  }
  if (!isValidCount(readiness.actionRequired)
      || readiness.actionRequired !== expectedActions.length
      || actions.length !== expectedActions.length) {
    return false;
  }

  for (let index = 0; index < expectedActions.length; index += 1) {
    const action = actions[index];
    const area = expectedActions[index];
    if (!action || typeof action !== "object"
        || action.area !== area.id
        || action.status !== area.status) {
      return false;
    }
  }

  return true;
}

function renderIncompleteReadiness(panel) {
  panel.className = "platform-readiness-panel blocked";
  $("#platformReadinessStatus").className = "platform-readiness-status blocked";
  $("#platformReadinessStatus").textContent = statusLabels.blocked;
  $("#platformReadinessSummary").textContent = "平台就绪度数据不完整，不能据此启用自动化。";
  renderCounts({ ready: 0, attention: 0, blocked: 0 });
  $("#platformReadinessActions").innerHTML = `
    <li class="blocked">
      <span class="platform-readiness-action-status blocked">${statusLabels.blocked}</span>
      <strong>就绪度数据校验失败</strong>
      <span>请刷新数据并检查平台就绪度接口。</span>
    </li>
  `;
}

export function renderPlatformReadiness(readiness) {
  const panel = $("#platformReadinessPanel");
  if (!isConsistentReadiness(readiness)) {
    renderIncompleteReadiness(panel);
    return;
  }

  const actions = readiness.actions;
  const status = safeReadinessStatus(readiness.status);
  panel.className = `platform-readiness-panel ${status}`;
  $("#platformReadinessStatus").className = `platform-readiness-status ${status}`;
  $("#platformReadinessStatus").textContent = statusLabels[status];
  $("#platformReadinessSummary").textContent = status === "ready"
    ? "平台就绪度：八个运维领域均已满足当前就绪条件。"
    : `平台就绪度：${readiness.actionRequired} 个领域需要处理，先解除阻断项再启用自动化。`;
  renderCounts(readiness.counts);

  if (status === "ready") {
    $("#platformReadinessActions").innerHTML = '<li class="ready"><strong>当前无待办</strong><span>继续保持配置、采集和备份验证。</span></li>';
    return;
  }

  const actionItems = [];
  for (const action of actions) {
    const item = action;
    const actionStatus = safeReadinessStatus(item.status);
    actionItems.push(`
      <li class="${actionStatus}">
        <span class="platform-readiness-action-status ${actionStatus}">${statusLabels[actionStatus]}</span>
        <strong>${escapeHtml(item.label || item.area || "运维领域")}</strong>
        <span>${escapeHtml(item.message || "检查该领域的纳管状态。")}</span>
      </li>
    `);
  }
  $("#platformReadinessActions").innerHTML = actionItems.join("");
}

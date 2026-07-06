import {
  loadAccountAudit,
  loadAccountLockouts,
  loadAccountUsers,
  loginCurrentUser,
  logoutCurrentUser,
  refreshSession,
  renderAuthControls,
} from "./accounts.js";
import {
  acknowledgeResourceExpiry,
  configureActionRuntime,
  openActionDialog,
  openManualBackupDialog,
  openManualCertRenewalDialog,
  openManualRecoveryDialog,
  runCurrentAction,
  toggleAutoBackup,
  toggleAutoRecovery,
  toggleCertRenewal,
} from "./actions.js";
import {
  fetchConfig,
  fetchDashboard,
  fetchMetricSeries,
} from "./client.js";
import { $, camelToKebab, escapeHtml } from "./dom.js";
import {
  backupLabels,
  certRenewalLabels,
  dataQualityLabels,
  formatCert,
  formatDate,
  formatElapsed,
  formatSeconds,
  formatStatusCode,
  formatTime,
  healthLabels,
  metricLabels,
  metricValue,
  recoveryLabels,
  resourceExpiryLabels,
  serverTypeLabels,
  statusText,
} from "./format.js";
import { canFetchSeries } from "./prometheus.js";
import { state } from "./state.js";
function serverAddress(server) {
  const instance = server.labels?.instance || "";
  return instance.replace(/:9100$/, "") || "--";
}

function serverMetaRows(server) {
  const typeLabel = serverTypeLabels[server.type] || server.group || "服务器";
  const rows = [
    ["类型", typeLabel],
    ["地址", serverAddress(server)],
  ];

  if (server.type === "virtual" || server.hostServerId) {
    rows.push(["宿主机", server.hostServerName || "未配置宿主机"]);
  }

  return `<div class="meta-list">
    ${rows.map(([label, value]) => `
      <span>
        <b>${escapeHtml(label)}</b>
        ${escapeHtml(value)}
      </span>
    `).join("")}
  </div>`;
}

function uniqueGroups() {
  const servers = state.dashboard?.servers || [];
  const websites = state.dashboard?.websites || [];
  return ["全部", ...Array.from(new Set([...servers, ...websites].map((item) => item.group || "默认")))];
}

function filteredServers() {
  const servers = state.dashboard?.servers || [];
  if (state.selectedGroup === "全部") return servers;
  return servers.filter((server) => (server.group || "默认") === state.selectedGroup);
}

function filteredWebsites() {
  const websites = state.dashboard?.websites || [];
  if (state.selectedGroup === "全部") return websites;
  return websites.filter((website) => (website.group || "默认") === state.selectedGroup);
}

async function loadConfig() {
  const payload = await fetchConfig();
  state.config = payload.config;
  await refreshSession();
  await loadAccountUsers();
  await loadAccountLockouts();
  await loadAccountAudit();
  renderAuthControls();
  $("#appName").textContent = state.config.appName || "本地服务器监控台";
  $("#prometheusUrl").textContent = state.config.prometheusUrl || "";
  $("#tokenInput").classList.toggle("hidden", !state.config.actionsRequireToken);
  document.querySelector(".token-field span").classList.toggle("hidden", !state.config.actionsRequireToken);
}

async function refreshDashboard() {
  $("#refreshButton").disabled = true;
  try {
    state.dashboard = await fetchDashboard();
    render();
  } catch (error) {
    renderError(error);
  } finally {
    $("#refreshButton").disabled = false;
  }
}

function renderError(error) {
  $("#serverGrid").innerHTML = "";
  $("#websiteGrid").innerHTML = "";
  $("#resourceExpiryList").innerHTML = "";
  $("#incidentLogList").innerHTML = "";
  $("#recoveryLogList").innerHTML = "";
  $("#configValidationPanel").innerHTML = "";
  $("#configValidationPanel").classList.add("hidden");
  $("#emergencyRunbookPanel").classList.add("hidden");
  $("#emergencyRunbookList").innerHTML = "";
  $("#emptyState").classList.remove("hidden");
  $("#websiteEmptyState").classList.add("hidden");
  $("#resourceExpiryEmptyState").classList.add("hidden");
  $("#incidentLogEmptyState").classList.add("hidden");
  $("#recoveryLogEmptyState").classList.add("hidden");
  $("#emptyState h2").textContent = "无法读取监控数据";
  $("#emptyState p").textContent = error.message;
}

function render() {
  const summary = state.dashboard?.summary || { total: 0, online: 0, offline: 0, unknown: 0 };
  const websiteSummary = state.dashboard?.websiteSummary || { total: 0, online: 0, offline: 0, unknown: 0 };
  const resourceExpirySummary = state.dashboard?.resourceExpirySummary
    || { total: 0, expired: 0, critical: 0, warning: 0, unknown: 0, actionRequired: 0 };
  $("#totalCount").textContent = summary.total;
  $("#onlineCount").textContent = summary.online;
  $("#offlineCount").textContent = summary.offline;
  $("#unknownCount").textContent = summary.unknown;
  $("#websiteTotalCount").textContent = websiteSummary.total;
  $("#websiteOnlineCount").textContent = websiteSummary.online;
  $("#websiteOfflineCount").textContent = websiteSummary.offline;
  $("#websiteUnknownCount").textContent = websiteSummary.unknown;
  $("#resourceTotalCount").textContent = resourceExpirySummary.total;
  $("#resourceExpiredCount").textContent = resourceExpirySummary.expired;
  $("#resourceRiskCount").textContent = resourceExpirySummary.actionRequired;
  $("#resourceUnknownCount").textContent = resourceExpirySummary.unknown;
  $("#lastUpdated").textContent = new Date((state.dashboard?.generatedAt || Date.now() / 1000) * 1000)
    .toLocaleTimeString("zh-CN", { hour12: false });

  renderSystemNotice();
  renderConfigValidation();
  renderEmergencyRunbook();
  renderGroups();
  renderServers();
  renderWebsites();
  renderResourceExpiry();
  renderIncidentLogs();
  renderRecoveryLogs();
}

function renderSystemNotice() {
  const notice = $("#systemNotice");
  const messages = [];
  const prometheus = state.dashboard?.prometheus;
  const configSource = state.dashboard?.configSource || {};

  if (prometheus && !prometheus.available) {
    const detail = prometheus.error ? `（${prometheus.error}）` : "";
    messages.push(`Prometheus 当前不可用：${prometheus.message || "无法连接采集服务"}${detail}。这会导致所有目标显示“未知”，不代表服务器全部宕机。`);
  }

  if (!configSource.usingLocalConfig) {
    messages.push(`当前加载 ${configSource.configFile || "config/servers.json"}。这是公开/示例配置；真实内网配置建议放到 config/servers.local.json。`);
  } else {
    messages.push(`当前加载本地私有配置 ${configSource.configFile}。`);
  }

  notice.classList.toggle("hidden", messages.length === 0);
  notice.innerHTML = messages.map((message) => `<p>${escapeHtml(message)}</p>`).join("");
}

function renderConfigValidation() {
  const panel = $("#configValidationPanel");
  const validation = state.dashboard?.configValidation;
  if (!validation) {
    panel.classList.add("hidden");
    panel.innerHTML = "";
    return;
  }

  const status = validation.status || "unknown";
  const items = validation.issues || [];
  const title = {
    ok: "配置健康",
    warning: "配置需要核查",
    error: "配置存在错误",
    unknown: "配置状态未知",
  }[status] || "配置状态未知";
  const summary = [
    `检查项 ${validation.total ?? items.length}`,
    `错误 ${validation.errorCount ?? 0}`,
    `警告 ${validation.warningCount ?? 0}`,
  ];

  panel.className = `config-validation-panel ${escapeHtml(status)}`;
  panel.innerHTML = `
    <div class="config-validation-head">
      <div>
        <strong>${escapeHtml(title)}</strong>
        <p>${escapeHtml(summary.join(" · "))}</p>
      </div>
      <span class="config-validation-badge ${escapeHtml(status)}">${escapeHtml(status)}</span>
    </div>
    ${items.length ? `<div class="config-validation-list">
      ${items.map((item) => `
        <div class="config-validation-item ${escapeHtml(item.severity || "unknown")}">
          <span>${escapeHtml(item.severity || "unknown")}</span>
          <p>${escapeHtml(item.message || "")}</p>
        </div>
      `).join("")}
    </div>` : ""}
  `;
}

function renderEmergencyRunbook() {
  const panel = $("#emergencyRunbookPanel");
  const items = state.dashboard?.emergencyItems || [];
  const summary = state.dashboard?.emergencySummary || { total: 0, critical: 0, warning: 0, info: 0 };
  if (!items.length) {
    panel.classList.add("hidden");
    $("#emergencyRunbookList").innerHTML = "";
    return;
  }

  const badgeStatus = summary.critical ? "critical" : summary.warning ? "warning" : "info";
  panel.className = `emergency-runbook-panel ${badgeStatus}`;
  $("#emergencyRunbookSummary").textContent = `共 ${summary.total || items.length} 项 · 严重 ${summary.critical || 0} · 预警 ${summary.warning || 0}`;
  $("#emergencyRunbookBadge").className = `emergency-badge ${badgeStatus}`;
  $("#emergencyRunbookBadge").textContent = String(summary.critical || summary.warning || summary.total || items.length);
  $("#emergencyRunbookList").innerHTML = items.map((item) => {
    const actionButton = emergencyActionButton(item);
    return `
      <article class="emergency-item ${escapeHtml(item.severity || "info")}">
        <div class="emergency-item-head">
          <strong>${escapeHtml(item.title || item.id || "应急项")}</strong>
          <span class="emergency-badge ${escapeHtml(item.severity || "info")}">${escapeHtml(item.severity || "info")}</span>
        </div>
        <p>${escapeHtml(item.message || "")}</p>
        <ol>
          ${(item.nextSteps || []).map((step) => `<li>${escapeHtml(step)}</li>`).join("")}
        </ol>
        ${actionButton ? `<div class="emergency-actions">${actionButton}</div>` : ""}
      </article>
    `;
  }).join("");
  $("#emergencyRunbookList").querySelectorAll("[data-emergency-manual-cert-renewal]").forEach((button) => {
    button.addEventListener("click", () => openManualCertRenewalDialog(button.dataset.websiteId));
  });
  $("#emergencyRunbookList").querySelectorAll("[data-emergency-manual-backup]").forEach((button) => {
    button.addEventListener("click", () => openManualBackupDialog(button.dataset.serverId));
  });
  $("#emergencyRunbookList").querySelectorAll("[data-emergency-manual-recovery]").forEach((button) => {
    button.addEventListener("click", () => openManualRecoveryDialog(button.dataset.targetType, button.dataset.targetId));
  });
  $("#emergencyRunbookList").querySelectorAll("[data-emergency-resource-ack]").forEach((button) => {
    button.addEventListener("click", () => acknowledgeResourceExpiry(button.dataset.resourceId));
  });
}

function emergencyActionButton(item) {
  if (["server", "website"].includes(item.targetType)) {
    const targets = item.targetType === "server" ? (state.config?.servers || []) : (state.config?.websites || []);
    const target = targets.find((candidate) => candidate.id === item.targetId);
    const manualRecovery = target?.manualRecovery;
    if (manualRecovery?.available) {
      return `<button type="button" class="secondary recovery-trigger compact" data-emergency-manual-recovery="true" data-target-type="${escapeHtml(item.targetType)}" data-target-id="${escapeHtml(target.id)}">${escapeHtml(manualRecovery.label || "手动恢复")}</button>`;
    }
  }
  if (item.targetType === "website-cert") {
    const website = (state.config?.websites || []).find((candidate) => candidate.id === item.targetId);
    const manualCertRenewal = website?.manualCertRenewal;
    if (manualCertRenewal?.available) {
      return `<button type="button" class="secondary recovery-trigger compact" data-emergency-manual-cert-renewal="true" data-website-id="${escapeHtml(website.id)}">${escapeHtml(manualCertRenewal.label || "手动续期")}</button>`;
    }
  }
  if (item.targetType === "server-backup") {
    const server = (state.config?.servers || []).find((candidate) => candidate.id === item.targetId);
    const manualBackup = server?.manualBackup;
    if (manualBackup?.available) {
      return `<button type="button" class="secondary recovery-trigger compact" data-emergency-manual-backup="true" data-server-id="${escapeHtml(server.id)}">${escapeHtml(manualBackup.label || "立即备份")}</button>`;
    }
  }
  if (item.targetType === "resource") {
    const resource = (state.dashboard?.resourceExpiryItems || []).find((candidate) => candidate.id === item.targetId);
    if (!resource) return "";

    const actions = [];
    if (resource.renewUrl) {
      actions.push(`<a class="secondary recovery-trigger compact" href="${escapeHtml(resource.renewUrl)}" target="_blank" rel="noreferrer">续费入口</a>`);
    }
    if (resource.actionRequired && ["critical", "warning"].includes(resource.status || "")) {
      actions.push(`<button type="button" class="secondary recovery-trigger compact" data-emergency-resource-ack="true" data-resource-id="${escapeHtml(resource.id)}">确认 7 天</button>`);
    }
    return actions.join("");
  }
  return "";
}

function renderGroups() {
  const groups = uniqueGroups();
  if (!groups.includes(state.selectedGroup)) state.selectedGroup = "全部";

  const servers = state.dashboard?.servers || [];
  const websites = state.dashboard?.websites || [];
  $("#groupList").innerHTML = groups.map((group) => {
    const count = group === "全部"
      ? servers.length + websites.length
      : servers.filter((item) => (item.group || "默认") === group).length
        + websites.filter((item) => (item.group || "默认") === group).length;
    const active = group === state.selectedGroup ? "active" : "";
    return `<button class="group-button ${active}" type="button" data-group="${escapeHtml(group)}">
      <span>${escapeHtml(group)}</span>
      <span class="count-pill">${count}</span>
    </button>`;
  }).join("");

  document.querySelectorAll(".group-button").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedGroup = button.dataset.group;
      render();
    });
  });
}

function renderServers() {
  const servers = filteredServers();
  $("#emptyState").classList.toggle("hidden", servers.length !== 0);
  $("#serverGrid").innerHTML = servers.map(serverCard).join("");
  const container = $("#serverGrid");

  container.querySelectorAll("[data-action-id]").forEach((button) => {
    button.addEventListener("click", () => openActionDialog(button.dataset.serverId, button.dataset.actionId));
  });

  container.querySelectorAll("[data-manual-recovery]").forEach((button) => {
    button.addEventListener("click", () => openManualRecoveryDialog(button.dataset.targetType, button.dataset.targetId));
  });

  container.querySelectorAll("[data-auto-recovery-toggle]").forEach((input) => {
    input.addEventListener("change", () => toggleAutoRecovery(input.dataset.targetType, input.dataset.targetId, input.checked));
  });

  container.querySelectorAll("[data-manual-backup]").forEach((button) => {
    button.addEventListener("click", () => openManualBackupDialog(button.dataset.serverId));
  });

  container.querySelectorAll("[data-auto-backup-toggle]").forEach((input) => {
    input.addEventListener("change", () => toggleAutoBackup(input.dataset.serverId, input.checked));
  });

  container.querySelectorAll("[data-chart-metric]").forEach((button) => {
    button.addEventListener("click", async () => {
      state.chartMetric = button.dataset.chartMetric;
      renderServers();
      await loadCharts();
    });
  });

  loadCharts();
}

function renderWebsites() {
  const websites = filteredWebsites();
  $("#websiteEmptyState").classList.toggle("hidden", websites.length !== 0);
  $("#websiteGrid").innerHTML = websites.map(websiteCard).join("");
  const container = $("#websiteGrid");

  container.querySelectorAll("[data-manual-recovery]").forEach((button) => {
    button.addEventListener("click", () => openManualRecoveryDialog(button.dataset.targetType, button.dataset.targetId));
  });

  container.querySelectorAll("[data-auto-recovery-toggle]").forEach((input) => {
    input.addEventListener("change", () => toggleAutoRecovery(input.dataset.targetType, input.dataset.targetId, input.checked));
  });

  container.querySelectorAll("[data-manual-cert-renewal]").forEach((button) => {
    button.addEventListener("click", () => openManualCertRenewalDialog(button.dataset.websiteId));
  });

  container.querySelectorAll("[data-cert-renewal-toggle]").forEach((input) => {
    input.addEventListener("change", () => toggleCertRenewal(input.dataset.websiteId, input.checked));
  });
}

function renderResourceExpiry() {
  const items = state.dashboard?.resourceExpiryItems || [];
  $("#resourceExpiryEmptyState").classList.toggle("hidden", items.length !== 0);
  $("#resourceExpiryList").innerHTML = items.map(resourceExpiryCard).join("");
  $("#resourceExpiryList").querySelectorAll("[data-resource-ack]").forEach((button) => {
    button.addEventListener("click", () => acknowledgeResourceExpiry(button.dataset.resourceId));
  });
}

function renderIncidentLogs() {
  const logs = state.dashboard?.incidentLogs || [];
  $("#incidentLogEmptyState").classList.toggle("hidden", logs.length !== 0);
  $("#incidentLogList").innerHTML = logs.slice().reverse().map(incidentLogCard).join("");
}

function renderRecoveryLogs() {
  const logs = state.dashboard?.recoveryLogs || [];
  $("#recoveryLogEmptyState").classList.toggle("hidden", logs.length !== 0);
  $("#recoveryLogList").innerHTML = logs.slice().reverse().map(recoveryLogCard).join("");
}

function serverCard(server) {
  const configured = state.config?.servers?.find((item) => item.id === server.id) || {};
  const actions = configured.actions || [];
  const description = configured.description || `${server.labels?.instance || ""}`;

  return `<article class="server-card" data-server-id="${escapeHtml(server.id)}">
    <div class="server-head">
      <div class="server-title">
        <h2>${escapeHtml(server.name || server.id)}</h2>
        <p class="muted">${escapeHtml(description)}</p>
      </div>
      <span class="status ${escapeHtml(server.health || server.status)}">${healthLabels[server.health] || statusText(server.status)}</span>
    </div>
    ${serverMetaRows(server)}
    ${dataQualityBlock(server.dataQuality)}
    ${issuesBlock(server.issues)}
    ${incidentBlock(server.autoRecovery?.incident)}
    <div class="metric-grid">
      ${metricBlock("cpu", server.metrics.cpu)}
      ${metricBlock("memory", server.metrics.memory)}
      ${metricBlock("disk", server.metrics.disk)}
      ${metricBlock("load", server.metrics.load)}
      ${metricBlock("rx", server.metrics.rx)}
      ${metricBlock("tx", server.metrics.tx)}
      ${metricBlock("uptime", server.metrics.uptime)}
    </div>
    <div class="chart-row">
      <div class="chart-head">
        <strong>${metricLabels[state.chartMetric]} 趋势</strong>
        <div class="segmented">
          ${["cpu", "memory", "disk", "rx", "tx"].map((metric) => `
            <button type="button" data-chart-metric="${metric}" class="${metric === state.chartMetric ? "active" : ""}">
              ${metricLabels[metric]}
            </button>`).join("")}
        </div>
      </div>
      <canvas width="620" height="180" data-chart-server="${escapeHtml(server.id)}"></canvas>
    </div>
    ${recoveryBlock(server.autoRecovery, configured.manualRecovery, "server", server.id)}
    ${backupBlock(server.autoBackup, configured.manualBackup, server)}
    <div class="actions">
      ${actions.length ? actions.map((action) => actionButton(server, action)).join("") : '<span class="muted">没有已启用操作</span>'}
    </div>
  </article>`;
}

function websiteCard(website) {
  const configured = state.config?.websites?.find((item) => item.id === website.id) || {};
  const description = configured.description || website.url || "";
  const server = website.serverId
    ? state.dashboard?.servers?.find((item) => item.id === website.serverId)
    : null;
  const linkedServer = server ? `<span class="linked-server">${escapeHtml(server.name || server.id)}</span>` : "";

  return `<article class="server-card website-card" data-website-id="${escapeHtml(website.id)}">
    <div class="server-head">
      <div class="server-title">
        <h2>${escapeHtml(website.name || website.id)}</h2>
        <p class="muted">${escapeHtml(description)}</p>
      </div>
      <span class="status ${escapeHtml(website.health || website.status)}">${healthLabels[website.health] || statusText(website.status)}</span>
    </div>
    ${dataQualityBlock(website.dataQuality)}
    ${issuesBlock(website.issues)}
    ${incidentBlock(website.autoRecovery?.incident)}
    <div class="metric-grid website-metrics">
      ${websiteMetricBlock("HTTP", formatStatusCode(website.metrics.statusCode))}
      ${websiteMetricBlock("响应", formatSeconds(website.metrics.duration))}
      ${websiteMetricBlock("证书", formatCert(website.metrics.certExpiresIn))}
      ${websiteMetricBlock("关联服务器", linkedServer || "--", true)}
    </div>
    ${recoveryBlock(website.autoRecovery, configured.manualRecovery, "website", website.id)}
    ${certRenewalBlock(website.certRenewal, configured.manualCertRenewal, website)}
  </article>`;
}

function metricBlock(metric, value) {
  return `<div class="metric">
    <span>${metricLabels[metric]}</span>
    <strong>${metricValue(metric, value)}</strong>
  </div>`;
}

function websiteMetricBlock(label, value, raw = false) {
  return `<div class="metric">
    <span>${escapeHtml(label)}</span>
    <strong>${raw ? value : escapeHtml(value)}</strong>
  </div>`;
}

function dataQualityBlock(quality) {
  if (!quality || quality.level === "ok") return "";
  const level = quality.level || "unknown";
  const trusted = quality.trusted !== false;
  const title = dataQualityLabels[level] || level;
  const trustText = trusted ? "判定可信" : "数据不可信，自动恢复已阻断";
  return `<div class="quality-block ${escapeHtml(level)} ${trusted ? "trusted" : "untrusted"}">
    <div class="quality-head">
      <strong>${escapeHtml(title)}</strong>
      <span>${escapeHtml(trustText)}</span>
    </div>
    <p>${escapeHtml(quality.message || "暂无数据质量说明")}</p>
  </div>`;
}

function issuesBlock(issues = []) {
  if (!issues.length) return "";
  return `<div class="issues">
    ${issues.map((issue) => `<span>${escapeHtml(issue)}</span>`).join("")}
  </div>`;
}

function incidentBlock(incident) {
  if (!incident || (!incident.active && !incident.recoveredAt)) return "";
  const label = incident.active ? "中断中" : "已恢复";
  const status = incident.active ? "failed" : "triggered";
  const duration = incident.active
    ? formatElapsed(incident.durationSeconds || 0)
    : formatElapsed(incident.durationSeconds || 0);
  const meta = incident.active
    ? `开始 ${formatTime(incident.startedAt)}，已持续 ${duration}`
    : `恢复 ${formatTime(incident.recoveredAt)}，持续 ${duration}`;
  return `<div class="incident-block">
    <div class="recovery-head">
      <strong>中断追踪</strong>
      <span class="recovery-badge ${status}">${label}</span>
    </div>
    <div class="recovery-meta">
      <span>${escapeHtml(meta)}</span>
      ${incident.lastLogId ? `<span>日志 ${escapeHtml(incident.lastLogId)}</span>` : ""}
    </div>
    <p class="recovery-message muted">${escapeHtml(incident.summary || incident.reason || "暂无摘要")}</p>
  </div>`;
}

function resourceExpiryCard(item) {
  const status = item.status || "unknown";
  const label = resourceExpiryLabels[status] || status;
  const daysText = item.daysRemaining === null || item.daysRemaining === undefined
    ? "--"
    : `${item.daysRemaining} 天`;
  const meta = [
    item.type ? `类型 ${item.type}` : "",
    item.provider ? `供应商 ${item.provider}` : "",
    item.owner ? `负责人 ${item.owner}` : "",
    item.linkedTarget ? `关联 ${item.linkedTarget}` : "",
  ].filter(Boolean);
  const renewLink = item.renewUrl
    ? `<a href="${escapeHtml(item.renewUrl)}" target="_blank" rel="noreferrer">续费入口</a>`
    : "";
  const canAcknowledge = item.actionRequired && ["critical", "warning"].includes(status);
  const ackText = item.acknowledged
    ? `已确认至 ${formatDate(item.acknowledgedUntil)}`
    : "";
  const missingHandlingFields = Array.isArray(item.missingHandlingFields)
    ? item.missingHandlingFields.join(", ")
    : "";
  const handlingWarning = item.handlingMessage
    ? `${item.handlingMessage}${missingHandlingFields ? ` (${missingHandlingFields})` : ""}`
    : "";
  const ackButton = canAcknowledge
    ? `<button type="button" class="secondary recovery-trigger compact" data-resource-ack="true" data-resource-id="${escapeHtml(item.id)}">确认 7 天</button>`
    : "";
  return `<article class="expiry-card ${escapeHtml(status)}">
    <div class="expiry-head">
      <div>
        <h3>${escapeHtml(item.name || item.id || "未命名资源")}</h3>
        <p class="muted">${escapeHtml(item.message || "")}</p>
      </div>
      <span class="expiry-badge ${escapeHtml(status)}">${escapeHtml(label)}</span>
    </div>
    <div class="expiry-meta">
      <span>到期 ${escapeHtml(formatDate(item.expiresAt))}</span>
      <span>剩余 ${escapeHtml(daysText)}</span>
      <span>预警 ${escapeHtml(String(item.warningDays ?? 30))} 天</span>
      <span>临界 ${escapeHtml(String(item.criticalDays ?? 7))} 天</span>
      ${meta.map((text) => `<span>${escapeHtml(text)}</span>`).join("")}
    </div>
    ${item.notes || handlingWarning || renewLink || ackText || ackButton ? `<div class="expiry-notes">${item.notes ? `<span>${escapeHtml(item.notes)}</span>` : ""}${handlingWarning ? `<span>${escapeHtml(handlingWarning)}</span>` : ""}${ackText ? `<span>${escapeHtml(ackText)}</span>` : ""}${renewLink}${ackButton}</div>` : ""}
  </article>`;
}

function recoveryBlock(recovery, manualRecovery, targetType, targetId) {
  if (!recovery) return "";
  const manualButton = manualRecovery?.available
    ? `<button type="button" class="secondary recovery-trigger compact" data-manual-recovery="true" data-target-type="${escapeHtml(targetType)}" data-target-id="${escapeHtml(targetId)}">${escapeHtml(manualRecovery.label || "手动执行")}</button>`
    : "";
  const status = recovery.status || "idle";
  const statusText = recovery.enabled ? (recoveryLabels[status] || status) : "未启用";
  const logText = recovery.lastLogId || "--";
  return `<div class="recovery-block">
    <div class="recovery-head">
      <div class="block-title-row">
        <strong>自动恢复</strong>
        ${toggleControl(recovery.enabled, "auto-recovery-toggle", { targetType, targetId })}
      </div>
      <span class="recovery-badge ${escapeHtml(status)}">${escapeHtml(statusText)}</span>
    </div>
    <div class="recovery-meta">
      <span>连续失败 ${escapeHtml(String(recovery.consecutiveFailures ?? 0))} 次</span>
      <span>最近尝试 ${escapeHtml(formatTime(recovery.lastAttemptAt))}</span>
      <span>最近执行 ${escapeHtml(formatTime(recovery.lastCompletedAt))}</span>
      <span>关联日志 ${escapeHtml(logText)}</span>
    </div>
    <p class="recovery-message muted">${escapeHtml(recovery.message || recovery.lastReason || "暂无自动恢复记录")}</p>
    ${manualButton ? `<div class="recovery-actions">${manualButton}</div>` : ""}
  </div>`;
}

function backupBlock(autoBackup, manualBackup, server) {
  if (!autoBackup) return "";
  const manualButton = manualBackup?.available
    ? `<button type="button" class="secondary recovery-trigger compact" data-manual-backup="true" data-server-id="${escapeHtml(server.id)}">${escapeHtml(manualBackup.label || "立即备份")}</button>`
    : "";
  const status = autoBackup.status || "idle";
  const statusText = autoBackup.enabled ? (backupLabels[status] || status) : "未启用";
  const intervalHours = Math.max(1, Math.round((autoBackup.intervalSeconds || 86400) / 3600));
  const logText = autoBackup.lastLogId || "--";
  return `<div class="recovery-block">
    <div class="recovery-head">
      <div class="block-title-row">
        <strong>自动备份</strong>
        ${toggleControl(autoBackup.enabled, "auto-backup-toggle", { serverId: server.id })}
      </div>
      <span class="recovery-badge ${escapeHtml(status)}">${escapeHtml(statusText)}</span>
    </div>
    <div class="recovery-meta">
      <span>周期 ${escapeHtml(String(intervalHours))} 小时</span>
      <span>最近尝试 ${escapeHtml(formatTime(autoBackup.lastAttemptAt))}</span>
      <span>最近备份 ${escapeHtml(formatTime(autoBackup.lastCompletedAt))}</span>
      <span>关联日志 ${escapeHtml(logText)}</span>
    </div>
    <p class="recovery-message muted">${escapeHtml(autoBackup.message || autoBackup.lastReason || "暂无自动备份记录")}</p>
    ${manualButton ? `<div class="recovery-actions">${manualButton}</div>` : ""}
  </div>`;
}

function certRenewalBlock(certRenewal, manualCertRenewal, website) {
  if (!certRenewal) return "";
  const manualButton = manualCertRenewal?.available
    ? `<button type="button" class="secondary recovery-trigger compact" data-manual-cert-renewal="true" data-website-id="${escapeHtml(website.id)}">${escapeHtml(manualCertRenewal.label || "手动续期")}</button>`
    : "";
  const status = certRenewal.status || "idle";
  const statusText = certRenewal.enabled ? (certRenewalLabels[status] || status) : "未启用";
  const expireText = certRenewal.expiresInDays === null || certRenewal.expiresInDays === undefined
    ? "证书天数未知"
    : `剩余 ${certRenewal.expiresInDays} 天`;
  const logText = certRenewal.lastLogId || "--";
  return `<div class="recovery-block">
    <div class="recovery-head">
      <div class="block-title-row">
        <strong>证书续期</strong>
        ${toggleControl(certRenewal.enabled, "cert-renewal-toggle", { websiteId: website.id })}
      </div>
      <span class="recovery-badge ${escapeHtml(status)}">${escapeHtml(statusText)}</span>
    </div>
    <div class="recovery-meta">
      <span>${escapeHtml(expireText)}</span>
      <span>提前 ${escapeHtml(String(certRenewal.renewBeforeDays ?? 14))} 天续期</span>
      <span>最近尝试 ${escapeHtml(formatTime(certRenewal.lastAttemptAt))}</span>
      <span>最近续期 ${escapeHtml(formatTime(certRenewal.lastCompletedAt))}</span>
      <span>关联日志 ${escapeHtml(logText)}</span>
    </div>
    <p class="recovery-message muted">${escapeHtml(certRenewal.message || certRenewal.lastReason || "暂无证书续期记录")}</p>
    ${manualButton ? `<div class="recovery-actions">${manualButton}</div>` : ""}
  </div>`;
}

function toggleControl(enabled, kind, data = {}) {
  const attrs = Object.entries(data)
    .map(([key, value]) => `data-${camelToKebab(key)}="${escapeHtml(value)}"`)
    .join(" ");
  const checked = enabled ? "checked" : "";
  return `<label class="toggle-control">
    <input type="checkbox" ${checked} data-${escapeHtml(kind)}="true" ${attrs}>
    <span class="toggle-track" aria-hidden="true"></span>
  </label>`;
}

function recoveryLogCard(log) {
  const statusClass = log.ok ? "healthy" : "down";
  const invocationText = {
    auto: "自动恢复",
    "auto-recovery-toggle": "恢复开关",
    manual: "手动执行",
    "manual-recovery": "手动恢复",
    "auto-backup": "自动备份",
    "auto-backup-toggle": "备份开关",
    "manual-backup": "手动备份",
    "auto-cert": "自动续期",
    "manual-cert": "手动续期",
    "cert-renewal-toggle": "证书开关",
    "resource-ack": "资源确认",
  }[log.invocation] || log.invocation || "--";
  const output = [
    log.message || "",
    `原因: ${log.reason || "--"}`,
    `目标: ${log.targetName || log.targetId || "--"}`,
    `动作: ${log.actionName || log.actionId || "--"}`,
    `方式: ${invocationText}`,
    `执行时间: ${formatTime(log.timestamp)}`,
    `退出码: ${log.returnCode ?? "-"}`,
    `耗时: ${log.durationSeconds ?? "-"}s`,
    "",
    log.stdout ? `STDOUT\n${log.stdout}` : "",
    log.stderr ? `STDERR\n${log.stderr}` : "",
  ].filter(Boolean).join("\n");

  return `<article class="log-card">
    <div class="log-head">
      <div>
        <h3>${escapeHtml(log.targetName || log.targetId || "恢复日志")}</h3>
        <p class="muted">${escapeHtml(log.actionServerName || log.actionServerId || "")}</p>
      </div>
      <span class="status ${statusClass}">${log.ok ? "成功" : "失败"}</span>
    </div>
    <pre class="log-output">${escapeHtml(output)}</pre>
  </article>`;
}

function incidentLogCard(log) {
  const active = log.status === "active";
  const statusClass = active ? "down" : "healthy";
  const statusText = active ? "中断中" : "已恢复";
  const actionResult = incidentActionResultText(log);
  const output = [
    log.summary || "",
    `类型: ${log.targetKind || log.targetType || "--"}`,
    `目标: ${log.targetName || log.targetId || "--"}`,
    `原因: ${log.reason || "--"}`,
    `开始: ${formatTime(log.startedAt)}`,
    `恢复: ${log.recoveredAt ? formatTime(log.recoveredAt) : "--"}`,
    `持续: ${formatElapsed(log.durationSeconds || 0)}`,
    log.lastLogId ? `关联恢复日志: ${log.lastLogId}` : "",
    actionResult,
  ].filter(Boolean).join("\n");

  return `<article class="log-card incident-log-card">
    <div class="log-head">
      <div>
        <h3>${escapeHtml(log.targetName || log.targetId || "中断事件")}</h3>
        <p class="muted">${escapeHtml(log.targetKind || log.targetType || "")}</p>
      </div>
      <span class="status ${statusClass}">${statusText}</span>
    </div>
    <pre class="log-output">${escapeHtml(output)}</pre>
  </article>`;
}

function incidentActionResultText(log) {
  if (!log.lastActionResult) return "";
  const resultLabels = {
    success: "成功",
    failed: "失败",
  };
  const result = resultLabels[log.lastActionResult] || log.lastActionResult;
  const actionAt = log.lastActionAt ? `，时间 ${formatTime(log.lastActionAt)}` : "";
  const logText = log.lastLogId ? `，日志 ${log.lastLogId}` : "，无日志 ID";
  return `最近恢复动作: ${result}${actionAt}${logText}`;
}

function actionButton(server, action) {
  const danger = action.danger || "low";
  const manualOnly = action.enabled === false;
  const classes = [danger, manualOnly ? "manual-only" : ""].filter(Boolean).join(" ");
  const label = `${action.name || action.id}${manualOnly ? "（仅手动）" : ""}`;
  return `<button type="button" class="${escapeHtml(classes)}" data-server-id="${escapeHtml(server.id)}" data-action-id="${escapeHtml(action.id)}">
    ${escapeHtml(label)}
  </button>`;
}

async function loadCharts() {
  const canvases = Array.from(document.querySelectorAll("canvas[data-chart-server]"));
  if (!canFetchSeries(state.dashboard)) {
    canvases.forEach((canvas) => drawChart(canvas, [], state.chartMetric, "Prometheus 采集层不可用，暂无趋势数据"));
    return;
  }

  await Promise.all(canvases.map(async (canvas) => {
    try {
      const payload = await fetchMetricSeries({
        serverId: canvas.dataset.chartServer,
        metric: state.chartMetric,
        minutes: 60,
      });
      drawChart(canvas, payload.values || [], state.chartMetric);
    } catch (error) {
      drawChart(canvas, [], state.chartMetric, error.message);
    }
  }));
}

function drawChart(canvas, values, metric, errorText = "") {
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, width, height);
  ctx.strokeStyle = "#e2e8f0";
  ctx.lineWidth = 1;
  for (let y = 30; y < height; y += 30) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }

  const points = values
    .map((item) => [Number(item[0]), Number(item[1])])
    .filter((item) => Number.isFinite(item[0]) && Number.isFinite(item[1]));

  if (!points.length) {
    ctx.fillStyle = "#627182";
    ctx.font = "14px Microsoft YaHei, Segoe UI, Arial";
    ctx.fillText(errorText || "暂无趋势数据", 18, height / 2);
    return;
  }

  const data = points.map((item) => item[1]);
  let min = Math.min(...data);
  let max = Math.max(...data);
  if (["cpu", "memory", "disk"].includes(metric)) {
    min = 0;
    max = 100;
  } else if (max === min) {
    max += 1;
    min = Math.max(0, min - 1);
  }

  const pad = 18;
  ctx.beginPath();
  points.forEach((point, index) => {
    const x = pad + (index / Math.max(1, points.length - 1)) * (width - pad * 2);
    const y = height - pad - ((point[1] - min) / Math.max(1, max - min)) * (height - pad * 2);
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = ["rx", "tx"].includes(metric) ? "#1f8a5b" : "#2563eb";
  ctx.lineWidth = 3;
  ctx.stroke();

  const latest = data[data.length - 1];
  ctx.fillStyle = "#17202a";
  ctx.font = "14px Microsoft YaHei, Segoe UI, Arial";
  ctx.fillText(metricValue(metric, latest), 18, 24);
}

configureActionRuntime({ loadConfig, refreshDashboard, render });

$("#refreshButton").addEventListener("click", refreshDashboard);
$("#loginForm").addEventListener("submit", (event) => loginCurrentUser(event, { refreshDashboard }));
$("#logoutButton").addEventListener("click", logoutCurrentUser);
$("#actionForm").addEventListener("submit", async (event) => {
  if (event.submitter?.value !== "run") return;
  event.preventDefault();
  await runCurrentAction();
});

loadConfig()
  .then(refreshDashboard)
  .then(() => {
    state.refreshTimer = window.setInterval(refreshDashboard, 30000);
  })
  .catch(renderError);

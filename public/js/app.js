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
  deleteResourceExpiryRecord,
  openActionDialog,
  openManualBackupDialog,
  openManualCertRenewalDialog,
  openManualRecoveryDialog,
  runCurrentAction,
  saveResourceExpiryRecord,
  toggleAutoBackup,
  toggleAutoRecovery,
  toggleCertRenewal,
} from "./actions.js";
import {
  fetchConfig,
  fetchDashboard,
  fetchMetricSeries,
  fetchPrometheusAlerts,
  fetchPrometheusRules,
} from "./client.js";
import { $, camelToKebab, escapeHtml } from "./dom.js";
import {
  backupLabels,
  certRenewalLabels,
  dataQualityLabels,
  formatCert,
  formatDate,
  formatDateTime,
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
import { renderSystemNotice } from "./notices.js";
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

function unavailableAlertsPayload(error) {
  return {
    ok: false,
    available: false,
    message: error?.message || "Prometheus 告警接口不可用",
    summary: { total: 0, firing: 0, pending: 0, severityCounts: {}, stateCounts: {}, actionRequired: false },
    alerts: [],
  };
}

function unavailableRulesPayload(error) {
  return {
    ok: false,
    available: false,
    status: "unavailable",
    message: error?.message || "Prometheus 规则接口不可用",
    summary: {
      expected: 0,
      loaded: 0,
      missing: 0,
      unhealthy: 0,
      missingRules: [],
      unhealthyRules: [],
      actionRequired: true,
    },
    rules: [],
  };
}

async function loadPrometheusAlerts() {
  try {
    return await fetchPrometheusAlerts();
  } catch (error) {
    return unavailableAlertsPayload(error);
  }
}

async function loadPrometheusRules() {
  try {
    return await fetchPrometheusRules();
  } catch (error) {
    return unavailableRulesPayload(error);
  }
}

async function refreshDashboard() {
  $("#refreshButton").disabled = true;
  try {
    const [dashboard, prometheusAlerts, prometheusRules] = await Promise.all([
      fetchDashboard(),
      loadPrometheusAlerts(),
      loadPrometheusRules(),
    ]);
    state.dashboard = dashboard;
    state.prometheusAlerts = prometheusAlerts;
    state.prometheusRules = prometheusRules;
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
  $("#monitoringLinks").innerHTML = "";
  $("#monitoringLinks").classList.add("hidden");
  $("#platformHealthPanel").innerHTML = "";
  $("#platformHealthPanel").classList.add("hidden");
  $("#accountSecurityPanel").innerHTML = "";
  $("#accountSecurityPanel").classList.add("hidden");
  $("#actionSafetyPanel").classList.add("hidden");
  $("#actionSafetyList").innerHTML = "";
  $("#prometheusAlertsPanel").classList.add("hidden");
  $("#prometheusAlertsList").innerHTML = "";
  $("#prometheusRulesPanel").classList.add("hidden");
  $("#prometheusRulesList").innerHTML = "";
  $("#unmanagedTargetsPanel").classList.add("hidden");
  $("#unmanagedTargetsList").innerHTML = "";
  $("#emergencyRunbookPanel").classList.add("hidden");
  $("#emergencyRunbookList").innerHTML = "";
  $("#certRenewalRiskPanel").classList.add("hidden");
  $("#certRenewalRiskList").innerHTML = "";
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

  renderMonitoringLinks();
  renderSystemNotice();
  renderConfigValidation();
  renderPlatformHealth();
  renderAuthControls();
  renderActionSafety();
  renderPrometheusAlerts();
  renderPrometheusRules();
  renderUnmanagedTargets();
  renderEmergencyRunbook();
  renderCertRenewalRisks();
  renderGroups();
  renderServers();
  renderWebsites();
  renderResourceExpiry();
  renderIncidentLogs();
  renderRecoveryLogs();
}

function renderMonitoringLinks() {
  const links = $("#monitoringLinks");
  const grafana = state.dashboard?.grafana || {};
  const items = [];
  if (grafana.url) {
    items.push(`<a href="${escapeHtml(grafana.url)}" target="_blank" rel="noreferrer">Grafana</a>`);
  }
  if (grafana.dashboardUrl) {
    items.push(`<a href="${escapeHtml(grafana.dashboardUrl)}" target="_blank" rel="noreferrer">Ops dashboard</a>`);
  }

  links.classList.toggle("hidden", items.length === 0);
  links.innerHTML = items.join("");
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

function renderPlatformHealth() {
  const panel = $("#platformHealthPanel");
  const health = state.dashboard?.platformHealth;
  if (!health) {
    panel.classList.add("hidden");
    panel.innerHTML = "";
    return;
  }

  const status = health.status || "unknown";
  const summary = health.summary || {};
  const issues = health.issues || [];
  const root = health.rootVolumeHealth || {};
  const title = {
    ok: "Platform health",
    warning: "Platform needs attention",
    critical: "Platform risk",
    error: "Platform risk",
    unknown: "Platform health unknown",
  }[status] || "Platform health unknown";
  const summaryText = [
    `services ${summary.localOk ?? 0}/${summary.localTotal ?? 0}`,
    `binaries ${summary.binaryOk ?? 0}/${summary.binaryTotal ?? 0}`,
    `dirs ${summary.directoryOk ?? 0}/${summary.directoryTotal ?? 0}`,
    `junctions ${summary.junctionCount ?? 0}`,
    `prometheus TSDB quarantines ${summary.prometheusQuarantineCount ?? 0}`,
    `watchdog ${summary.watchdogStatus || "unknown"}`,
  ];
  const rootText = root.Drive
    ? `${root.Drive} ${root.OperationalStatus || root.HealthStatus || root.Status || "unknown"}`
    : "";

  panel.className = `platform-health-panel ${escapeHtml(status)}`;
  panel.innerHTML = `
    <div class="platform-health-head">
      <div>
        <strong>${escapeHtml(title)}</strong>
        <p>${escapeHtml(summaryText.join(" / "))}${rootText ? ` / ${escapeHtml(rootText)}` : ""}</p>
      </div>
      <span class="platform-health-badge ${escapeHtml(status)}">${escapeHtml(status)}</span>
    </div>
    ${issues.length ? `<div class="platform-health-list">
      ${issues.map((item) => `
        <div class="platform-health-item ${escapeHtml(item.severity || "unknown")}">
          <span>${escapeHtml(item.severity || "unknown")}</span>
          <p>${escapeHtml(item.message || item.id || "")}</p>
        </div>
      `).join("")}
    </div>` : ""}
  `;
}

const actionSafetyIssueLabels = {
  missing_confirm: "高危动作缺少确认文本",
  auto_missing_timeout: "自动动作缺少超时时间",
  invalid_command: "命令配置无效",
};

const actionSafetyWatchLabels = {
  allow_auto: "允许自动执行",
  high_danger: "高危动作",
};

function renderActionSafety() {
  const panel = $("#actionSafetyPanel");
  const actionSafetySummary = state.dashboard?.actionSafetySummary;
  if (!actionSafetySummary || actionSafetySummary.status === "ok") {
    panel.classList.add("hidden");
    $("#actionSafetyList").innerHTML = "";
    return;
  }

  const items = actionSafetySummary.items || [];
  const level = actionSafetySummary.actionRequired ? "attention" : "watch";
  panel.className = `action-safety-panel ${level}`;
  $("#actionSafetyBadge").className = `action-safety-badge ${level}`;
  $("#actionSafetyBadge").textContent = String(actionSafetySummary.actionRequired || items.length || 0);
  $("#actionSafetySummary").textContent = `动作 ${actionSafetySummary.total ?? 0} 个，自动 ${actionSafetySummary.allowAuto ?? 0} 个，高危 ${actionSafetySummary.highDanger ?? 0} 个，需处理 ${actionSafetySummary.actionRequired ?? 0} 项。`;
  $("#actionSafetyList").innerHTML = items.length
    ? items.map(actionSafetyCard).join("")
    : `<article class="action-safety-item watch"><p>存在自动或高危动作，请定期复核动作权限、超时和确认文本。</p></article>`;
}

function actionSafetyCard(item) {
  const issues = item.issues || [];
  const watchReasons = item.watchReasons || [];
  const labels = issues
    .map((issue) => actionSafetyIssueLabels[issue] || issue)
    .concat(watchReasons.map((reason) => actionSafetyWatchLabels[reason] || reason));
  const level = issues.length ? "attention" : "watch";
  const meta = [
    item.serverName || item.serverId,
    item.allowAuto ? "自动执行" : "仅手动",
    item.danger ? `风险 ${item.danger}` : "",
    item.timeoutSeconds ? `超时 ${item.timeoutSeconds}s` : "未配置超时",
  ].filter(Boolean).join(" / ");
  return `
    <article class="action-safety-item ${escapeHtml(level)}">
      <div class="action-safety-item-head">
        <strong>${escapeHtml(item.actionName || item.actionId || "未命名动作")}</strong>
        <span>${escapeHtml(level === "attention" ? "需处理" : "关注")}</span>
      </div>
      <p class="muted">${escapeHtml(meta)}</p>
      <p>${escapeHtml(labels.join("；") || "建议复核动作配置。")}</p>
    </article>
  `;
}

function renderPrometheusAlerts() {
  const panel = $("#prometheusAlertsPanel");
  const alerts = state.prometheusAlerts?.alerts || [];
  const summary = state.prometheusAlerts?.summary || { total: 0, firing: 0, pending: 0, severityCounts: {} };
  if (!state.prometheusAlerts) {
    panel.classList.add("hidden");
    $("#prometheusAlertsList").innerHTML = "";
    return;
  }

  const level = state.prometheusAlerts.available === false
    ? "warning"
    : summary.firing > 0
      ? "critical"
      : summary.pending > 0
        ? "warning"
        : "ok";
  panel.className = `prometheus-alerts-panel ${level}`;
  $("#prometheusAlertsBadge").className = `prometheus-alert-badge ${level}`;
  $("#prometheusAlertsBadge").textContent = String(summary.firing || summary.pending || summary.total || 0);
  $("#prometheusAlertsSummary").textContent = state.prometheusAlerts.available === false
    ? `告警接口不可用：${state.prometheusAlerts.message || "未知错误"}`
    : `当前 ${summary.total || alerts.length} 条，触发中 ${summary.firing || 0} 条，等待触发 ${summary.pending || 0} 条`;

  if (state.prometheusAlerts.available === false) {
    $("#prometheusAlertsList").innerHTML = `
      <article class="prometheus-alert-item warning">
        <div class="prometheus-alert-item-head">
          <strong>告警数据不可用</strong>
          <span>warning</span>
        </div>
        <p>${escapeHtml(state.prometheusAlerts.message || "")}</p>
        <p class="alert-action">应急建议：检查 Prometheus /-/ready、/api/v1/alerts 和本平台 Prometheus 地址配置。</p>
      </article>
    `;
    return;
  }

  $("#prometheusAlertsList").innerHTML = alerts.length
    ? alerts.map(prometheusAlertCard).join("")
    : `
      <article class="prometheus-alert-item ok">
        <div class="prometheus-alert-item-head">
          <strong>当前无 Prometheus 告警</strong>
          <span>ok</span>
        </div>
        <p>Prometheus 告警接口可用，当前没有 firing 或 pending 告警。</p>
      </article>
    `;
}

function prometheusAlertCard(alert) {
  const stateLabel = { firing: "触发中", pending: "等待触发" }[alert.state] || alert.state || "未知";
  const severity = alert.severity || "unknown";
  const title = alert.summary || alert.alertName || "Prometheus 告警";
  const meta = [
    alert.alertName,
    stateLabel,
    alert.activeAt ? `开始 ${formatDateTime(alert.activeAt)}` : "",
    alert.value ? `值 ${alert.value}` : "",
  ].filter(Boolean).join(" / ");
  return `
    <article class="prometheus-alert-item ${escapeHtml(severity)}">
      <div class="prometheus-alert-item-head">
        <strong>${escapeHtml(title)}</strong>
        <span>${escapeHtml(severity)}</span>
      </div>
      <p class="muted">${escapeHtml(meta)}</p>
      ${alert.description ? `<p>${escapeHtml(alert.description)}</p>` : ""}
      <p class="alert-action">应急建议：${escapeHtml(alert.actionHint || "查看 Prometheus 告警详情并按应急处置执行。")}</p>
    </article>
  `;
}

function renderPrometheusRules() {
  const panel = $("#prometheusRulesPanel");
  const rules = state.prometheusRules?.rules || [];
  const summary = state.prometheusRules?.summary || {
    expected: 0,
    loaded: 0,
    missing: 0,
    unhealthy: 0,
    missingRules: [],
    unhealthyRules: [],
  };
  if (!state.prometheusRules) {
    panel.classList.add("hidden");
    $("#prometheusRulesList").innerHTML = "";
    return;
  }

  const level = state.prometheusRules.available === false
    ? "warning"
    : summary.missing || summary.unhealthy
      ? "critical"
      : "ok";
  panel.className = `prometheus-rules-panel ${level}`;
  $("#prometheusRulesBadge").className = `prometheus-rules-badge ${level}`;
  $("#prometheusRulesBadge").textContent = String(summary.missing || summary.unhealthy || summary.loaded || 0);
  $("#prometheusRulesSummary").textContent = state.prometheusRules.available === false
    ? `规则接口不可用：${state.prometheusRules.message || "未知错误"}`
    : `预期 ${summary.expected || 0} 条，已加载 ${summary.loaded || 0} 条，缺失 ${summary.missing || 0} 条，异常 ${summary.unhealthy || 0} 条`;

  if (state.prometheusRules.available === false) {
    $("#prometheusRulesList").innerHTML = `
      <article class="prometheus-rule-item warning">
        <div class="prometheus-rule-item-head">
          <strong>规则健康不可确认</strong>
          <span>warning</span>
        </div>
        <p>${escapeHtml(state.prometheusRules.message || "")}</p>
        <p class="alert-action">应急建议：检查 Prometheus /api/v1/rules、规则文件路径和 Prometheus reload 日志。</p>
      </article>
    `;
    return;
  }

  const missingCards = (summary.missingRules || []).map((name) => `
    <article class="prometheus-rule-item critical">
      <div class="prometheus-rule-item-head">
        <strong>${escapeHtml(name)}</strong>
        <span>missing</span>
      </div>
      <p class="alert-action">应急建议：确认 ops-alerts.yml 已写入 Prometheus rule_files，并 reload Prometheus。</p>
    </article>
  `);
  const ruleCards = rules.map(prometheusRuleCard);
  $("#prometheusRulesList").innerHTML = missingCards.concat(ruleCards).join("");
}

function prometheusRuleCard(rule) {
  const health = rule.health || "unknown";
  const level = health === "ok" ? "ok" : "critical";
  const meta = [
    rule.group ? `group ${rule.group}` : "",
    rule.file ? `file ${rule.file}` : "",
    rule.state ? `state ${rule.state}` : "",
  ].filter(Boolean).join(" / ");
  return `
    <article class="prometheus-rule-item ${escapeHtml(level)}">
      <div class="prometheus-rule-item-head">
        <strong>${escapeHtml(rule.name || "Prometheus rule")}</strong>
        <span>${escapeHtml(health)}</span>
      </div>
      ${meta ? `<p class="muted">${escapeHtml(meta)}</p>` : ""}
      ${rule.lastError ? `<p>${escapeHtml(rule.lastError)}</p>` : ""}
    </article>
  `;
}

function renderUnmanagedTargets() {
  const panel = $("#unmanagedTargetsPanel");
  const targets = state.dashboard?.unmanagedTargets || [];
  if (!targets.length) {
    panel.classList.add("hidden");
    $("#unmanagedTargetsList").innerHTML = "";
    return;
  }

  panel.className = "unmanaged-targets-panel warning";
  $("#unmanagedTargetsBadge").textContent = String(targets.length);
  $("#unmanagedTargetsSummary").textContent = `未纳管目标清单：Prometheus 正在采集 ${targets.length} 个未纳管目标，需要补录到配置或清理过期 scrape。`;
  $("#unmanagedTargetsList").innerHTML = targets.map(unmanagedTargetCard).join("");
  $("#unmanagedTargetsList").querySelectorAll("[data-copy-unmanaged-config]").forEach((button) => {
    button.addEventListener("click", () => copySuggestedConfig(Number(button.dataset.copyUnmanagedConfig), button));
  });
}

function unmanagedTargetCard(target, index) {
  const suggestedLabels = target.suggestedLabels || {};
  const suggestedConfig = target.suggestedConfig || {};
  const configText = suggestedConfig.json || "";
  const sectionText = suggestedConfig.section
    ? `config/servers.local.json -> ${suggestedConfig.section}[]`
    : "config/servers.local.json";
  const labelsText = Object.entries(suggestedLabels)
    .map(([key, value]) => `${key}=${value}`)
    .join(", ");
  const meta = [
    target.job ? `job ${target.job}` : "",
    target.instance ? `instance ${target.instance}` : "",
    target.health ? `状态 ${target.health}` : "",
    target.suggestedType ? `建议 ${target.suggestedType}` : "",
  ].filter(Boolean).join(" / ");
  return `
    <article class="unmanaged-target-item">
      <div class="unmanaged-target-item-head">
        <strong>${escapeHtml(target.name || target.instance || "未纳管目标")}</strong>
        <span>${escapeHtml(target.suggestedType || "target")}</span>
      </div>
      <p class="muted">${escapeHtml(meta)}</p>
      ${target.lastError ? `<p>${escapeHtml(target.lastError)}</p>` : ""}
      <p class="target-labels">建议标签：${escapeHtml(labelsText || "缺少可用标签")}</p>
      ${configText ? `
        <div class="config-snippet">
          <div class="config-snippet-head">
            <span>${escapeHtml(sectionText)}</span>
            <button type="button" class="secondary recovery-trigger compact" data-copy-unmanaged-config="${escapeHtml(String(index))}">复制配置片段</button>
          </div>
          <pre>${escapeHtml(configText)}</pre>
        </div>
      ` : ""}
      <p class="alert-action">处理建议：${escapeHtml(target.actionHint || "补录到 config/servers.local.json，或从 Prometheus scrape 配置移除。")}</p>
    </article>
  `;
}

async function copySuggestedConfig(index, button) {
  const target = (state.dashboard?.unmanagedTargets || [])[index];
  const text = target?.suggestedConfig?.json || "";
  if (!text) return;

  const originalText = button.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = "已复制";
  } catch (_error) {
    button.textContent = "复制失败，请手动复制";
  } finally {
    window.setTimeout(() => {
      button.textContent = originalText;
    }, 2000);
  }
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
  $("#emergencyRunbookList").querySelectorAll("[data-emergency-cert-renewal-disable]").forEach((button) => {
    button.addEventListener("click", () => toggleCertRenewal(button.dataset.websiteId, false));
  });
  $("#emergencyRunbookList").querySelectorAll("[data-emergency-manual-backup]").forEach((button) => {
    button.addEventListener("click", () => openManualBackupDialog(button.dataset.serverId));
  });
  $("#emergencyRunbookList").querySelectorAll("[data-emergency-manual-recovery]").forEach((button) => {
    button.addEventListener("click", () => openManualRecoveryDialog(button.dataset.targetType, button.dataset.targetId));
  });
  $("#emergencyRunbookList").querySelectorAll("[data-emergency-auto-recovery-disable]").forEach((button) => {
    button.addEventListener("click", () => toggleAutoRecovery(button.dataset.targetType, button.dataset.targetId, false));
  });
  $("#emergencyRunbookList").querySelectorAll("[data-emergency-resource-ack]").forEach((button) => {
    button.addEventListener("click", () => acknowledgeResourceExpiry(button.dataset.resourceId));
  });
}

function emergencyActionButton(item) {
  if (["server", "website"].includes(item.targetType)) {
    const configTargets = item.targetType === "server" ? (state.config?.servers || []) : (state.config?.websites || []);
    const dashboardTargets = item.targetType === "server" ? (state.dashboard?.servers || []) : (state.dashboard?.websites || []);
    const target = configTargets.find((candidate) => candidate.id === item.targetId);
    const dashboardTarget = dashboardTargets.find((candidate) => candidate.id === item.targetId);
    const targetId = target?.id || dashboardTarget?.id || item.targetId;
    const manualRecovery = target?.manualRecovery;
    const autoRecovery = dashboardTarget?.autoRecovery || target?.autoRecovery;
    const actions = [];
    if (manualRecovery?.available) {
      actions.push(`<button type="button" class="secondary recovery-trigger compact" data-emergency-manual-recovery="true" data-target-type="${escapeHtml(item.targetType)}" data-target-id="${escapeHtml(targetId)}">${escapeHtml(manualRecovery.label || "手动恢复")}</button>`);
    }
    if (autoRecovery?.enabled && autoRecovery?.status === "failed") {
      actions.push(`<button type="button" class="secondary recovery-trigger compact high" data-emergency-auto-recovery-disable="true" data-target-type="${escapeHtml(item.targetType)}" data-target-id="${escapeHtml(targetId)}">暂停自动恢复</button>`);
    }
    return actions.join("");
  }
  if (item.targetType === "website-cert") {
    const website = (state.config?.websites || []).find((candidate) => candidate.id === item.targetId);
    const manualCertRenewal = website?.manualCertRenewal;
    const actions = [];
    if (manualCertRenewal?.available) {
      actions.push(`<button type="button" class="secondary recovery-trigger compact" data-emergency-manual-cert-renewal="true" data-website-id="${escapeHtml(website.id)}">${escapeHtml(manualCertRenewal.label || "手动续期")}</button>`);
    }
    if (website?.certRenewal?.enabled) {
      actions.push(`<button type="button" class="secondary recovery-trigger compact high" data-emergency-cert-renewal-disable="true" data-website-id="${escapeHtml(website.id)}">暂停自动续期</button>`);
    }
    return actions.join("");
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
    if (canAcknowledgeResource(resource)) {
      actions.push(`<button type="button" class="secondary recovery-trigger compact" data-emergency-resource-ack="true" data-resource-id="${escapeHtml(resource.id)}">确认 7 天</button>`);
    }
    return actions.join("");
  }
  return "";
}

function certRenewalRiskItems() {
  return (state.dashboard?.websites || []).filter((website) => {
    const certRenewal = website.certRenewal || {};
    if (!certRenewal || certRenewal.notApplicable) return false;

    const status = certRenewal.status || "idle";
    if (["failed", "blocked", "verifying"].includes(status)) return true;

    const expiresInDays = Number(certRenewal.expiresInDays);
    if (!Number.isFinite(expiresInDays)) return Boolean(certRenewal.enabled);

    const renewBeforeDays = Number(certRenewal.renewBeforeDays ?? 14);
    const threshold = Number.isFinite(renewBeforeDays) ? renewBeforeDays : 14;
    if (expiresInDays <= threshold) return true;
    return !certRenewal.enabled && expiresInDays <= 30;
  });
}

function renderCertRenewalRisks() {
  const panel = $("#certRenewalRiskPanel");
  const items = certRenewalRiskItems();
  if (!items.length) {
    panel.classList.add("hidden");
    $("#certRenewalRiskList").innerHTML = "";
    return;
  }

  panel.className = "cert-renewal-risk-panel warning";
  $("#certRenewalRiskBadge").textContent = String(items.length);
  $("#certRenewalRiskSummary").textContent = `发现 ${items.length} 个证书续期风险，需确认自动续期动作、证书剩余天数或手动续期结果。`;
  $("#certRenewalRiskList").innerHTML = items.map(certRenewalRiskCard).join("");
  $("#certRenewalRiskList").querySelectorAll("[data-cert-risk-manual-renewal]").forEach((button) => {
    button.addEventListener("click", () => openManualCertRenewalDialog(button.dataset.websiteId));
  });
}

function certRenewalRiskCard(website) {
  const certRenewal = website.certRenewal || {};
  const manualCertRenewal = website.manualCertRenewal || {};
  const status = certRenewal.status || "idle";
  const expiresText = certRenewal.expiresInDays === null || certRenewal.expiresInDays === undefined
    ? "证书天数未知"
    : `剩余 ${certRenewal.expiresInDays} 天`;
  const reason = certRenewalRiskReason(certRenewal);
  const manualButton = manualCertRenewal.available
    ? `<button type="button" class="secondary recovery-trigger compact" data-cert-risk-manual-renewal="true" data-website-id="${escapeHtml(website.id)}">${escapeHtml(manualCertRenewal.label || "手动续期")}</button>`
    : "";
  return `
    <article class="cert-renewal-risk-item ${escapeHtml(status)}">
      <div class="cert-renewal-risk-item-head">
        <strong>${escapeHtml(website.name || website.id || "未命名网站")}</strong>
        <span>${escapeHtml(certRenewalLabels[status] || status)}</span>
      </div>
      <p class="muted">${escapeHtml([website.url, expiresText, `提前 ${certRenewal.renewBeforeDays ?? 14} 天续期`].filter(Boolean).join(" / "))}</p>
      <p>${escapeHtml(reason)}</p>
      ${certRenewal.message ? `<p class="alert-action">${escapeHtml(certRenewal.message)}</p>` : ""}
      ${manualButton ? `<div class="cert-renewal-risk-actions">${manualButton}</div>` : ""}
    </article>
  `;
}

function certRenewalRiskReason(certRenewal) {
  const status = certRenewal.status || "idle";
  if (status === "failed") return "最近一次证书续期失败，需要查看恢复日志并手动确认。";
  if (status === "blocked") return "自动续期被策略或数据质量阻断，执行前需要修正配置或监控数据。";
  if (status === "verifying") return "续期命令已执行，正在等待证书到期时间延长确认。";
  if (certRenewal.expiresInDays === null || certRenewal.expiresInDays === undefined) {
    return "证书剩余天数未知，自动判断不可信。";
  }
  if (!certRenewal.enabled) return "证书接近到期，但自动续期未启用。";
  return "证书已进入自动续期窗口，需要确认续期动作可执行。";
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
  $("#resourceExpiryList").querySelectorAll("[data-resource-edit]").forEach((button) => {
    button.addEventListener("click", () => populateResourceForm(button.dataset.resourceId));
  });
  $("#resourceExpiryList").querySelectorAll("[data-resource-delete]").forEach((button) => {
    button.addEventListener("click", () => deleteResourceExpiryRecord(button.dataset.resourceId));
  });
}

function resourceDateInputValue(value) {
  return String(value || "").slice(0, 10);
}

function resetResourceForm() {
  $("#resourceExpiryForm").reset();
  $("#resourceId").readOnly = false;
  $("#resourceFormError").textContent = "";
}

function populateResourceForm(resourceId) {
  const item = (state.dashboard?.resourceExpiryItems || []).find((candidate) => candidate.id === resourceId);
  if (!item) return;
  $("#resourceId").value = item.id || "";
  $("#resourceId").readOnly = true;
  $("#resourceName").value = item.name || "";
  $("#resourceType").value = item.type || "resource";
  $("#resourceExpiresAt").value = resourceDateInputValue(item.expiresAt);
  $("#resourceProvider").value = item.provider || "";
  $("#resourceOwner").value = item.owner || "";
  $("#resourceRenewUrl").value = item.renewUrl || "";
  $("#resourceNotes").value = item.notes || "";
  $("#resourceFormError").textContent = "";
}

function resourceFormPayload() {
  return {
    id: $("#resourceId").value.trim(),
    name: $("#resourceName").value.trim(),
    type: $("#resourceType").value,
    expiresAt: $("#resourceExpiresAt").value,
    provider: $("#resourceProvider").value.trim(),
    owner: $("#resourceOwner").value.trim(),
    renewUrl: $("#resourceRenewUrl").value.trim(),
    notes: $("#resourceNotes").value.trim(),
  };
}

async function submitResourceForm(event) {
  event.preventDefault();
  $("#resourceFormError").textContent = "";
  const button = $("#resourceSaveButton");
  button.disabled = true;
  try {
    await saveResourceExpiryRecord(resourceFormPayload());
    resetResourceForm();
  } catch (error) {
    $("#resourceFormError").textContent = error.payload?.message || error.message;
  } finally {
    button.disabled = false;
  }
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
  const diagnostics = quality.details?.targetDiagnostics;
  const diagnosticsText = diagnostics?.message
    ? `${diagnostics.category || "target"}: ${diagnostics.message}${diagnostics.lastError ? ` (${diagnostics.lastError})` : ""}`
    : "";
  const actionHintText = diagnostics ? diagnostics.actionHint || "" : "";
  return `<div class="quality-block ${escapeHtml(level)} ${trusted ? "trusted" : "untrusted"}">
    <div class="quality-head">
      <strong>${escapeHtml(title)}</strong>
      <span>${escapeHtml(trustText)}</span>
    </div>
    <p>${escapeHtml(quality.message || "暂无数据质量说明")}</p>
    ${diagnosticsText ? `<p class="quality-diagnostics">${escapeHtml(diagnosticsText)}</p>` : ""}
    ${actionHintText ? `<p class="quality-diagnostics">建议：${escapeHtml(actionHintText)}</p>` : ""}
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

function canAcknowledgeResource(item) {
  const status = item.status || "";
  return item.actionRequired && item.handlingReady !== false && ["critical", "warning"].includes(status);
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
  const canAcknowledge = canAcknowledgeResource(item);
  const ackActorText = item.acknowledgedBy ? `，确认人 ${item.acknowledgedBy}` : "";
  const ackAtText = item.acknowledgedAt ? `，确认时间 ${formatDateTime(item.acknowledgedAt)}` : "";
  const ackText = item.acknowledged
    ? `已确认至 ${formatDate(item.acknowledgedUntil)}${ackActorText}${ackAtText}`
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
  const manageButtons = `
    <button type="button" class="secondary recovery-trigger compact" data-resource-edit="true" data-resource-id="${escapeHtml(item.id)}">编辑</button>
    <button type="button" class="secondary recovery-trigger compact high" data-resource-delete="true" data-resource-id="${escapeHtml(item.id)}">删除</button>
  `;
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
    <div class="expiry-notes">${item.notes ? `<span>${escapeHtml(item.notes)}</span>` : ""}${handlingWarning ? `<span>${escapeHtml(handlingWarning)}</span>` : ""}${ackText ? `<span>${escapeHtml(ackText)}</span>` : ""}${renewLink}${ackButton}${manageButtons}</div>
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
  const statusText = certRenewal.notApplicable ? "不适用" : (certRenewal.enabled ? (certRenewalLabels[status] || status) : "未启用");
  const expireText = certRenewal.notApplicable
    ? "HTTP 无 HTTPS 证书"
    : (certRenewal.expiresInDays === null || certRenewal.expiresInDays === undefined
      ? "证书天数未知"
      : `剩余 ${certRenewal.expiresInDays} 天`);
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
  const actorName = log.actor?.displayName || log.actor?.username || "";
  const actorRole = log.actor?.role || "";
  const actorText = actorName ? `${actorName}${actorRole ? ` (${actorRole})` : ""}` : "系统/未记录";
  const output = [
    log.message || "",
    `原因: ${log.reason || "--"}`,
    `目标: ${log.targetName || log.targetId || "--"}`,
    `动作: ${log.actionName || log.actionId || "--"}`,
    `方式: ${invocationText}`,
    `操作者: ${actorText}`,
    `来源 IP: ${log.sourceIp || "--"}`,
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
$("#resourceExpiryForm").addEventListener("submit", submitResourceForm);
$("#resourceResetButton").addEventListener("click", resetResourceForm);
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

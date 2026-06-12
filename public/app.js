const state = {
  config: null,
  dashboard: null,
  selectedGroup: "全部",
  chartMetric: "cpu",
  currentAction: null,
  refreshTimer: null,
};

const $ = (selector) => document.querySelector(selector);

const metricLabels = {
  cpu: "CPU",
  memory: "内存",
  disk: "磁盘",
  rx: "入站",
  tx: "出站",
  load: "负载",
  uptime: "运行",
};

const healthLabels = {
  healthy: "正常",
  warning: "告警",
  down: "异常",
  unknown: "未知",
};

const serverTypeLabels = {
  physical: "物理服务器",
  virtual: "虚拟机",
};

const recoveryLabels = {
  idle: "空闲",
  waiting: "等待触发",
  blocked: "配置阻塞",
  triggered: "已执行",
  failed: "执行失败",
};

const backupLabels = {
  idle: "空闲",
  waiting: "等待备份",
  blocked: "配置阻塞",
  triggered: "已备份",
  failed: "备份失败",
};

const certRenewalLabels = {
  idle: "空闲",
  waiting: "等待续期",
  blocked: "配置阻塞",
  triggered: "已续期",
  failed: "续期失败",
};

function formatPercent(value) {
  if (value === null || value === undefined || Number.isNaN(value)) return "--";
  return `${Math.max(0, value).toFixed(1)}%`;
}

function formatBytesPerSecond(value) {
  if (value === null || value === undefined || Number.isNaN(value)) return "--";
  const units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
  let size = Math.max(0, value);
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function formatDuration(seconds) {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) return "--";
  const day = 86400;
  const hour = 3600;
  if (seconds >= day) return `${Math.floor(seconds / day)} 天`;
  if (seconds >= hour) return `${Math.floor(seconds / hour)} 小时`;
  return `${Math.floor(seconds / 60)} 分钟`;
}

function formatSeconds(value) {
  if (value === null || value === undefined || Number.isNaN(value)) return "--";
  return `${value.toFixed(value >= 10 ? 1 : 2)}s`;
}

function formatStatusCode(value) {
  if (value === null || value === undefined || Number.isNaN(value)) return "--";
  return String(Math.trunc(value));
}

function formatCert(value) {
  if (value === null || value === undefined || Number.isNaN(value)) return "--";
  if (value <= 0) return "已过期";
  return `${Math.floor(value / 86400)} 天`;
}

function formatTime(value) {
  if (!value) return "--";
  return new Date(value * 1000).toLocaleString("zh-CN", { hour12: false });
}

function metricValue(metric, value) {
  if (["cpu", "memory", "disk"].includes(metric)) return formatPercent(value);
  if (["rx", "tx"].includes(metric)) return formatBytesPerSecond(value);
  if (metric === "load") return value === null || value === undefined ? "--" : value.toFixed(2);
  if (metric === "uptime") return formatDuration(value);
  return value ?? "--";
}

function statusText(status) {
  if (status === "online") return "在线";
  if (status === "offline") return "离线";
  return "未知";
}

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

async function getJson(url, options) {
  const response = await fetch(url, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload.ok === false) {
    const error = new Error(payload.message || `HTTP ${response.status}`);
    error.payload = payload;
    throw error;
  }
  return payload;
}

async function loadConfig() {
  const payload = await getJson("/api/config");
  state.config = payload.config;
  $("#appName").textContent = state.config.appName || "本地服务器监控台";
  $("#prometheusUrl").textContent = state.config.prometheusUrl || "";
  $("#tokenInput").classList.toggle("hidden", !state.config.actionsRequireToken);
  document.querySelector(".token-field span").classList.toggle("hidden", !state.config.actionsRequireToken);
}

async function refreshDashboard() {
  $("#refreshButton").disabled = true;
  try {
    state.dashboard = await getJson("/api/dashboard");
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
  $("#recoveryLogList").innerHTML = "";
  $("#emptyState").classList.remove("hidden");
  $("#websiteEmptyState").classList.add("hidden");
  $("#recoveryLogEmptyState").classList.add("hidden");
  $("#emptyState h2").textContent = "无法读取监控数据";
  $("#emptyState p").textContent = error.message;
}

function render() {
  const summary = state.dashboard?.summary || { total: 0, online: 0, offline: 0, unknown: 0 };
  const websiteSummary = state.dashboard?.websiteSummary || { total: 0, online: 0, offline: 0, unknown: 0 };
  $("#totalCount").textContent = summary.total;
  $("#onlineCount").textContent = summary.online;
  $("#offlineCount").textContent = summary.offline;
  $("#unknownCount").textContent = summary.unknown;
  $("#websiteTotalCount").textContent = websiteSummary.total;
  $("#websiteOnlineCount").textContent = websiteSummary.online;
  $("#websiteOfflineCount").textContent = websiteSummary.offline;
  $("#websiteUnknownCount").textContent = websiteSummary.unknown;
  $("#lastUpdated").textContent = new Date((state.dashboard?.generatedAt || Date.now() / 1000) * 1000)
    .toLocaleTimeString("zh-CN", { hour12: false });

  renderGroups();
  renderServers();
  renderWebsites();
  renderRecoveryLogs();
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
    ${issuesBlock(server.issues)}
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
    ${issuesBlock(website.issues)}
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

function issuesBlock(issues = []) {
  if (!issues.length) return "";
  return `<div class="issues">
    ${issues.map((issue) => `<span>${escapeHtml(issue)}</span>`).join("")}
  </div>`;
}

function recoveryBlock(recovery, manualRecovery, targetType, targetId) {
  if (!recovery) return "";
  const manualButton = manualRecovery?.available
    ? `<button type="button" class="secondary recovery-trigger compact" data-manual-recovery="true" data-target-type="${escapeHtml(targetType)}" data-target-id="${escapeHtml(targetId)}">${escapeHtml(manualRecovery.label || "手动执行")}</button>`
    : "";
  const status = recovery.status || "idle";
  const statusText = recovery.enabled ? (recoveryLabels[status] || status) : "未启用";
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
      <span>最近执行 ${escapeHtml(formatTime(recovery.lastCompletedAt))}</span>
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
      <span>最近备份 ${escapeHtml(formatTime(autoBackup.lastCompletedAt))}</span>
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
  return `<div class="recovery-block">
    <div class="recovery-head">
      <strong>证书续期</strong>
      <span class="recovery-badge ${escapeHtml(status)}">${escapeHtml(statusText)}</span>
    </div>
    <div class="recovery-meta">
      <span>${escapeHtml(expireText)}</span>
      <span>提前 ${escapeHtml(String(certRenewal.renewBeforeDays ?? 14))} 天续期</span>
      <span>最近续期 ${escapeHtml(formatTime(certRenewal.lastCompletedAt))}</span>
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
    manual: "手动执行",
    "manual-recovery": "手动恢复",
    "auto-backup": "自动备份",
    "manual-backup": "手动备份",
    "auto-cert": "自动续期",
    "manual-cert": "手动续期",
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
  await Promise.all(canvases.map(async (canvas) => {
    try {
      const payload = await getJson(`/api/series?serverId=${encodeURIComponent(canvas.dataset.chartServer)}&metric=${encodeURIComponent(state.chartMetric)}&minutes=60`);
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

function openActionDialog(serverId, actionId, meta = {}) {
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

function openManualRecoveryDialog(targetType, targetId) {
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

function openManualCertRenewalDialog(websiteId) {
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

function openManualBackupDialog(serverId) {
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

async function toggleAutoRecovery(targetType, targetId, enabled) {
  try {
    const payload = await getJson("/api/settings/auto-recovery", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ targetType, targetId, enabled }),
    });
    state.dashboard = payload;
    state.dashboard.ok = true;
    await loadConfig();
    render();
  } catch (error) {
    await refreshDashboard();
  }
}

async function toggleAutoBackup(serverId, enabled) {
  try {
    const payload = await getJson("/api/settings/auto-backup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ serverId, enabled }),
    });
    state.dashboard = payload;
    state.dashboard.ok = true;
    await loadConfig();
    render();
  } catch (error) {
    await refreshDashboard();
  }
}

async function runCurrentAction() {
  const { server, action, meta = {} } = state.currentAction;
  const button = $("#runActionButton");
  button.disabled = true;
  button.textContent = "执行中";
  try {
    const payload = await getJson("/api/actions/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        serverId: server.id,
        actionId: action.id,
        token: $("#tokenInput").value,
        confirm: $("#confirmInput").value,
        targetType: meta.targetType || "server",
        targetId: meta.targetId || server.id,
        targetName: meta.targetName || server.name || server.id,
        invocation: meta.invocation || "manual",
        reason: meta.reason || "手动执行",
      }),
    });
    const output = [
      payload.message,
      payload.logId ? `日志ID: ${payload.logId}` : "",
      `退出码: ${payload.returnCode ?? "-"}`,
      `耗时: ${payload.durationSeconds ?? "-"}s`,
      "",
      payload.stdout ? `STDOUT\n${payload.stdout}` : "",
      payload.stderr ? `STDERR\n${payload.stderr}` : "",
    ].filter(Boolean).join("\n");
    $("#actionOutput").textContent = output;
    $("#actionOutput").classList.remove("hidden");
  } catch (error) {
    const payload = error.payload || {};
    const output = [
      payload.message || error.message,
      payload.logId ? `日志ID: ${payload.logId}` : "",
      `退出码: ${payload.returnCode ?? "-"}`,
      `耗时: ${payload.durationSeconds ?? "-"}s`,
      "",
      payload.stdout ? `STDOUT\n${payload.stdout}` : "",
      payload.stderr ? `STDERR\n${payload.stderr}` : "",
    ].filter(Boolean).join("\n");
    $("#actionOutput").textContent = output || error.message;
    $("#actionOutput").classList.remove("hidden");
  } finally {
    await refreshDashboard();
    button.disabled = false;
    button.textContent = "执行";
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function camelToKebab(value) {
  return String(value).replace(/[A-Z]/g, (match) => `-${match.toLowerCase()}`);
}

$("#refreshButton").addEventListener("click", refreshDashboard);
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

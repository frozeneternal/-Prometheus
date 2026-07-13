import { $, escapeHtml } from "./dom.js";
import { targetDiagnosticLabels } from "./format.js";
import { state } from "./state.js";

export function renderSystemNotice() {
  const notice = $("#systemNotice");
  const messages = [];
  const prometheus = state.dashboard?.prometheus;
  const coverage = state.dashboard?.targetCoverage;
  const issueSummary = state.dashboard?.targetIssueSummary;
  const dataQualitySummary = state.dashboard?.dataQualitySummary;
  const exporterDiagnostics = state.dashboard?.exporterDiagnostics;
  const platformHealth = state.dashboard?.platformHealth;
  const emergencySummary = state.dashboard?.emergencySummary;
  const recoverySummary = state.dashboard?.recoverySummary;
  const backupSummary = state.dashboard?.backupSummary;
  const incidentSummary = state.dashboard?.incidentSummary;
  const certRenewalSummary = state.dashboard?.certRenewalSummary;
  const resourceExpirySummary = state.dashboard?.resourceExpirySummary;
  const accountSecurity = state.dashboard?.accountSecurity;
  const accountRuntimeSecurity = state.dashboard?.accountRuntimeSecurity;
  const actionSafetySummary = state.dashboard?.actionSafetySummary;
  const configSource = state.dashboard?.configSource || {};
  const dashboardGeneratedAt = Number(state.dashboard?.generatedAt || 0);
  const pollIntervalSeconds = Number(state.config?.monitoring?.pollIntervalSeconds || 30);
  const snapshotStaleAfterSeconds = Math.max(30, pollIntervalSeconds * 3);
  const snapshotAgeSeconds = dashboardGeneratedAt > 0
    ? Math.max(0, Math.floor(Date.now() / 1000 - dashboardGeneratedAt))
    : 0;

  if (prometheus && !prometheus.available) {
    const detail = prometheus.error ? `（${prometheus.error}）` : "";
    messages.push(`Prometheus 当前不可用：${prometheus.message || "无法连接采集服务"}${detail}。这会导致所有目标显示“未知”，不代表服务器全部宕机。`);
  }

  if (dashboardGeneratedAt > 0 && snapshotAgeSeconds > snapshotStaleAfterSeconds) {
    messages.push(`数据刷新：页面快照已 ${snapshotAgeSeconds} 秒未刷新，超过 ${snapshotStaleAfterSeconds} 秒阈值；请先刷新页面或检查后台轮询。`);
  }

  if (coverage) {
    if (coverage.prometheusAvailable === false) {
      messages.push(`Prometheus 覆盖：采集器不可用，${coverage.unknown ?? coverage.total ?? 0} 个配置目标无法核验。`);
    } else {
      messages.push(`Prometheus 覆盖：已匹配 ${coverage.matched ?? 0}/${coverage.total ?? 0}，缺失 ${coverage.missing ?? 0}，异常 ${coverage.unhealthy ?? 0}，未纳管 ${coverage.unmanaged ?? 0}。`);
    }
  }

  if (issueSummary?.total) {
    const issueCategories = issueSummary.categories || [];
    const categoryText = issueCategories
      .map((category) => `${targetDiagnosticLabels[category.category] || category.category} ${category.count}`)
      .join("，");
    messages.push(`Prometheus 异常原因：${categoryText || `${issueSummary.total} 个目标异常`}。`);
  }

  if (dataQualitySummary && dataQualitySummary.status !== "ok") {
    messages.push(`数据可信度：可信 ${dataQualitySummary.trusted ?? 0}/${dataQualitySummary.total ?? 0}，不可信 ${dataQualitySummary.untrusted ?? 0}，部分可信 ${dataQualitySummary.partial ?? 0}。自动恢复只会使用可信监控数据。`);
  }

  if (exporterDiagnostics?.summary) {
    const diagnosticSummary = exporterDiagnostics.summary;
    const staleText = exporterDiagnostics.stale
      ? `，使用上次成功结果${exporterDiagnostics.error ? `（${exporterDiagnostics.error}）` : ""}`
      : "";
    messages.push(`Exporter 诊断：需处理 ${diagnosticSummary.actionRequired ?? 0}，指标正常 ${diagnosticSummary.metricsOpen ?? 0}，SSH 隧道覆盖 ${diagnosticSummary.coveredByTunnel ?? 0}${staleText}。`);
  }

  if (platformHealth && platformHealth.status !== "ok") {
    const platformIssues = platformHealth.issues || [];
    const platformCriticalIssues = platformIssues.filter((issue) => ["critical", "error"].includes(issue.severity)).length;
    const platformWarningIssues = platformIssues.filter((issue) => issue.severity === "warning").length;
    messages.push(`平台健康：${platformHealth.status}，严重 ${platformCriticalIssues}，预警 ${platformWarningIssues}，总问题 ${platformIssues.length}。`);
  }

  if ((emergencySummary?.total ?? 0) > 0) {
    messages.push(`应急事项：待处理 ${emergencySummary.total ?? 0}，严重 ${emergencySummary.critical ?? 0}，预警 ${emergencySummary.warning ?? 0}。`);
  }

  if (recoverySummary) {
    messages.push(`自动恢复：已启用 ${recoverySummary.enabled ?? 0}/${recoverySummary.total ?? 0}，阻断 ${recoverySummary.blocked ?? 0}，等待 ${recoverySummary.waiting ?? 0}，失败 ${recoverySummary.failed ?? 0}，中断中 ${recoverySummary.activeIncidents ?? 0}。`);
  }

  if (backupSummary) {
    messages.push(`自动备份：已启用 ${backupSummary.enabled ?? 0}/${backupSummary.total ?? 0}，阻断 ${backupSummary.blocked ?? 0}，等待 ${backupSummary.waiting ?? 0}，失败 ${backupSummary.failed ?? 0}。`);
  }

  if (incidentSummary) {
    const activeIncidentNames = (incidentSummary.items || [])
      .slice(0, 3)
      .map((item) => item.targetName || item.targetId)
      .filter(Boolean)
      .join("，");
    const overflowText = (incidentSummary.active || 0) > 3 ? ` 等 ${incidentSummary.active} 个` : "";
    const activeText = activeIncidentNames ? `（${activeIncidentNames}${overflowText}）` : "";
    messages.push(`中断事件：中断中 ${incidentSummary.active ?? 0}${activeText}，已恢复 ${incidentSummary.recovered ?? 0}。`);
  }

  if (certRenewalSummary) {
    messages.push(`证书续期：已启用 ${certRenewalSummary.enabled ?? 0}/${certRenewalSummary.total ?? 0}，失败 ${certRenewalSummary.failed ?? 0}，阻断 ${certRenewalSummary.blocked ?? 0}，即将到期 ${certRenewalSummary.expiring ?? 0}，证书天数未知 ${certRenewalSummary.unknownExpiry ?? 0}。`);
  }

  if (resourceExpirySummary?.status === "unconfigured") {
    messages.push(`资源到期：${resourceExpirySummary.message || "未配置任何资源到期记录，资源到期告警尚未覆盖真实资产。"}。`);
  } else if ((resourceExpirySummary?.actionRequired ?? 0) > 0) {
    messages.push(`资源到期：需处理 ${resourceExpirySummary.actionRequired ?? 0}/${resourceExpirySummary.total ?? 0}，已过期 ${resourceExpirySummary.expired ?? 0}，严重 ${resourceExpirySummary.critical ?? 0}，预警 ${resourceExpirySummary.warning ?? 0}，未知 ${resourceExpirySummary.unknown ?? 0}，缺处置入口 ${resourceExpirySummary.actionRequiredWithoutHandling ?? 0}。`);
  }

  if (accountSecurity && accountSecurity.severity !== "ok") {
    const accountIssueCount = (accountSecurity.issues || []).length;
    const accountSeverityText = accountSecurity.severity === "error" ? "严重" : "预警";
    messages.push(`账号安全：${accountSeverityText}，启用账号 ${accountSecurity.enabledUsers ?? 0}，管理员 ${accountSecurity.adminUsers ?? 0}，运维账号 ${accountSecurity.operatorUsers ?? 0}，问题 ${accountIssueCount}。`);
  }

  if (accountRuntimeSecurity && accountRuntimeSecurity.status !== "ok") {
    messages.push(`账号运行态：锁定 ${accountRuntimeSecurity.lockedUsers ?? 0}，失败账号 ${accountRuntimeSecurity.failedUsers ?? 0}，失败次数 ${accountRuntimeSecurity.recentFailures ?? 0}，撤销会话 ${accountRuntimeSecurity.revokedSessions ?? 0}。`);
  }

  if (actionSafetySummary && actionSafetySummary.status !== "ok") {
    messages.push(`动作安全：动作 ${actionSafetySummary.total ?? 0}，自动 ${actionSafetySummary.allowAuto ?? 0}，高危 ${actionSafetySummary.highDanger ?? 0}，需处理 ${actionSafetySummary.actionRequired ?? 0}。`);
  }

  if (!configSource.usingLocalConfig) {
    messages.push(`当前加载 ${configSource.configFile || "config/servers.json"}。这是公开/示例配置；真实内网配置建议放到 config/servers.local.json。`);
  } else {
    messages.push(`当前加载本地私有配置 ${configSource.configFile}。`);
  }

  notice.classList.toggle("hidden", messages.length === 0);
  notice.innerHTML = messages.map((message) => `<p>${escapeHtml(message)}</p>`).join("");
}

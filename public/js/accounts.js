import {
  fetchAccountAudit,
  fetchAccountLockouts,
  fetchAccountUsers,
  fetchDashboard,
  fetchSession,
  loginUser,
  logoutSession,
  removeAccountUser,
  saveAccountUser as saveAccountUserRequest,
  unlockAccount,
} from "./client.js";
import { $, escapeHtml } from "./dom.js";
import { formatElapsed, formatTime } from "./format.js";
import { state } from "./state.js";

export async function refreshSession() {
  const auth = state.config?.auth || {};
  if (auth.mode !== "users") {
    state.currentUser = null;
    return;
  }
  if (!state.sessionToken) {
    state.currentUser = null;
    return;
  }
  try {
    const payload = await fetchSession(state.sessionToken);
    state.currentUser = payload.user || null;
  } catch (error) {
    state.sessionToken = "";
    state.currentUser = null;
    window.localStorage.removeItem("monitorSessionToken");
  }
}

export function renderAuthControls() {
  const auth = state.config?.auth || {};
  const userMode = auth.mode === "users";
  $("#loginForm").classList.toggle("hidden", !userMode || Boolean(state.currentUser));
  $("#accountSession").classList.toggle("hidden", !userMode || !state.currentUser);
  document.querySelector(".token-field").classList.toggle("hidden", userMode || !state.config?.actionsRequireToken);
  if (state.currentUser) {
    $("#accountUserLabel").textContent = `${state.currentUser.displayName || state.currentUser.username} · ${state.currentUser.role}`;
  }
  renderAccountSecurity();
  renderAccountManagement();
  renderAccountLockouts();
}

export function authPayload() {
  const auth = state.config?.auth || {};
  if (auth.mode === "users") return { sessionToken: state.sessionToken };
  if (state.config?.actionsRequireToken) return { token: $("#tokenInput").value };
  return {};
}

export function isAdminUser() {
  return state.currentUser?.role === "admin";
}

function canBootstrapFirstAdmin() {
  const auth = state.config?.auth || {};
  const users = auth.users || [];
  return auth.mode === "token" && state.config?.actionsRequireToken === true && users.length === 0;
}

function accountModeLabel(mode) {
  return {
    users: "账号登录模式",
    token: "旧操作口令模式",
    unconfigured: "未配置认证",
  }[mode] || "未知认证模式";
}

function accountSeverityLabel(severity) {
  return {
    ok: "正常",
    warning: "需核查",
    error: "高风险",
  }[severity] || "未知";
}

export function renderAccountSecurity() {
  const panel = $("#accountSecurityPanel");
  const security = state.dashboard?.accountSecurity;
  if (!security) {
    panel.classList.add("hidden");
    panel.innerHTML = "";
    return;
  }

  const severity = security.severity || "warning";
  const secret = security.sessionSecret || {};
  const secretStatus = secret.configured
    ? `${secret.source === "sessionSecret" ? "独立会话密钥" : "复用操作口令"}${secret.weak ? "，长度不足" : ""}${secret.placeholder ? "，仍是占位值" : ""}`
    : "未配置会话密钥";
  const issues = security.issues || [];
  const recommendations = security.recommendations || [];

  panel.className = `account-security-panel ${escapeHtml(severity)}`;
  panel.innerHTML = `
    <div class="account-security-head">
      <div>
        <strong>账号安全</strong>
        <p>${escapeHtml(accountModeLabel(security.mode))} · 管理员 ${escapeHtml(String(security.adminUsers ?? 0))} · 可操作账号 ${escapeHtml(String(security.operatorUsers ?? 0))}</p>
      </div>
      <span class="account-security-badge ${escapeHtml(severity)}">${escapeHtml(accountSeverityLabel(severity))}</span>
    </div>
    <div class="account-security-grid">
      <span>账号数：${escapeHtml(String(security.enabledUsers ?? 0))}</span>
      <span>会话密钥：${escapeHtml(secretStatus)}</span>
      <span>${security.requiresBootstrapAdmin ? "建议：创建首个管理员账号" : "建议：定期审查账号权限"}</span>
    </div>
    ${(issues.length || recommendations.length) ? `<div class="account-security-list">
      ${issues.map((item) => `<p>${escapeHtml(item)}</p>`).join("")}
      ${recommendations.map((item) => `<p>${escapeHtml(item)}</p>`).join("")}
    </div>` : ""}
  `;
}

export async function loadAccountLockouts() {
  if (!state.sessionToken || !isAdminUser()) {
    state.accountLockouts = [];
    return;
  }

  try {
    const payload = await fetchAccountLockouts(state.sessionToken);
    state.accountLockouts = payload.lockouts || [];
  } catch (error) {
    state.accountLockouts = [];
  }
}

export async function loadAccountUsers() {
  if (!state.sessionToken || !isAdminUser()) {
    state.accountUsers = [];
    return;
  }

  try {
    const payload = await fetchAccountUsers(state.sessionToken);
    state.accountUsers = payload.users || [];
  } catch (error) {
    state.accountUsers = [];
  }
}

export async function loadAccountAudit() {
  if (!state.sessionToken || !isAdminUser()) {
    state.accountAuditLogs = [];
    state.accountAuditPage = { total: 0, limit: 50, offset: 0, hasMore: false };
    return;
  }

  try {
    const payload = await fetchAccountAudit(state.sessionToken, { limit: 50, offset: 0 });
    state.accountAuditLogs = payload.logs || [];
    state.accountAuditPage = {
      total: payload.total || 0,
      limit: payload.limit || 50,
      offset: payload.offset || 0,
      hasMore: Boolean(payload.hasMore),
    };
  } catch (error) {
    state.accountAuditLogs = [];
    state.accountAuditPage = { total: 0, limit: 50, offset: 0, hasMore: false };
  }
}

export function renderAccountManagement() {
  const panel = $("#accountManagementPanel");
  const bootstrapFirstAdmin = canBootstrapFirstAdmin();
  if (!isAdminUser() && !bootstrapFirstAdmin) {
    panel.classList.add("hidden");
    $("#accountUserList").innerHTML = "";
    $("#accountUserSummary").textContent = "";
    $("#accountPasswordPolicy").textContent = "";
    return;
  }

  const users = state.accountUsers || [];
  panel.classList.remove("hidden");
  renderAccountPasswordPolicy();
  $("#accountRole").disabled = bootstrapFirstAdmin;
  if (bootstrapFirstAdmin) $("#accountRole").value = "admin";
  $("#accountUserSummary").textContent = bootstrapFirstAdmin
    ? "创建首个管理员账号"
    : (users.length ? `${users.length} 个账号` : "当前没有账号");
  $("#accountUserList").innerHTML = users.length
    ? users.map((user) => `
      <div class="account-user-item ${user.enabled ? "" : "disabled"}">
        <div>
          <strong>${escapeHtml(user.displayName || user.username || "")}</strong>
          <span class="muted">${escapeHtml(user.username || "")} · ${escapeHtml(user.role || "viewer")}${user.enabled ? "" : " · 已停用"}</span>
        </div>
        <div class="account-user-actions">
          <button type="button" class="secondary compact" data-edit-user="${escapeHtml(user.username || "")}">编辑</button>
          <button type="button" class="secondary compact" data-delete-user="${escapeHtml(user.username || "")}">删除</button>
        </div>
      </div>
    `).join("")
    : (bootstrapFirstAdmin
      ? '<p class="muted">使用顶部操作口令创建首个管理员账号；创建后请用新账号登录。</p>'
      : '<p class="muted">暂无账号。</p>');

  $("#accountUserList").querySelectorAll("[data-edit-user]").forEach((button) => {
    button.addEventListener("click", () => editManagedAccount(button.dataset.editUser));
  });
  $("#accountUserList").querySelectorAll("[data-delete-user]").forEach((button) => {
    button.addEventListener("click", () => deleteManagedAccount(button.dataset.deleteUser));
  });

  const form = $("#accountUserForm");
  if (!form.dataset.bound) {
    form.addEventListener("submit", saveAccountUser);
    $("#accountUserResetButton").addEventListener("click", resetAccountUserForm);
    form.dataset.bound = "true";
  }
}

function renderAccountPasswordPolicy() {
  const minLength = state.config?.auth?.policy?.passwordMinLength || 8;
  $("#accountPasswordPolicy").textContent = `新密码至少 ${minLength} 位`;
}

export function renderAccountLockouts() {
  const panel = $("#accountLockoutPanel");
  const bootstrapFirstAdmin = canBootstrapFirstAdmin();
  if (!isAdminUser()) {
    if (bootstrapFirstAdmin) {
      panel.classList.remove("hidden");
      $("#accountLockoutList").innerHTML = "";
      $("#accountLockoutSummary").textContent = "创建管理员后启用锁定处理";
      $("#accountAuditList").innerHTML = "";
      $("#accountAuditSummary").textContent = "创建管理员后启用账号审计";
      return;
    }
    panel.classList.add("hidden");
    $("#accountManagementPanel").classList.add("hidden");
    $("#accountUserList").innerHTML = "";
    $("#accountUserSummary").textContent = "";
    $("#accountLockoutList").innerHTML = "";
    $("#accountLockoutSummary").textContent = "";
    $("#accountAuditList").innerHTML = "";
    $("#accountAuditSummary").textContent = "";
    return;
  }

  const lockouts = state.accountLockouts || [];
  panel.classList.remove("hidden");
  $("#accountLockoutSummary").textContent = lockouts.length
    ? `${lockouts.length} 个账号需要处理`
    : "当前没有锁定账号";
  $("#accountLockoutList").innerHTML = lockouts.length
    ? lockouts.map((item) => `
      <div class="account-lockout-item">
        <div>
          <strong>${escapeHtml(item.username || "")}</strong>
          <span class="muted">剩余 ${formatElapsed(item.secondsRemaining || 0)} · 失败 ${escapeHtml(String(item.failureCount || 0))} 次</span>
        </div>
        <button type="button" class="secondary compact" data-unlock-user="${escapeHtml(item.username || "")}">解锁</button>
      </div>
    `).join("")
    : '<p class="muted">没有账号处于临时锁定状态。</p>';

  $("#accountLockoutList").querySelectorAll("[data-unlock-user]").forEach((button) => {
    button.addEventListener("click", () => unlockLoginAccount(button.dataset.unlockUser));
  });
  renderAccountAudit();
}

export function renderAccountAudit() {
  const logs = (state.accountAuditLogs || []).slice().reverse();
  const page = state.accountAuditPage || { total: logs.length, limit: 50, offset: 0, hasMore: false };
  $("#accountAuditSummary").textContent = page.total
    ? `最近 ${logs.length} / ${page.total} 条账号安全事件${page.hasMore ? "，还有更早记录" : ""}`
    : "最近账号安全事件";
  $("#accountAuditList").innerHTML = logs.length
    ? logs.map((log) => `
      <article class="account-audit-item">
        <div>
          <strong>${escapeHtml(log.username || "--")}</strong>
          <span class="muted">${escapeHtml(log.message || log.event || "")}</span>
        </div>
        <div class="account-audit-meta">
          <span>${escapeHtml(formatTime(log.timestamp))}</span>
          <span>${escapeHtml(log.actor?.username ? `操作者 ${log.actor.username}` : "系统")}</span>
          <span>${escapeHtml(log.sourceIp ? `来源 IP ${log.sourceIp}` : "来源 IP --")}</span>
        </div>
      </article>
    `).join("")
    : '<p class="muted">暂无账号审计事件。</p>';
}

function resetAccountUserForm() {
  const bootstrapFirstAdmin = canBootstrapFirstAdmin();
  $("#accountUsername").value = "";
  $("#accountUsername").disabled = false;
  $("#accountDisplayName").value = "";
  $("#accountRole").value = bootstrapFirstAdmin ? "admin" : "operator";
  $("#accountRole").disabled = bootstrapFirstAdmin;
  $("#accountPassword").value = "";
  $("#accountEnabled").checked = true;
  $("#accountUserError").textContent = "";
  renderAccountPasswordPolicy();
}

function editManagedAccount(username) {
  const user = (state.accountUsers || []).find((item) => item.username === username);
  if (!user) return;
  $("#accountUsername").value = user.username || "";
  $("#accountUsername").disabled = true;
  $("#accountDisplayName").value = user.displayName || user.username || "";
  $("#accountRole").value = user.role || "viewer";
  $("#accountPassword").value = "";
  $("#accountEnabled").checked = user.enabled !== false;
  $("#accountUserError").textContent = "";
  renderAccountPasswordPolicy();
}

export async function saveAccountUser(event) {
  event.preventDefault();
  const bootstrapFirstAdmin = canBootstrapFirstAdmin();
  const bootstrapUsername = $("#accountUsername").value.trim();
  $("#accountUserError").textContent = "";
  $("#accountUserSubmitButton").disabled = true;
  try {
    const payload = await saveAccountUserRequest({
      user: {
        username: $("#accountUsername").value,
        displayName: $("#accountDisplayName").value,
        role: bootstrapFirstAdmin ? "admin" : $("#accountRole").value,
        password: $("#accountPassword").value,
        enabled: $("#accountEnabled").checked,
      },
      auth: authPayload(),
    });
    state.accountUsers = payload.users || [];
    if (state.config?.auth) {
      state.config.auth.users = state.accountUsers;
      if (bootstrapFirstAdmin) state.config.auth.mode = "users";
    }
    if (bootstrapFirstAdmin) {
      state.config.actionsRequireToken = false;
      state.sessionToken = "";
      state.currentUser = null;
      window.localStorage.removeItem("monitorSessionToken");
      $("#tokenInput").value = "";
      try {
        state.dashboard = await fetchDashboard();
      } catch (error) {
        // The new admin can still log in even if the advisory dashboard refresh fails.
      }
    }
    resetAccountUserForm();
    if (!bootstrapFirstAdmin) await loadAccountAudit();
    renderAuthControls();
    if (bootstrapFirstAdmin) {
      $("#loginUsername").value = bootstrapUsername;
      $("#loginError").textContent = "管理员账号已创建，请使用新账号登录。";
      $("#loginPassword").focus();
    }
  } catch (error) {
    $("#accountUserError").textContent = error.message;
  } finally {
    $("#accountUserSubmitButton").disabled = false;
  }
}

export async function deleteManagedAccount(username) {
  if (!username || !window.confirm(`删除账号 ${username}？`)) return;
  try {
    const payload = await removeAccountUser({ username, auth: { sessionToken: state.sessionToken } });
    state.accountUsers = payload.users || [];
    if (state.config?.auth) state.config.auth.users = state.accountUsers;
    await loadAccountAudit();
    renderAuthControls();
  } catch (error) {
    $("#accountUserError").textContent = error.message;
  }
}

async function unlockLoginAccount(username) {
  try {
    const payload = await unlockAccount({ username, auth: { sessionToken: state.sessionToken } });
    state.accountLockouts = payload.lockouts || [];
    await loadAccountAudit();
    renderAccountLockouts();
  } catch (error) {
    await loadAccountLockouts();
    await loadAccountAudit();
    renderAccountLockouts();
  }
}

export async function loginCurrentUser(event, options = {}) {
  event.preventDefault();
  $("#loginError").textContent = "";
  $("#loginButton").disabled = true;
  try {
    const payload = await loginUser({
      username: $("#loginUsername").value,
      password: $("#loginPassword").value,
    });
    state.sessionToken = payload.sessionToken || "";
    state.currentUser = payload.user || null;
    window.localStorage.setItem("monitorSessionToken", state.sessionToken);
    $("#loginPassword").value = "";
    await loadAccountUsers();
    await loadAccountLockouts();
    await loadAccountAudit();
    renderAuthControls();
    await options.refreshDashboard?.();
  } catch (error) {
    $("#loginError").textContent = error.message;
  } finally {
    $("#loginButton").disabled = false;
  }
}

export async function logoutCurrentUser() {
  const token = state.sessionToken;
  try {
    if (token) {
      await logoutSession(token);
    }
  } catch (error) {
    // Local logout must still proceed even if the server session is already expired.
  } finally {
    state.sessionToken = "";
    state.currentUser = null;
    state.accountUsers = [];
    state.accountLockouts = [];
    state.accountAuditLogs = [];
    window.localStorage.removeItem("monitorSessionToken");
    renderAuthControls();
  }
}

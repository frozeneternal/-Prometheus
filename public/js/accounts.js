import {
  fetchAccountAudit,
  fetchAccountLockouts,
  fetchSession,
  loginUser,
  logoutSession,
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

export async function loadAccountAudit() {
  if (!state.sessionToken || !isAdminUser()) {
    state.accountAuditLogs = [];
    return;
  }

  try {
    const payload = await fetchAccountAudit(state.sessionToken);
    state.accountAuditLogs = payload.logs || [];
  } catch (error) {
    state.accountAuditLogs = [];
  }
}

export function renderAccountLockouts() {
  const panel = $("#accountLockoutPanel");
  if (!isAdminUser()) {
    panel.classList.add("hidden");
    $("#accountLockoutList").innerHTML = "";
    $("#accountLockoutSummary").textContent = "";
    $("#accountAuditList").innerHTML = "";
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
        </div>
      </article>
    `).join("")
    : '<p class="muted">暂无账号审计事件。</p>';
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
    state.accountLockouts = [];
    state.accountAuditLogs = [];
    window.localStorage.removeItem("monitorSessionToken");
    renderAuthControls();
  }
}

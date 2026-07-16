import { fetchResourceDetails } from "./client.js";
import { $ } from "./dom.js";
import { state } from "./state.js";

let actionToken = "";
let requestGeneration = 0;
let activeAuthMode = "";

function authMode() {
  return String(state.config?.auth?.mode || "");
}

function authModeKey() {
  return `${authMode()}:${state.config?.actionsRequireToken === true ? "required" : "disabled"}`;
}

function clearResourceDom({ clearCredential = false } = {}) {
  const form = $("#resourceExpiryForm");
  if (form) form.reset();
  const resourceId = $("#resourceId");
  if (resourceId) resourceId.readOnly = false;
  const formError = $("#resourceFormError");
  if (formError) formError.textContent = "";
  const list = $("#resourceExpiryList");
  if (list) list.innerHTML = "";
  $("#resourceExpiryEmptyState")?.classList.add("hidden");
  $("#resourceManagementPanel")?.classList.add("hidden");
  if (clearCredential) {
    const tokenInput = $("#resourceAccessToken");
    if (tokenInput) tokenInput.value = "";
  }
}

function replaceAccessState(status, message = "", capabilities = {}) {
  state.resourceAccess = {
    status,
    authMode: authMode(),
    capabilities: { ...capabilities },
    message,
  };
}

function clearResourceDetails({
  status = "locked",
  message = "",
  clearCredential = false,
  invalidateRequests = false,
} = {}) {
  if (invalidateRequests) requestGeneration += 1;
  if (clearCredential) actionToken = "";
  state.resourceDetails = [];
  replaceAccessState(status, message);
  clearResourceDom({ clearCredential });
  renderResourceAccess();
}

export function setResourceActionToken(value) {
  actionToken = String(value || "");
}

export function resourceAuthHeaders() {
  const mode = authMode();
  if (mode === "users") {
    const role = state.currentUser?.role;
    if (!["operator", "admin"].includes(role) || !state.sessionToken) return {};
    return { Authorization: `Bearer ${state.sessionToken}` };
  }
  if (mode === "token" && state.config?.actionsRequireToken === true && actionToken) {
    return { "X-Action-Token": actionToken };
  }
  return {};
}

export function syncResourceAuthMode() {
  const nextMode = authModeKey();
  if (activeAuthMode && activeAuthMode !== nextMode) {
    activeAuthMode = nextMode;
    purgeResourceDetails("认证模式已变化，请重新授权资源详情。", "locked");
    return true;
  }
  activeAuthMode = nextMode;
  state.resourceAccess.authMode = authMode();
  renderResourceAccess();
  return false;
}

export function purgeResourceDetails(message = "", status = "locked") {
  clearResourceDetails({
    status,
    message,
    clearCredential: true,
    invalidateRequests: true,
  });
}

function blockedAccessState() {
  const mode = authMode();
  if (mode === "users") {
    if (state.currentUser && !["operator", "admin"].includes(state.currentUser.role)) {
      return { status: "denied", message: "当前账号没有查看资源详情的权限。" };
    }
    return { status: "locked", message: "请使用运维或管理员账号登录。" };
  }
  if (mode === "token" && state.config?.actionsRequireToken === true) {
    return { status: "locked", message: "输入操作口令后解锁资源详情。" };
  }
  return { status: "denied", message: "资源详情认证尚未配置。" };
}

export async function loadResourceDetails() {
  const headers = resourceAuthHeaders();
  if (Object.keys(headers).length === 0) {
    const blocked = blockedAccessState();
    clearResourceDetails({ ...blocked, invalidateRequests: true });
    return null;
  }

  const generation = ++requestGeneration;
  state.resourceDetails = [];
  replaceAccessState("loading", "正在读取受保护的资源详情。");
  clearResourceDom();
  renderResourceAccess();

  try {
    const payload = await fetchResourceDetails(headers);
    if (generation !== requestGeneration) return null;
    const capabilities = payload?.capabilities || {};
    if (capabilities.viewResourceDetails !== true || !Array.isArray(payload?.items)) {
      clearResourceDetails({
        status: "denied",
        message: "服务端未授予资源详情读取权限。",
        clearCredential: true,
        invalidateRequests: true,
      });
      return null;
    }
    state.resourceDetails = payload.items.slice();
    replaceAccessState("ready", "资源详情已授权。", capabilities);
    renderResourceAccess();
    return payload;
  } catch (error) {
    if (generation !== requestGeneration) return null;
    if (error.status === 401) {
      clearResourceDetails({
        status: "locked",
        message: "资源凭据已失效，请重新授权。",
        clearCredential: true,
        invalidateRequests: true,
      });
    } else if (error.status === 403) {
      clearResourceDetails({
        status: "denied",
        message: error.payload?.message || "当前凭据没有资源详情权限。",
        clearCredential: true,
        invalidateRequests: true,
      });
    } else {
      clearResourceDetails({
        status: "error",
        message: error.message || "资源详情读取失败，可稍后重试。",
      });
    }
    return null;
  }
}

export function renderResourceAccess() {
  const panel = $("#resourceAccessPanel");
  if (!panel) return;
  const access = state.resourceAccess || {};
  const status = access.status || "locked";
  const labels = {
    locked: "待授权",
    loading: "读取中",
    ready: "已授权",
    denied: "无权限",
    error: "读取失败",
  };
  panel.className = `resource-access-panel ${status}`;
  const statusElement = $("#resourceAccessStatus");
  if (statusElement) {
    statusElement.className = `resource-access-status ${status}`;
    statusElement.textContent = labels[status] || labels.locked;
  }
  const message = $("#resourceAccessMessage");
  if (message) message.textContent = access.message || "资源详情需要单独授权。";

  const tokenMode = authMode() === "token" && state.config?.actionsRequireToken === true;
  $("#resourceAccessForm")?.classList.toggle("hidden", !tokenMode);
  const canManage = status === "ready" && access.capabilities?.manageResources === true;
  $("#resourceManagementPanel")?.classList.toggle("hidden", !canManage);
  const emptyState = $("#resourceExpiryEmptyState");
  if (emptyState) {
    emptyState.classList.toggle("hidden", status !== "ready" || state.resourceDetails.length !== 0);
  }
}

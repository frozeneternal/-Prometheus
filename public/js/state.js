export const state = {
  config: null,
  dashboard: null,
  selectedGroup: "全部",
  chartMetric: "cpu",
  currentAction: null,
  refreshTimer: null,
  sessionToken: window.localStorage.getItem("monitorSessionToken") || "",
  currentUser: null,
  accountLockouts: [],
  accountAuditLogs: [],
};

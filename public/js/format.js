export const metricLabels = {
  cpu: "CPU",
  memory: "内存",
  disk: "磁盘",
  rx: "入站",
  tx: "出站",
  load: "负载",
  uptime: "运行",
};

export const healthLabels = {
  healthy: "正常",
  warning: "告警",
  down: "异常",
  unknown: "未知",
};

export const serverTypeLabels = {
  physical: "物理服务器",
  virtual: "虚拟机",
};

export const recoveryLabels = {
  idle: "空闲",
  waiting: "等待触发",
  blocked: "配置阻塞",
  triggered: "已执行",
  failed: "执行失败",
};

export const backupLabels = {
  idle: "空闲",
  waiting: "等待备份",
  blocked: "配置阻塞",
  triggered: "已备份",
  failed: "备份失败",
};

export const certRenewalLabels = {
  idle: "空闲",
  waiting: "等待续期",
  verifying: "确认中",
  blocked: "配置阻塞",
  triggered: "已续期",
  failed: "续期失败",
};

export const dataQualityLabels = {
  ok: "数据可信",
  partial: "指标不完整",
  collector_down: "采集层不可用",
  no_series: "没有采集序列",
  target_down: "目标不可达",
  query_error: "查询失败",
  unknown: "未知",
};

export const targetDiagnosticLabels = {
  healthy: "正常",
  timeout: "采集超时",
  connection_refused: "连接被拒绝",
  ssh_tunnel_down: "SSH 隧道断开",
  network_unreachable: "网络不可达",
  scrape_error: "采集错误",
  target_down: "目标不可达",
  no_target: "未匹配目标",
  collector_down: "采集器不可用",
  unknown: "未知",
};

export const resourceExpiryLabels = {
  expired: "已过期",
  critical: "即将到期",
  warning: "到期预警",
  ok: "正常",
  unknown: "待核实",
};

function isFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

export function formatPercent(value) {
  if (!isFiniteNumber(value)) return "--";
  return `${Math.max(0, value).toFixed(1)}%`;
}

export function formatBytesPerSecond(value) {
  if (!isFiniteNumber(value)) return "--";
  const units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
  let size = Math.max(0, value);
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

export function formatDuration(seconds) {
  if (!isFiniteNumber(seconds)) return "--";
  const day = 86400;
  const hour = 3600;
  if (seconds >= day) return `${Math.floor(seconds / day)} 天`;
  if (seconds >= hour) return `${Math.floor(seconds / hour)} 小时`;
  return `${Math.floor(seconds / 60)} 分钟`;
}

export function formatElapsed(seconds) {
  if (!isFiniteNumber(seconds)) return "--";
  const value = Math.max(0, Math.floor(seconds));
  const day = 86400;
  const hour = 3600;
  const minute = 60;
  if (value >= day) return `${Math.floor(value / day)}天${Math.floor((value % day) / hour)}小时`;
  if (value >= hour) return `${Math.floor(value / hour)}小时${Math.floor((value % hour) / minute)}分钟`;
  if (value >= minute) return `${Math.floor(value / minute)}分钟${value % minute}秒`;
  return `${value}秒`;
}

export function formatSeconds(value) {
  if (!isFiniteNumber(value)) return "--";
  return `${value.toFixed(value >= 10 ? 1 : 2)}s`;
}

export function formatStatusCode(value) {
  if (!isFiniteNumber(value)) return "--";
  return String(Math.trunc(value));
}

export function formatCert(value) {
  if (!isFiniteNumber(value)) return "--";
  if (value <= 0) return "已过期";
  return `${Math.floor(value / 86400)} 天`;
}

export function formatTime(value) {
  if (!value) return "--";
  return new Date(value * 1000).toLocaleString("zh-CN", { hour12: false });
}

export function formatDate(value) {
  if (!value) return "--";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleDateString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit" });
}

export function formatDateTime(value) {
  if (!value) return "--";
  const date = new Date(isFiniteNumber(value) ? value * 1000 : value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("zh-CN", { hour12: false });
}

export function metricValue(metric, value) {
  if (["cpu", "memory", "disk"].includes(metric)) return formatPercent(value);
  if (["rx", "tx"].includes(metric)) return formatBytesPerSecond(value);
  if (metric === "load") return isFiniteNumber(value) ? value.toFixed(2) : "--";
  if (metric === "uptime") return formatDuration(value);
  return value ?? "--";
}

export function statusText(status) {
  if (status === "online") return "在线";
  if (status === "offline") return "离线";
  return "未知";
}

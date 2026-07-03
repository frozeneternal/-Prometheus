# 本地服务器监控台

这是一个本机运行的 Prometheus 监控网页。Prometheus 负责采集服务器指标和网站探测结果，本地 Python 后端负责查询 Prometheus、提供网页、以及执行你在配置文件里显式允许的服务器操作。

现在它还支持：

- 自动恢复：服务器或网站连续异常后，自动执行你配置好的恢复动作。
- 恢复日志：每次自动恢复或手动执行，都会把原因、时间、stdout、stderr 记到面板。

## 你要改哪几个文件

- `prometheus/prometheus.yml`：告诉 Prometheus 去采集哪些服务器、探测哪些网站。
- `config/servers.json`：告诉本地网页如何展示服务器、网站，以及允许执行哪些操作。
- `config/servers.local.json`：本机私有真实配置，优先级高于 `servers.json`，已经被 `.gitignore` 忽略，不会提交到公开仓库。
- `prometheus/blackbox.yml`：网站探测规则，默认已经能探测 HTTP/HTTPS。
- `scripts/restart_vm_by_ip.py`：通过宿主机 SSH + `virsh` 按虚拟机 IP 拉起虚拟机的辅助脚本。

如果你要把项目上传到公开 Git 仓库，保留脱敏后的 `config/servers.json` 即可；真实内网 IP、运维账号、站点映射放到 `config/servers.local.json`。可以先复制模板：

```powershell
Copy-Item .\config\servers.local.template.json .\config\servers.local.json
```

启动时后端和 `scripts/render_prometheus_config.py` 都会优先读取 `servers.local.json`。

## 加一台服务器

1. 先在服务器上安装并启动 `node_exporter`，默认端口是 `9100`。
2. 在 `prometheus/prometheus.yml` 的 `job_name: node` 下面加目标：

```yaml
- job_name: node
  static_configs:
    - targets:
        - 10.0.0.11:9100
        - 10.0.0.12:9100
```

3. 在 `config/servers.json` 的 `servers` 数组里加同一台服务器：

```json
{
  "id": "web-01",
  "name": "Web 01",
  "type": "physical",
  "group": "生产",
  "labels": {
    "job": "node",
    "instance": "10.0.0.11:9100"
  },
  "diskMountpoint": "/",
  "thresholds": {
    "cpu": 85,
    "memory": 90,
    "disk": 90
  },
  "actions": []
}
```

`labels.instance` 必须和 `prometheus/prometheus.yml` 里的 `IP:9100` 完全一致。

## 自定义名称和虚拟机归属

每台服务器或虚拟机的显示名都改 `name`：

```json
{
  "id": "physical-host-b",
  "name": "Primary Physical Host",
  "type": "physical"
}
```

虚拟机要写 `type: "virtual"`，并用 `hostServerId` 指向它所在的物理服务器 `id`：

```json
{
  "id": "vm-app-01",
  "name": "Customer App VM",
  "type": "virtual",
  "hostServerId": "physical-host-b"
}
```

页面会在虚拟机卡片上显示“宿主机：一号物理机”。如果暂时不知道在哪台物理服务器下，把 `hostServerId` 留空，页面会显示“未配置宿主机”。

## 加一个网站

1. 在 `prometheus/prometheus.yml` 的 `job_name: blackbox` 下面加 URL：

```yaml
- job_name: blackbox
  metrics_path: /probe
  params:
    module:
      - http_2xx
  static_configs:
    - targets:
        - https://example.com
        - https://admin.example.com/login
```

2. 在 `config/servers.json` 的 `websites` 数组里加同一个 URL：

```json
{
  "id": "web-01-home",
  "name": "Web 01 首页",
  "group": "生产",
  "serverId": "web-01",
  "url": "https://example.com",
  "thresholds": {
    "duration": 3,
    "certDays": 14
  }
}
```

`url` 必须和 Prometheus blackbox 目标完全一致。`serverId` 用来把网站关联到某台服务器。

## 资源到期告警

把域名、账号、云资源、服务器租约、合同或授权放到顶层 `resources` 清单里。这个功能不依赖 Prometheus，即使采集层不可用，也会继续按配置里的到期时间计算风险。

```json
{
  "resources": [
    {
      "id": "domain-main",
      "name": "Main Public Domain",
      "type": "domain",
      "provider": "Example Registrar",
      "owner": "ops@example.com",
      "linkedTarget": "external-site-a",
      "expiresAt": "2026-08-15",
      "warningDays": 30,
      "criticalDays": 7,
      "renewUrl": "https://registrar.example.com/domains",
      "notes": "Renew domain before DNS change freeze window."
    }
  ]
}
```

状态规则：
- `expired`：已经过期。
- `critical`：剩余天数小于等于 `criticalDays`。
- `warning`：剩余天数小于等于 `warningDays`。
- `ok`：暂未进入预警窗口。
- `unknown`：`expiresAt` 为空或日期格式无效。

全局默认阈值可以放在 `monitoring` 里：

```json
{
  "monitoring": {
    "resourceExpiryWarningDays": 30,
    "resourceExpiryCriticalDays": 7
  }
}
```

真实账号、域名、供应商入口和备注建议只写入 `config/servers.local.json`，不要提交到公开仓库。

## 账号管理

默认保持旧的 `actionToken` 模式，适合只在本机临时使用。要启用账号模式，在私有的 `config/servers.local.json` 中配置 `sessionSecret` 和 `users`。

```json
{
  "sessionSecret": "replace-with-a-long-random-session-secret",
  "users": [
    {
      "username": "ops",
      "displayName": "Operations",
      "role": "operator",
      "passwordHash": "pbkdf2_sha256$210000$..."
    }
  ]
}
```

生成密码哈希：

```powershell
python -c "import app; print(app.hash_password('replace-this-password'))"
```

角色规则：
- `viewer`：只读，不能执行恢复、备份、证书续期，也不能修改开关。
- `operator`：可以执行手动动作和修改自动化开关。
- `admin`：预留给后续账号增删改和平台级设置。

一旦 `users` 中存在启用的账号，面板会切换到登录模式，手动动作和设置接口必须带有效会话；旧 `actionToken` 不再作为绕过入口。

## 代码分层

后端正在从单体 `app.py` 逐步拆到 `backend/` 包：

- `backend/auth.py`：账号、角色、密码哈希、会话签名、操作鉴权。
- `backend/expiry.py`：资源到期日期解析、风险分级、汇总统计。
- `app.py`：暂时保留 HTTP 路由、Prometheus 查询、动作执行和运行时状态。

迁移规则：纯业务逻辑优先放到 `backend/`，`app.py` 只做编排和兼容入口。后续前端也会按同样原则从单个 `public/app.js` 拆成模块化目录。

## 怎么看是否正常

网页打开后看两块：

- 服务器：显示 CPU、内存、磁盘、网络、负载、运行时间。
- 网站：显示 HTTP 状态码、响应时间、HTTPS 证书剩余天数。

状态含义：

- 正常：服务器能采集，指标没超过阈值；网站探测成功。
- 告警：服务器还在线但 CPU/内存/磁盘过高；网站能打开但响应慢或证书快过期。
- 异常：服务器 exporter 离线；网站探测失败或返回不符合规则。
- 未知：Prometheus 还没有采到数据，通常是 Prometheus 没启动、配置没 reload、IP/URL 写错、网络不通。

## 加操作按钮

在某台服务器的 `actions` 里写白名单命令：

```json
{
  "id": "restart_nginx",
  "name": "重启 Nginx",
  "danger": "high",
  "enabled": true,
  "confirm": "restart nginx",
  "timeoutSeconds": 30,
  "command": [
    "ssh",
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=5",
    "root@10.0.0.11",
    "sudo",
    "systemctl",
    "restart",
    "nginx"
  ]
}
```

建议先加低风险命令，例如 `df -h`、`systemctl status nginx`。确认 SSH 密钥和 sudo 权限没问题后，再启用重启服务这类高风险操作。

`enabled: false` 的动作不会参与自动恢复，但仍会在面板里显示为“仅手动”，输入操作口令后可以手动执行。要禁止一个动作被任何方式执行，就把它从 `actions` 里移除。

## 自动恢复

`config/servers.json` 里的 `autoRecovery` 控制自动恢复行为。现在面板里也有开关，改动会直接写回配置文件。

```json
{
  "enabled": true,
  "actionServerId": "physical-host-b",
  "actionId": "restart_vm_example",
  "minimumConsecutiveFailures": 2,
  "cooldownSeconds": 300,
  "triggerHealth": ["down"]
}
```

字段含义：

- `enabled`：是否启用自动恢复。
- `actionServerId`：在哪台服务器的 `actions` 里找恢复动作。
- `actionId`：恢复动作 ID。
- `minimumConsecutiveFailures`：连续失败多少次后再执行。
- `cooldownSeconds`：两次自动恢复之间至少间隔多久。
- `triggerHealth`：哪些健康状态会触发，常见是 `["down"]`，也可以加 `warning`。

动作本身要显式允许自动恢复：

```json
{
  "id": "restart_nginx",
  "name": "重启 Nginx",
  "enabled": true,
  "allowAuto": true,
  "command": ["ssh", "..."]
}
```

如果 `allowAuto` 不是 `true`，后台不会自动执行，面板会显示“配置阻塞”。

如果你只想保留手动恢复，把 `autoRecovery.enabled` 关掉即可；卡片上的小按钮还会保留。

## 虚拟机恢复

现在示例里已经给 `vm-app-01` 配了一个恢复动作：

- 监控对象：`vm-app-01`
- 恢复执行机：`physical-host-b`
- 恢复方式：通过 `scripts/restart_vm_by_ip.py` SSH 到宿主机，然后尝试用 `virsh` 通过来宾 IP 找 VM，再执行 `reboot` 或 `start`

这要求宿主机满足：

- 可以通过受限运维账号免密 SSH
- 宿主机装有 `virsh`
- `virsh domifaddr` 能看到目标虚拟机地址

如果你不是 libvirt/KVM，而是 VMware、Proxmox 或别的平台，要把恢复动作改成对应平台命令。

## 网站恢复

网站自动恢复不是“Prometheus 自己重启网站”，而是：

1. blackbox exporter 发现 URL 连续失败
2. 本地面板按 `websites[].autoRecovery` 找到对应动作
3. 在指定服务器上执行你配置的恢复命令
4. 把触发原因和输出写到恢复日志

示例：

```json
{
  "id": "vm-app-01-site",
  "name": "测试站点",
  "serverId": "vm-app-01",
  "url": "http://10.0.1.20",
  "autoRecovery": {
    "enabled": true,
    "actionServerId": "vm-app-01",
    "actionId": "restart_web_stack",
    "minimumConsecutiveFailures": 2,
    "cooldownSeconds": 300,
    "triggerHealth": ["down"]
  }
}
```

要真正启用网站自动恢复，你还需要：

- 在 `prometheus/prometheus.yml` 的 `blackbox` 目标里加真实 URL
- 把对应服务器里的网站重启动作改成真实服务名
- 把那个动作的 `enabled` 和 `allowAuto` 都设成 `true`

## 证书续期

网站卡片现在会显示 HTTPS 证书剩余天数，也支持手动续期和自动续期。

先在网站所在服务器的 `actions` 里放一个续期动作，常见是 `certbot` 或 `acme.sh`：

```json
{
  "id": "renew_certbot_homepage",
  "name": "续期首页证书",
  "danger": "medium",
  "enabled": true,
  "allowAuto": true,
  "timeoutSeconds": 180,
  "command": [
    "ssh",
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=5",
    "root@10.0.0.11",
    "sudo",
    "certbot",
    "renew",
    "--quiet"
  ]
}
```

再在对应 `websites[]` 里加证书续期配置：

```json
{
  "id": "web-01-homepage",
  "name": "Web 01 首页",
  "serverId": "web-01",
  "url": "https://example.com",
  "certRenewal": {
    "enabled": true,
    "actionServerId": "web-01",
    "actionId": "renew_certbot_homepage",
    "renewBeforeDays": 14,
    "cooldownSeconds": 86400
  }
}
```

字段含义：

- `enabled`：是否启用证书自动续期。
- `actionServerId`：在哪台服务器上执行续期命令。
- `actionId`：续期动作 ID。
- `renewBeforeDays`：距离到期多少天以内开始自动续期。
- `cooldownSeconds`：两次自动续期之间至少间隔多久。

面板里的行为：

- 网站卡片会显示证书剩余天数。
- 如果配置了 `certRenewal`，会出现一个小号的 `手动续期` 按钮。
- 当证书剩余天数小于等于 `renewBeforeDays` 时，后台会自动执行续期动作。
- 每次自动续期或手动续期都会写入恢复日志。

注意：

- 只有 `https://` 站点才会有证书天数。
- 如果 443 不通、证书不是公开 TLS、或者 blackbox 拿不到证书，面板会显示“证书天数未知”。
- 续期命令本身仍需要你在服务器上提前配置好，例如 `certbot` 的站点定义、DNS API、`acme.sh` 环境变量等。

## 自动备份

服务器卡片现在支持：

- 自动备份开关
- 立即备份按钮
- 最近一次备份时间
- 备份执行日志

先在服务器的 `actions` 里放一个备份动作：

```json
{
  "id": "backup_web_root",
  "name": "备份网站目录",
  "danger": "medium",
  "enabled": true,
  "allowAuto": true,
  "timeoutSeconds": 600,
  "command": [
    "ssh",
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=5",
    "root@10.0.0.11",
    "bash",
    "-lc",
    "mkdir -p /var/backups/web-01 && tar -czf /var/backups/web-01/site-$(date +%F-%H%M%S).tar.gz /var/www/html"
  ]
}
```

再在对应 `servers[]` 里加：

```json
{
  "id": "web-01",
  "autoBackup": {
    "enabled": true,
    "actionServerId": "web-01",
    "actionId": "backup_web_root",
    "intervalSeconds": 86400
  }
}
```

字段含义：

- `enabled`：是否启用自动备份。
- `actionServerId`：在哪台服务器上执行备份命令。
- `actionId`：备份动作 ID。
- `intervalSeconds`：备份周期，默认 86400 秒。

说明：

- 开关打开后会从当前时刻开始计时，到下一个周期再自动备份。
- 手动点击 `立即备份` 不受周期限制。
- 备份是否落本地、远端、对象存储，取决于你自己写的命令。

## 启动

启动 Prometheus 和网站探测器：

```powershell
.\scripts\start-prometheus.ps1
```

如果 PowerShell 提示脚本执行策略限制，改用：

```cmd
scripts\start-prometheus.cmd
```

启动本地网页：

```powershell
.\scripts\start-console.ps1
```

同样也可以用：

```cmd
scripts\start-console.cmd
```

打开 [http://127.0.0.1:8787](http://127.0.0.1:8787)。

## 开机自启

已经提供 Windows 计划任务安装脚本。安装或重新安装自启：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-startup.ps1
```

它会创建计划任务 `LocalMonitorStartup`，在当前用户登录时自动运行：

- `scripts\start-prometheus.cmd`：启动 Prometheus 和 blackbox_exporter。
- `scripts\start-console.cmd`：启动本地监控网页。

查看状态：

```powershell
Get-ScheduledTask -TaskName LocalMonitorStartup
```

卸载自启：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\uninstall-startup.ps1
```

## 修改配置后怎么生效

- 修改 `config/servers.json`：刷新网页即可。
- 修改 `prometheus/prometheus.yml` 或 `prometheus/blackbox.yml`：重新运行 `.\scripts\start-prometheus.ps1`。

## 面板里能看到什么

- 每张服务器/网站卡片会显示自动恢复状态、连续失败次数、最近执行时间。
- 每张服务器/网站卡片会显示中断追踪：什么时候开始异常、当前持续多久、恢复后持续了多久。
- 页面底部的“中断事件”会总结服务中断原因、恢复时间、持续时间，并关联对应恢复动作日志。
- 页面底部会显示恢复日志。
- 恢复日志会包含触发原因、动作名、执行方式、退出码、stdout、stderr。

## 推荐的生产落地方案

这套工具建议按“三层闭环”落地：

1. 采集层：Prometheus + node_exporter 采集服务器资源，blackbox_exporter 探测网站可用性和 HTTPS 证书。
2. 决策层：本地 Python 控制台读取 Prometheus 指标，按连续失败次数、冷却时间和阈值判断是否恢复。
3. 执行层：只执行 `config/servers.json` 白名单里的动作，所有动作写入恢复日志，中断事件写入 `data/incident_logs.json`。

新增或调整服务器、网站后，可以用配置生成脚本减少双写：

```powershell
python .\scripts\render_prometheus_config.py
.\scripts\start-prometheus.ps1
```

这个脚本会读取 `config/servers.json` 里的 `servers[].labels.instance` 和 `websites[].url`，生成 `prometheus/prometheus.yml`。如果只是想检查是否同步：

```powershell
python .\scripts\render_prometheus_config.py --check
```

服务器动作建议优先使用统一远程运维脚本 `scripts/remote_ops.py`，例如重启 Web 栈：

```json
{
  "id": "restart_web_stack",
  "name": "重启 Web 栈",
  "danger": "high",
  "enabled": true,
  "allowAuto": true,
  "timeoutSeconds": 60,
  "command": [
    "python",
    "scripts/remote_ops.py",
    "--host",
    "10.0.0.11",
    "--user",
    "ops",
    "--action",
    "service-restart",
    "--service",
    "nginx",
    "--service",
    "php-fpm"
  ]
}
```

证书续期可以走 `certbot`：

```json
{
  "id": "renew_certbot",
  "name": "续期证书",
  "danger": "medium",
  "enabled": true,
  "allowAuto": true,
  "timeoutSeconds": 180,
  "command": [
    "python",
    "scripts/remote_ops.py",
    "--host",
    "10.0.0.11",
    "--user",
    "ops",
    "--action",
    "certbot-renew",
    "--reload-service",
    "nginx"
  ]
}
```

也可以走 `acme.sh`：

```json
{
  "id": "renew_acme_example",
  "name": "续期 example.com",
  "danger": "medium",
  "enabled": true,
  "allowAuto": true,
  "timeoutSeconds": 180,
  "command": [
    "python",
    "scripts/remote_ops.py",
    "--host",
    "10.0.0.11",
    "--user",
    "ops",
    "--action",
    "acme-renew",
    "--domain",
    "example.com",
    "--reload-service",
    "nginx"
  ]
}
```

严谨一点的生产配置建议：

- 自动恢复只给服务重启、虚拟机拉起这类可预期动作开启 `allowAuto: true`。
- 整机重启保留 `confirm`，并把 `allowAuto` 设为 `false`，只允许人工触发。
- 网站恢复先重启应用服务或反向代理，连续失败多次仍不恢复时再人工介入。
- 证书续期建议提前 14 到 30 天触发，并保留一天以上冷却时间。
- 运维账号使用免密 SSH 和 sudo 白名单，只允许 `systemctl restart/status/reload`、`certbot renew`、`virsh start/reboot` 等必要命令。
- `data/recovery_logs.json` 记录执行输出，`data/incident_logs.json` 记录中断与恢复摘要，建议定期备份但不要提交到公开仓库。

## 安全建议

- 默认只监听 `127.0.0.1`，不要直接暴露到公网。
- 把 `config/servers.json` 里的 `actionToken` 换成强口令。
- SSH 建议使用密钥登录，并为网页操作单独创建低权限账号。
- 高风险操作一定配置 `confirm`，例如重启服务器。
- 只把确实需要的操作写进 `actions`；`enabled: false` 代表“仅手动”，不是彻底禁用。

## 常用排查

- Prometheus 目标状态：[http://127.0.0.1:9090/targets](http://127.0.0.1:9090/targets)
- 服务器是否采到：`up{job="node"}`
- 网站是否成功：`probe_success{job="blackbox"}`
- 网站状态码：`probe_http_status_code{job="blackbox"}`
- 网站响应时间：`probe_duration_seconds{job="blackbox"}`

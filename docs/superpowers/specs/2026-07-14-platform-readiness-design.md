# 平台就绪度设计

## 目标

为当前本地运维控制台增加第一阶段的“平台就绪度”能力。它要明确展示哪些自动化能力已经在代码里具备，但还没有安全接入真实运行环境，帮助运维人员先补齐纳管缺口，再逐步启用证书自动续期、资源到期告警、账号管理、应急处置、自动备份和自动恢复。

这个阶段只做只读评估，不直接执行任何恢复、备份、续期、账号或配置变更。

## 当前证据

当前运行态 dashboard 地址是 `http://127.0.0.1:8787/api/dashboard`。

设计前最近一次观测到的状态：

- 服务器：11 台
- 网站：2 个
- 资源到期记录：0 条
- 应急项：8 条，其中严重 3 条
- 自动恢复摘要：`attention`
- 自动备份启用数：0
- 证书续期启用数：0
- 账号模式：`token`
- Prometheus 目标覆盖：`degraded`
- 数据可信度：`ok`

代码库已经有多个领域摘要，例如资源到期、证书续期、自动备份、账号安全、采集覆盖、平台健康和应急项。但这些信息分散在仪表盘载荷、通知条、面板和 Prometheus 指标里。运维人员需要一个统一视图，直接看到哪些能力已就绪、哪些能力未纳管、哪些状态有风险，以及下一步该处理什么。

## 范围

本阶段新增一个只读的平台就绪度视图。

本阶段包含：

- 新增后端就绪度领域模块。
- 在 `/api/dashboard` 中输出就绪度数据。
- 在 `/metrics` 中输出就绪度指标。
- 新增前端就绪度模块和可见面板。
- 增加后端行为、前端接线、指标和运行态载荷形状测试。
- 保持 `app.py` 只承担路由和运行时胶水；新的就绪度业务规则必须放在 `backend/` 和 `public/js/` 的分层模块中。

本阶段不包含：

- 在 `config/servers.local.json` 中启用证书续期。
- 创建真实用户账号。
- 添加真实资源到期记录。
- 启动、停止或重启被监控服务。
- 修改 Prometheus、Grafana、Docker、计划任务或 exporter 配置。
- 全量重构 `app.py`。

## 设计

### 后端领域模块

新增 `backend/readiness.py`。

职责：

- 接收现有 dashboard 摘要和配置状态。
- 生成稳定的 `platformReadiness` 载荷。
- 将每个就绪度区域分类为 `ready`、`attention` 或 `blocked`。
- 为每个区域提供简短、可执行的处理建议。
- 不暴露密钥、命令行、原始私有主机信息或 token 值。

就绪度区域：

- `resources`：资源到期跟踪是否已经配置并具备处置路径。
- `certificates`：适用的 HTTPS 网站是否已经配置证书续期覆盖。
- `accounts`：账号模式是否已经切换到用户体系，并具备管理员或运维账号路径。
- `backups`：是否存在自动备份，或至少存在明确的手动备份处置能力。
- `recovery`：自动恢复是否只在数据可信、动作安全的目标上启用。
- `collection`：Prometheus 目标覆盖和采集健康是否足以支撑自动化决策。
- `platform`：本地平台运行状态是否没有严重风险。
- `emergency`：当前应急项是否可见且具备处置方向。

聚合状态取最差区域状态：

- 任一区域为 `blocked` 时，整体为 `blocked`。
- 没有 `blocked`，但存在需要关注的区域时，整体为 `attention`。
- 所有区域都是 `ready` 时，整体才是 `ready`。

### 仪表盘集成

修改 `backend/dashboard.py`，在载荷中加入：

```python
"platformReadiness": platform_readiness(...),
```

`backend/dashboard.py` 只负责组装现有摘要并传给 `backend.readiness`。就绪度规则不能写散在 dashboard 模块里。

### 指标

修改 `backend/metrics.py`，导出以下就绪度指标：

- `ops_platform_readiness_status`
- `ops_platform_readiness_area_status{area="..."}`
- `ops_platform_readiness_action_required_total`

状态数值：

- `ready` = 0
- `attention` = 1
- `blocked` = 2

指标可以来自运行时仪表盘快照，也可以来自同一个后端 readiness 辅助函数。指标不能暴露私有主机标签或真实配置明细，只输出聚合状态和固定区域标签。

### 前端

新增 `public/js/readiness.js`。

职责：

- 从 `state.dashboard.platformReadiness` 渲染平台就绪度面板。
- 展示整体状态、区域计数和处置建议清单。
- 文案保持简洁、偏运维操作，不做营销式说明。
- 不引入大型首屏、装饰背景、卡片嵌套或无关视觉改动。

修改 `public/index.html`，在页面顶部靠前位置增加就绪度区域，放在系统通知后、详细应急处置手册前。

修改 `public/js/app.js`，导入并在 `render()` 中调用就绪度渲染函数。

修改 `public/styles.css`，添加和现有运维面板一致的紧凑样式。

### 系统通知

`public/js/notices.js` 继续只承担短全局警告。仅当整体就绪度不是 `ready` 时，增加一条简短的平台就绪度提示。详细处置建议清单必须放在 `public/js/readiness.js` 的面板中。

## 验证

本阶段必须完成以下验证：

- 聚焦后端 readiness 单元测试。
- 仪表盘载荷测试，证明 `platformReadiness` 存在且字段完整。
- 指标测试，证明 readiness gauges 已导出。
- 前端模块测试，证明面板、渲染函数、导入和 render 调用存在。
- 全量测试：`python -m unittest discover -s tests`。
- 运行态 HTTP 检查 `/api/dashboard`，确认返回 `platformReadiness`。
- 运行态 HTTP 检查 `/metrics`，确认返回 `ops_platform_readiness_*`。
- 运行态 UTF-8 拉取 `/` 和 `/js/readiness.js`，确认中文标签正常输出。

## 验收标准

本阶段完成的标准：

- `/api/dashboard` 包含 `platformReadiness` 对象，且包括整体状态、区域列表和处置建议。
- 页面中可见平台就绪度面板。
- 面板能解释当前纳管缺口，不要求运维人员去多个分散面板里拼信息。
- `/metrics` 输出整体和各区域就绪度指标。
- 渲染就绪度不会执行任何真实自动化动作。
- 不新增暴露私有配置值。
- `app.py` 不增加就绪度业务规则。
- 所有测试通过。
- 完成后提交并推送到 `origin/master`。

## 风险和控制

- 风险：就绪度信息和现有通知条重复。
  控制：详细处置建议只放在就绪度面板，系统通知只保留一条简短摘要。

- 风险：就绪度变成模糊分数。
  控制：不使用百分比，直接报告命名区域和具体下一步动作。

- 风险：指标泄露私有基础设施信息。
  控制：只输出聚合计数和固定区域标签。

- 风险：本阶段拖慢实际自动化接入。
  控制：保持只读、边界窄；输出结果直接作为下一阶段启用资源、证书、账号、备份和恢复的依据。

## 审批后的下一阶段

这份设计文档审查通过后，生成一个小步 TDD 实施计划：

1. 后端 readiness 模块。
2. 仪表盘载荷集成。
3. 指标导出。
4. 前端 readiness 模块和面板。
5. 运行态验证和 git 同步。

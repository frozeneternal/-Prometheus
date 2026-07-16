# 资源详情鉴权与前端管理门禁设计

## 目标

把资源到期能力从“公开页面直接返回全部详情”改造成清晰的权限边界：未认证访问只能读取资源风险汇总，只有通过操作认证的运维人员才能读取资源明细、续费入口、负责人、备注、确认人和管理按钮。

本批不添加真实资源，不执行续费，也不改变服务器、网站、证书、备份或恢复策略。它先为后续录入真实域名、账号、授权、合同和云资源建立可靠的数据保护边界。

## 当前问题

当前实现存在以下风险：

- `GET /api/config` 公开返回资源 ID、名称、供应商、负责人、关联目标、到期时间、续费入口和备注。
- `GET /api/dashboard` 公开返回完整 `resourceExpiryItems`，其中还包含确认人、确认时间和处置状态。
- Dashboard 的资源应急项、资源配置校验问题和资源操作日志会间接暴露资源名称、目标 ID、到期值、来源地址或操作人。
- 前端资源表单和编辑、删除、确认按钮始终显示，没有读取权限门禁。
- 前端编辑资源时没有回填和提交 `linkedTarget`、`warningDays`、`criticalDays`，容易造成已有配置被静默丢失。
- 资源续费地址只校验 `http/https`，仍可能包含 URL 用户信息或敏感查询参数。

## 威胁模型

需要防止以下情况：

- 未登录访问者从公开接口枚举真实资源、负责人、供应商、续费入口和内部关联目标。
- viewer 账号越权读取或管理资源明细。
- 用户模式误把 `X-Action-Token` 当成账号会话的替代凭据。
- token 模式通过查询字符串、请求体、浏览器持久化或日志泄露操作口令。
- 退出登录、会话过期、认证模式切换或并发请求返回较晚时，旧的敏感资源数据继续留在状态或 DOM 中。
- 续费链接通过 `user:password@host` 或 `token`、`secret`、`password` 等查询参数携带秘密。

## 权限模型

资源详情固定要求 `operator` 角色：

- 未认证访问者：只能读取资源风险汇总。
- viewer：只能读取资源风险汇总。
- operator、admin：可以读取、确认、新增、编辑和删除资源。
- token 模式：正确的操作口令等价于资源管理权限。
- 未配置任何操作认证：资源详情和管理功能保持阻断。

后端是最终权限边界。前端门禁只改善操作体验，不能替代后端鉴权。

## 后端设计

### 分层模块

新增 `backend/resource_access.py`，只负责资源访问边界：

- 从请求头解析资源详情凭据。
- 按固定字段白名单投影受保护的资源详情。
- 生成公开 Dashboard 投影，移除所有资源明细出口。
- 从公开恢复日志中移除资源操作事件。
- 返回受保护接口需要的缓存控制响应头。

`app.py` 只负责路由、调用模块和写 HTTP 响应，不放置资源权限规则。

### 公开接口

`GET /api/config` 保留现有公开配置形状，但固定返回：

```json
{
  "resources": [],
  "resourceDetailsProtected": true
}
```

`GET /api/dashboard` 保留 `resourceExpirySummary` 聚合数据，但必须：

- 把 `resourceExpiryItems` 设为空数组。
- 设置 `resourceDetailsProtected: true`。
- 移除 `targetType == "resource"` 的应急明细。
- 移除 `targetType == "resource"` 的配置校验明细。
- 移除资源新增、删除、确认产生的恢复日志。
- 不修改运行时缓存的原始 Dashboard 对象。

`GET /api/recovery-logs` 同样移除资源操作日志。资源操作事件按 `targetType`、`invocation` 和 `actionId` 三个维度防御性识别，避免旧日志或畸形日志绕过过滤。

资源总数、到期风险数量、平台就绪度资源区域和全局问题计数可以继续公开，因为它们是无标识的聚合状态。

### 受保护接口

新增 `GET /api/resources`。现有三个资源写接口同时迁移到同一套请求头鉴权：

- `POST /api/settings/resource-upsert`
- `POST /api/settings/resource-delete`
- `POST /api/settings/resource-ack`

用户模式只接受：

```http
Authorization: Bearer <session-token>
```

token 模式只接受：

```http
X-Action-Token: <action-token>
```

约束：

- 所有资源读写都不从查询字符串或 JSON 请求体读取凭据。
- 用户模式绝不回退到 `X-Action-Token`。
- token 模式不接受 `Authorization` 作为替代。
- 缺失或无效凭据返回 `401`。
- viewer 返回 `403`。
- 未配置操作认证返回 `403`，并保持失败闭合。
- 响应增加 `Cache-Control: private, no-store`、`Pragma: no-cache` 和 `Vary: Authorization, X-Action-Token`。

成功响应固定为：

```json
{
  "ok": true,
  "resourceDetailsProtected": true,
  "items": [],
  "capabilities": {
    "viewResourceDetails": true,
    "manageResources": true,
    "acknowledgeResourceExpiry": true
  },
  "auth": {
    "mode": "session",
    "user": {
      "username": "example",
      "displayName": "Example",
      "role": "operator"
    }
  }
}
```

token 模式的 `auth.mode` 为 `legacy-token`，`auth.user` 为 `null`。响应绝不回显会话 token 或操作口令。

三个资源写接口成功时只返回 `ok`、`message` 和 `logId`，不再返回完整 Dashboard。前端随后分别刷新公开 Dashboard 和受保护资源详情，避免把不必要的私有载荷混入通用页面状态。

### 资源字段白名单

`items` 只允许以下字段：

- 标识与分类：`id`、`name`、`type`、`linkedTarget`。
- 处置责任：`provider`、`owner`、`renewUrl`、`notes`。
- 到期判断：`expiresAt`、`daysRemaining`、`warningDays`、`criticalDays`、`status`、`message`。
- 确认状态：`acknowledged`、`acknowledgedUntil`、`acknowledgedBy`、`acknowledgedAt`。
- 处置状态：`actionRequired`、`handlingReady`、`missingHandlingFields`、`handlingMessage`。

未知配置字段、原始日志、来源 IP、内部命令、认证值和未列出的运行时字段不得进入响应。

### 续费地址安全

`safe_resource_renew_url()` 在现有协议校验基础上增加：

- 拒绝包含控制字符的 URL。
- 拒绝 URL 用户名或密码。
- 拒绝无有效主机名或端口非法的 URL。
- 拒绝查询键为 `token`、`access_token`、`api_key`、`apikey`、`key`、`secret`、`password`、`passwd`、`auth`、`authorization` 的 URL，键名大小写不敏感。
- 允许普通业务查询参数，例如 `product=domain`。

## 前端设计

### 访问状态模块

新增 `public/js/resource-access.js`，集中管理：

- 当前资源访问状态和能力。
- 用户模式的 Bearer 请求头。
- token 模式仅保存在模块闭包内的操作口令。
- 受保护资源详情加载。
- 会话失效、退出、模式变化和请求竞态时的资源数据清理。

操作口令不写入 `state`、`localStorage`、`sessionStorage`、URL 或日志。口令输入提交后立即清空。模块使用递增请求代次，较旧请求即使稍后成功也不能恢复已清理的数据。

`public/js/state.js` 只保存非秘密状态：

- `resourceDetails`：当前已授权资源明细。
- `resourceAccess`：`locked`、`loading`、`ready`、`denied` 或 `error`，以及服务端返回的 capabilities。

### 页面门禁

资源区域继续公开显示汇总计数。详情区新增紧凑访问状态栏：

- 用户模式下，operator/admin 登录后自动加载详情。
- viewer 显示权限不足状态，不发起越权管理操作。
- token 模式显示口令输入与解锁按钮。
- 未配置认证时显示阻断状态。
- 只有 `manageResources` 为真时显示资源表单和编辑、删除按钮。
- 只有 `acknowledgeResourceExpiry` 为真时显示确认按钮。

退出登录、会话失效、认证模式切换、资源接口 `401/403` 或页面级错误时，必须同步清空 `resourceDetails`、表单内容、资源卡片 DOM 和闭包内口令。

### 表单完整性

资源表单新增：

- `linkedTarget` 文本输入。
- `warningDays` 数字输入，最小值为 1。
- `criticalDays` 数字输入，最小值为 0。

编辑时必须回填，提交时必须包含这些字段；空阈值不伪造字符串值。未知但合法的 `linkedTarget` 原样保留，不用前端选项列表强行覆盖。

资源新增、编辑、删除或确认时，资源数据放在 JSON 请求体，认证凭据只放在模式对应请求头。成功后不再把写接口返回值作为页面 Dashboard，而是重新加载公开 Dashboard 和受保护资源详情。

## 错误处理

- 资源详情请求失败不影响服务器、网站和资源汇总继续显示。
- `401` 清理当前资源凭据和详情，状态回到锁定。
- `403` 清理详情并显示权限不足或认证未配置。
- 网络或服务错误清理详情并显示可重试状态，不展示上一次缓存。
- 公开投影遇到畸形数组、日志、校验问题或应急项时跳过无效值，不抛出敏感原始内容。

## 测试与验证

后端必须覆盖：

- 公开配置不含资源明细。
- 公开 Dashboard 同时过滤资源 items、应急项、校验问题和操作日志，且不修改原对象。
- 公开恢复日志过滤所有资源操作事件。
- 用户、viewer、token、错误模式、缺失凭据和模式隔离。
- 四个资源读写路由都拒绝查询参数和 JSON 请求体中的凭据。
- 字段白名单、响应头和不回显秘密。
- 续费 URL 用户信息与敏感查询参数拒绝。
- `GET /api/resources` 路由只读取请求头。

前端必须覆盖：

- 新模块、访问状态栏、表单字段和客户端路由接线。
- operator/admin 自动加载、viewer 阻断、token 解锁。
- 退出、`401/403`、模式切换和迟到响应不能保留或恢复敏感 DOM。
- 管理和确认按钮只按服务端 capability 显示。
- linkedTarget 与资源级阈值编辑后不丢失。
- 桌面 `1440x900` 和移动端 `390x844` 无溢出、重叠或口令残留。

最终运行全量测试，重启本地应用后检查公开接口、受保护接口、浏览器控制台和响应缓存头。

## 验收标准

- 匿名访问不能从任何公开资源相关出口获得资源标识、名称、负责人、供应商、到期值、关联目标、续费入口、备注、确认人或来源 IP。
- viewer 不能读取 `/api/resources`，也看不到资源管理控件。
- 资源新增、删除和确认不能使用请求体里的 token 或 sessionToken 绕过请求头鉴权。
- operator/admin 或正确操作口令可以读取和管理资源。
- 认证切换和失败后没有旧资源明细留在状态或 DOM。
- 前端编辑不再丢失 `linkedTarget`、`warningDays`、`criticalDays`。
- 续费 URL 不接受明显的凭据承载形式。
- 后端规则位于 `backend/`，前端状态规则位于独立 ES module，`app.py` 只保留路由胶水。
- 聚焦测试、全量测试、HTTP 检查和桌面/移动浏览器检查全部通过。

## 不在本批范围

- 录入真实资源记录。
- 自动执行域名、授权或合同续费。
- 把所有服务器和网站详情改成登录后可见。
- 重构现有账号会话在 `localStorage` 中的存储方式。
- 向资源详情接口返回操作日志或完整配置校验报告。

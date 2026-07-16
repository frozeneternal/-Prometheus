# 资源详情鉴权与前端管理门禁实施计划

> **Agent 执行要求：** 使用 `superpowers:subagent-driven-development` 按任务执行；每个实现任务先用 `superpowers:test-driven-development` 完成红、绿、重构，再依次做规格审查和代码质量审查。步骤使用复选框跟踪。

**目标：** 公开页面只暴露资源风险汇总，operator/admin 或正确操作口令通过受保护接口读取和管理完整资源详情，并保证认证变化后敏感状态立即清理。

**架构：** 新建 `backend/resource_access.py` 作为资源访问边界，`app.py` 只接入路由和响应头；新建 `public/js/resource-access.js` 管理非持久化凭据、访问状态、请求竞态和详情清理。公开 Dashboard 与受保护详情保持两个独立数据源，前端不得把受保护数据重新写回公开 Dashboard 载荷。

**技术栈：** Python 3 标准库、`unittest`、原生 ES Modules、HTML/CSS、Playwright、Git。

---

## 文件边界

- 新建 `backend/resource_access.py`：请求头鉴权、字段白名单、公开 Dashboard 投影、资源日志过滤和私有响应头。
- 修改 `backend/public_view.py`：公开配置固定隐藏资源数组。
- 修改 `backend/expiry.py`：强化续费 URL 安全校验。
- 修改 `app.py`：接入 `GET /api/resources`，把三个资源写路由迁移到请求头鉴权，为 JSON 响应支持额外响应头，并对公开 Dashboard/恢复日志应用投影。
- 新建 `tests/test_resource_access.py`：覆盖资源访问领域规则和 GET 路由。
- 新建 `public/js/resource-access.js`：资源访问凭据、状态、并发代次和清理。
- 修改 `public/js/api.js`：错误对象携带 HTTP 状态码。
- 修改 `public/js/client.js`：增加带请求头的资源详情 GET。
- 修改 `public/js/state.js`：增加非秘密资源访问状态。
- 修改 `public/js/accounts.js`：退出或会话失效时清理资源详情。
- 修改 `public/js/actions.js`：资源写操作后重新加载公开 Dashboard 和受保护详情。
- 修改 `public/js/app.js`：资源详情改读独立状态，接入门禁、解锁和完整表单字段。
- 修改 `public/index.html`：增加资源访问状态栏和缺失字段。
- 修改 `public/styles.css`：增加紧凑、响应式门禁布局。
- 修改 `tests/test_frontend_modules.py`：覆盖接线、浏览器行为、竞态清理和表单完整性。
- 更新 `README.md`：用中文说明公开汇总与受保护资源详情的接口边界。
- 更新桌面中文总览文档：记录本批能力和验证结果，不包含远程仓库、分支、提交或推送信息。

### 任务 1：后端资源访问边界

**文件：**

- 新建：`backend/resource_access.py`
- 新建：`tests/test_resource_access.py`
- 修改：`backend/public_view.py`
- 修改：`backend/expiry.py`
- 修改：`app.py`
- 修改：`README.md`

- [ ] **步骤 1：写公开投影失败测试**

在 `tests/test_resource_access.py` 构造包含资源详情、资源应急项、资源校验问题、资源操作日志和普通服务器日志的 Dashboard，断言：

```python
public = public_dashboard_view(source)
self.assertEqual(public["resourceExpiryItems"], [])
self.assertTrue(public["resourceDetailsProtected"])
self.assertFalse(any(item.get("targetType") == "resource" for item in public["emergencyItems"]))
self.assertFalse(any(item.get("targetType") == "resource" for item in public["configValidation"]["issues"]))
self.assertFalse(any(item.get("targetType") == "resource" for item in public["recoveryLogs"]))
self.assertEqual(source["resourceExpiryItems"][0]["owner"], "private-owner")
self.assertEqual(public["resourceExpirySummary"], source["resourceExpirySummary"])
```

同时断言 `public_config(config)["resources"] == []` 且 `resourceDetailsProtected` 为真。

- [ ] **步骤 2：运行红测并确认模块缺失**

运行：

```powershell
python -m unittest tests.test_resource_access.ResourceAccessTests.test_public_views_remove_every_resource_detail_exit -v
```

预期：失败，原因包含 `ModuleNotFoundError: No module named 'backend.resource_access'`。

- [ ] **步骤 3：实现公开投影和资源日志识别**

在 `backend/resource_access.py` 实现以下稳定接口：

```python
RESOURCE_INVOCATIONS = frozenset({"resource-upsert", "resource-delete", "resource-ack"})

def is_resource_operation_log(event: object) -> bool:
    if not isinstance(event, dict):
        return False
    return (
        str(event.get("targetType") or "") == "resource"
        or str(event.get("invocation") or "") in RESOURCE_INVOCATIONS
        or str(event.get("actionId") or "") in RESOURCE_INVOCATIONS
    )

def public_recovery_logs(logs: object) -> list[dict]:
    if not isinstance(logs, list):
        return []
    return [dict(event) for event in logs if isinstance(event, dict) and not is_resource_operation_log(event)]

def public_dashboard_view(dashboard: object) -> dict:
    source = dashboard if isinstance(dashboard, dict) else {}
    result = dict(source)
    result["resourceExpiryItems"] = []
    result["resourceDetailsProtected"] = True
    result["recoveryLogs"] = public_recovery_logs(source.get("recoveryLogs"))
    result["emergencyItems"] = [
        dict(item) for item in source.get("emergencyItems", [])
        if isinstance(item, dict) and str(item.get("targetType") or "") != "resource"
    ]
    validation = source.get("configValidation")
    if isinstance(validation, dict):
        public_validation = dict(validation)
        public_validation["issues"] = [
            dict(issue) for issue in validation.get("issues", [])
            if isinstance(issue, dict) and str(issue.get("targetType") or "") != "resource"
        ]
        result["configValidation"] = public_validation
    return result
```

在 `backend/public_view.py` 移除资源记录投影，固定输出空数组和保护标记。

- [ ] **步骤 4：写鉴权和字段白名单失败测试**

覆盖以下行为：

```python
self.assertEqual(resource_details_response(users_config, {})[0], 401)
self.assertEqual(resource_details_response(users_config, {"X-Action-Token": "legacy"})[0], 401)
self.assertEqual(resource_details_response(users_config, viewer_headers)[0], 403)
self.assertEqual(resource_details_response(users_config, operator_headers)[0], 200)
self.assertEqual(resource_details_response(token_config, {"Authorization": "Bearer ignored"})[0], 401)
self.assertEqual(resource_details_response(token_config, {"X-Action-Token": "valid"})[0], 200)
```

成功响应断言 `items` 的键集合严格等于字段白名单，`auth` 和序列化响应中不含会话 token、操作口令、未知字段、来源 IP 或日志。

- [ ] **步骤 5：运行红测并确认受保护响应尚不存在**

运行：

```powershell
python -m unittest tests.test_resource_access.ResourceAccessTests.test_resource_details_enforces_mode_exclusive_headers_and_operator_role -v
```

预期：失败，原因包含无法导入 `resource_details_response`。

- [ ] **步骤 6：实现请求头鉴权和资源白名单**

`backend/resource_access.py` 导入 `users_enabled`、`verify_session_token`、`role_allows`、`verify_action_token` 和 `resource_expiry_items`。请求头鉴权提取为 `authorize_resource_request(config, headers)`，GET 和三个 POST 路由必须复用。固定：

```python
RESOURCE_DETAIL_FIELDS = (
    "id", "name", "type", "provider", "owner", "linkedTarget", "renewUrl", "notes",
    "expiresAt", "daysRemaining", "warningDays", "criticalDays", "status", "message",
    "acknowledged", "acknowledgedUntil", "acknowledgedBy", "acknowledgedAt",
    "actionRequired", "handlingReady", "missingHandlingFields", "handlingMessage",
)

RESOURCE_PRIVATE_HEADERS = {
    "Cache-Control": "private, no-store",
    "Pragma": "no-cache",
    "Vary": "Authorization, X-Action-Token",
}
```

用户模式只解析严格的 Bearer 头并验证 operator；token 模式只读取 `X-Action-Token`。成功后对 `resource_expiry_items(config)` 的每项按 `RESOURCE_DETAIL_FIELDS` 复制，列表字段必须新建列表副本。

- [ ] **步骤 7：写续费 URL 失败测试并执行红测**

在 `tests/test_resource_access.py` 增加：

```python
self.assertEqual(safe_resource_renew_url("https://user:pass@example.test/renew"), "")
self.assertEqual(safe_resource_renew_url("https://example.test/renew?token=secret"), "")
self.assertEqual(safe_resource_renew_url("https://example.test/renew?ACCESS_TOKEN=secret"), "")
self.assertEqual(safe_resource_renew_url("https://example.test/renew?product=domain"), "https://example.test/renew?product=domain")
```

运行：

```powershell
python -m unittest tests.test_resource_access.ResourceAccessTests.test_renew_url_rejects_embedded_credentials -v
```

预期：失败，旧实现仍返回包含用户信息或 token 的 URL。

- [ ] **步骤 8：强化续费 URL 校验**

在 `backend/expiry.py` 使用 `urllib.parse.parse_qsl()` 检查查询键；访问 `parsed.hostname` 和 `parsed.port` 时捕获 `ValueError`。包含控制字符、用户信息、敏感查询键、无主机名或非法端口时返回空字符串。

- [ ] **步骤 9：写资源读写路由和响应头失败测试**

使用轻量 handler 替身调用 `MonitorHandler.do_GET()`，断言 `/api/resources?token=ignored`：

- 查询参数不能授权。
- 正确请求头返回 200。
- `json_response()` 收到 `Cache-Control`、`Pragma` 和 `Vary`。
- `/api/dashboard` 调用公开投影。
- `/api/recovery-logs` 调用资源日志过滤。

再调用三个资源 `POST` 路由，断言：

- JSON 中的 `token`、`sessionToken` 和 `_sessionToken` 均不能授权。
- 模式对应的正确请求头可以授权。
- 用户模式不能用 `X-Action-Token` 降级授权，token 模式不能用 Bearer 替代。
- 成功响应只含 `ok`、`message` 和 `logId`，不含 Dashboard、资源详情或请求凭据。

- [ ] **步骤 10：运行路由红测**

运行：

```powershell
python -m unittest tests.test_resource_access.ResourceAccessRouteTests -v
```

预期：失败，因为 `/api/resources` 尚未接入或 `json_response` 不接受额外响应头。

- [ ] **步骤 11：接入路由和缓存头**

把 `json_response` 改为：

```python
def json_response(handler, status: int, payload: dict, headers: dict[str, str] | None = None) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    for name, value in (headers or {}).items():
        handler.send_header(name, value)
    handler.end_headers()
    handler.wfile.write(body)
```

在 `do_GET()` 中：

- `/api/dashboard` 对运行态原始 Dashboard 调用 `public_dashboard_view()`。
- `/api/recovery-logs` 调用 `public_recovery_logs()`。
- `/api/resources` 调用 `resource_details_response(config, self.headers)`，并始终带 `RESOURCE_PRIVATE_HEADERS`。
- 三个资源写路由调用 `authorize_resource_request(config, self.headers)`，不再把 JSON body 传给通用 `authorize_operation()`。
- 三个资源写路由直接返回持久化函数的最小结果，不再调用 `settings_response()`。

- [ ] **步骤 12：更新中文 README 并验证后端批次**

README 说明公开接口只提供汇总，资源详情凭据必须通过模式对应请求头，不提供真实 token 示例。

运行：

```powershell
python -m unittest tests.test_resource_access tests.test_resource_expiry tests.test_backend_modules tests.test_accounts -v
```

预期：全部通过并输出 `OK`。

- [ ] **步骤 13：提交并同步后端资源访问边界**

运行：

```powershell
git add backend/resource_access.py backend/public_view.py backend/expiry.py app.py README.md tests/test_resource_access.py tests/test_backend_modules.py
git commit -m "Protect resource detail access"
git push origin master
```

预期：提交成功，远端 `master` 同步成功。

### 任务 2：前端资源访问状态和门禁

**文件：**

- 新建：`public/js/resource-access.js`
- 修改：`public/js/api.js`
- 修改：`public/js/client.js`
- 修改：`public/js/state.js`
- 修改：`public/js/accounts.js`
- 修改：`public/js/actions.js`
- 修改：`public/js/app.js`
- 修改：`public/index.html`
- 修改：`public/styles.css`
- 修改：`tests/test_frontend_modules.py`

- [ ] **步骤 1：写前端模块和 DOM 接线失败测试**

断言：

```python
self.assertTrue((PUBLIC / "js" / "resource-access.js").exists())
self.assertIn('id="resourceAccessPanel"', index_html)
self.assertIn('id="resourceAccessForm"', index_html)
self.assertIn('id="resourceAccessToken"', index_html)
self.assertIn('type="password"', resource_access_form)
self.assertIn('id="resourceLinkedTarget"', index_html)
self.assertIn('id="resourceWarningDays"', index_html)
self.assertIn('id="resourceCriticalDays"', index_html)
self.assertIn('from "./resource-access.js"', app_js)
self.assertIn('getJson("/api/resources", { headers })', client_js)
self.assertIn("error.status = response.status", api_js)
```

- [ ] **步骤 2：运行红测**

运行：

```powershell
python -m unittest tests.test_frontend_modules.FrontendModuleTests.test_resource_access_has_layered_frontend_gate -v
```

预期：失败，原因是新模块和访问 DOM 不存在。

- [ ] **步骤 3：实现客户端、状态和访问模块**

在 `public/js/api.js` 的错误分支增加 `error.status = response.status`。

在 `public/js/client.js` 增加：

```javascript
export function fetchResourceDetails(headers) {
  return getJson("/api/resources", { headers });
}
```

把 `postJson()` 改成合并 JSON 头和调用方认证头：

```javascript
function postJson(url, body, headers = {}) {
  return getJson(url, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...headers },
    body: JSON.stringify(body),
  });
}
```

三个资源写客户端函数改为接收 `headers`，请求体只包含 `resource`、`resourceId` 或 `acknowledgedUntil`，例如：

```javascript
export function acknowledgeResourceExpiryRisk({ resourceId, acknowledgedUntil, headers }) {
  return postJson("/api/settings/resource-ack", { resourceId, acknowledgedUntil }, headers);
}
```

在 `state` 增加：

```javascript
resourceDetails: [],
resourceAccess: { status: "locked", authMode: "", capabilities: {}, message: "" },
```

`public/js/resource-access.js` 使用模块闭包 `let actionToken = ""` 和 `let requestGeneration = 0`。导出：

```javascript
export function setResourceActionToken(value) {}
export function resourceAuthHeaders() {}
export function syncResourceAuthMode() {}
export function purgeResourceDetails(message = "") {}
export async function loadResourceDetails() {}
export function renderResourceAccess() {}
```

用户模式只为 operator/admin 发送 `Authorization`；token 模式只有闭包口令非空时发送 `X-Action-Token`。同一函数生成资源 GET 和三个资源 POST 的认证头，任何资源请求体都不得包含 `token`、`sessionToken` 或 `_sessionToken`。每次加载捕获当前 generation，响应返回时 generation 已变化则直接丢弃。`401/403` 必须清空详情，`401` 同时清空闭包口令。

- [ ] **步骤 4：接入页面门禁和完整表单**

在资源表单前增加访问状态栏和 token 解锁表单。资源管理表单默认 `hidden`。新增：

```html
<input id="resourceLinkedTarget" name="resourceLinkedTarget" autocomplete="off" placeholder="关联目标">
<input id="resourceWarningDays" name="resourceWarningDays" type="number" min="1" step="1" placeholder="预警天数">
<input id="resourceCriticalDays" name="resourceCriticalDays" type="number" min="0" step="1" placeholder="临界天数">
```

`app.js` 的资源卡片、编辑和应急资源动作统一读取 `state.resourceDetails`。`resourceFormPayload()` 仅在阈值输入非空时写入 Number 值，并始终保留 `linkedTarget`。

只有 capability 允许时生成管理或确认按钮；不能只依据本地角色猜测 capability。

- [ ] **步骤 5：接入认证生命周期和写后刷新**

- `refreshDashboard()` 在公开 Dashboard 成功后调用 `loadResourceDetails()`，资源详情失败不覆盖其他监控数据。
- token 解锁提交后立即清空 input，再加载资源详情。
- `refreshSession()` 无效和 `logoutCurrentUser()` 开始时调用 `purgeResourceDetails()`。
- `loadConfig()` 只在认证模式变化时清理闭包口令和详情。
- `actions.js` 的资源确认、新增、编辑、删除使用 `resourceAuthHeaders()`，请求体只含业务数据；成功后调用 `runtime.refreshDashboard()`，不再执行 `state.dashboard = payload`。
- 页面级 `renderError()` 清理资源详情和表单 DOM。

- [ ] **步骤 6：写并发、退出和权限浏览器失败测试**

用 Playwright 加载测试 DOM 和真实 ES module，模拟可控 `fetch`：

1. token 解锁后返回资源卡片和管理控件。
2. `localStorage`、`sessionStorage` 和 URL 不包含口令。
3. 调用 purge 后卡片、表单值和管理控件为空。
4. purge 后再完成旧请求，旧资源不会恢复。
5. viewer 不请求或不显示详情。
6. operator 的 Bearer 请求成功后显示详情。
7. 服务端 capability 关闭管理或确认时，对应按钮不存在。

- [ ] **步骤 7：运行浏览器红测并完善实现**

运行：

```powershell
python -m unittest tests.test_frontend_modules.FrontendModuleTests.test_resource_access_runtime_purges_sensitive_state_and_stale_responses -v
```

预期：首次因行为未完整接线而失败；修复后重新运行并通过。

- [ ] **步骤 8：增加响应式样式**

访问状态栏使用无嵌套卡片的全宽紧凑布局，圆角不超过 8px。资源表单在桌面保持稳定网格，在 `520px` 以下改为单列；口令、最长关联目标和错误文本必须换行，不得横向溢出。

- [ ] **步骤 9：验证前端批次**

运行：

```powershell
python -m unittest tests.test_frontend_modules -v
```

预期：全部通过，UTF-8 扫描、模块导入和浏览器行为测试均输出 `OK`。

- [ ] **步骤 10：提交并同步前端资源门禁**

运行：

```powershell
git add public/js/resource-access.js public/js/api.js public/js/client.js public/js/state.js public/js/accounts.js public/js/actions.js public/js/app.js public/index.html public/styles.css tests/test_frontend_modules.py
git commit -m "Gate resource management by access"
git push origin master
```

预期：提交成功，远端 `master` 同步成功。

### 任务 3：整体验收和中文总览更新

**文件：**

- 修改：`C:\Users\Administrator\Desktop\1\服务器资源整理项目总览-2026-07-15.md`

- [ ] **步骤 1：运行聚焦测试**

运行：

```powershell
python -m unittest tests.test_resource_access tests.test_resource_expiry tests.test_accounts tests.test_frontend_modules -v
```

预期：全部通过并输出 `OK`。

- [ ] **步骤 2：运行全量回归**

运行：

```powershell
python -m unittest discover -s tests
```

预期：全部通过，无失败、错误、warning 或 traceback。

- [ ] **步骤 3：重启应用并检查 HTTP 边界**

重启 `127.0.0.1:8787` 当前应用后执行：

```powershell
$config = Invoke-RestMethod -Uri 'http://127.0.0.1:8787/api/config' -TimeoutSec 30
$dashboard = Invoke-RestMethod -Uri 'http://127.0.0.1:8787/api/dashboard' -TimeoutSec 30
$logs = Invoke-RestMethod -Uri 'http://127.0.0.1:8787/api/recovery-logs' -TimeoutSec 30
if ($config.config.resources.Count -ne 0) { throw '公开配置泄露资源详情' }
if ($dashboard.resourceExpiryItems.Count -ne 0) { throw '公开 Dashboard 泄露资源详情' }
if (($dashboard.emergencyItems | Where-Object targetType -eq 'resource').Count -ne 0) { throw '公开应急项泄露资源详情' }
if (($dashboard.configValidation.issues | Where-Object targetType -eq 'resource').Count -ne 0) { throw '公开校验项泄露资源详情' }
if (($logs.logs | Where-Object targetType -eq 'resource').Count -ne 0) { throw '公开日志泄露资源操作' }
```

对 `/api/resources` 检查：

- 无凭据为 `401` 或认证未配置时为 `403`。
- 当前认证模式对应的正确请求头为 `200`。
- 错误模式请求头不能授权。
- `Cache-Control` 包含 `private, no-store`。
- `Vary` 同时包含 `Authorization` 和 `X-Action-Token`。
- 响应不回显请求凭据。

- [ ] **步骤 4：浏览器桌面与移动验收**

使用 Playwright 检查 `http://127.0.0.1:8787/`：

- `1440x900`：资源汇总、访问状态、表单和卡片无重叠或横向溢出。
- `390x844`：口令输入、状态、表单字段和资源卡片正常换行。
- 未解锁时 DOM 中没有资源卡片、续费链接、负责人、备注或管理按钮。
- 解锁后 capability 对应的按钮可用。
- 退出或模拟 `401` 后 DOM 立即清空，浏览器控制台无错误。

- [ ] **步骤 5：更新桌面中文总览**

记录：

- 新的资源详情访问边界和角色要求。
- 公开汇总与受保护详情的区别。
- 前端门禁、状态清理和表单完整性。
- 聚焦测试、全量测试、HTTP 和浏览器检查结果。

禁止写远程地址、仓库名称、分支、提交哈希、提交历史和推送步骤。

- [ ] **步骤 6：最终状态核对**

运行：

```powershell
git status -sb
git log -5 --oneline
git push origin master
```

预期：工作树干净，本批后端和前端功能均已同步。

## 完成定义

- 所有公开资源明细出口已关闭，只保留无标识聚合。
- 资源详情接口按认证模式独占请求头，并要求 operator/admin。
- 私有响应不可缓存，不回显凭据，只含字段白名单。
- 前端凭据不持久化，退出、失败、模式变化和竞态都能清理敏感状态与 DOM。
- 资源编辑完整保留关联目标和两个阈值。
- 后端、前端、README 和测试保持现代分层目录。
- 聚焦、全量、HTTP、桌面和移动验收全部通过。
- 每个功能批次独立提交并同步，桌面中文总览不包含 Git 上传信息。

# REST API 参考

Base: `http://<server>:8080`。除 `POST /api/login` 外全部需要会话 cookie
（`openxdr_session`）。权限约定：**GET = viewer 及以上，写操作 = analyst 及以上，
`/api/users` 与 `/api/audit` = admin**。

## 认证

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/login` | `{"username","password"}` → 设置会话 cookie。失败按源 IP 指数退避 |
| POST | `/api/logout` | 吊销当前会话 |
| GET | `/api/me` | 当前用户 `{username, role}` |

## 事件与告警

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/incidents?status=` | incident 列表（最新 50 条），含派生严重度与告警数 |
| GET | `/api/incidents/{id}` | 详情：实体图、告警明细（含原始事件）、AI verdict |
| POST | `/api/incidents/{id}/status` | `{"status":"open\|closed\|false_positive"}` |
| GET | `/api/incidents/{id}/report` | 事件报告（Markdown 附件下载）：判定、攻击链、涉及实体、告警时间线、处置记录、处置建议 |
| GET | `/api/events` | 原始事件检索，参数见下 |
| GET | `/api/stats` | 概览：24h 降噪漏斗、告警趋势、Top 规则、资产在线率 |
| GET | `/api/rules` | 引擎当前加载的规则（热重载后即时反映），含数据源覆盖标记与 ATT&CK 标签 |
| GET | `/api/attack` | ATT&CK 覆盖矩阵：按杀伤链顺序的战术列与技术格，含未打标签、无数据源的规则数 |
| POST | `/api/hunt` | 自然语言狩猎：`{"question"}` → `{answer, steps}`。模型用只读调查工具查证后作答，`steps` 是调用过的工具与参数，供复核。未配置 `AI_MODEL` 返回 503 |

`GET /api/events` 参数：`from`/`to`（RFC3339，默认近 24h）、`assetId`、
`classUid`（1001 文件 / 1007 进程 / 3002 认证 / 4001 网络 / 4003 DNS /
201002 注册表 / 100001 日志）、
`source`（agent/sensor/syslog）、`q`（对事件体子串匹配，通配符按字面量处理）、
`limit`（≤200，默认 100）。各类事件的字段 schema 见
[events.md](events.md)。

## 威胁情报

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/intel` | IOC 清单（含命中计数） |
| POST | `/api/intel` | 单条：`{"kind":"ip\|domain\|hash","value","source","severity","note","expiresInDays"}`，kind 缺省自动识别 |
| POST | `/api/intel/import` | 批量：`{"text":"一行一条","source","severity","expiresInDays"}`，类型自动识别，重复跳过，`#` 行忽略 |
| DELETE | `/api/intel/{id}` | 删除 |

## 误报抑制

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/suppressions` | 抑制清单（含压掉次数） |
| POST | `/api/suppressions` | `{"ruleId","assetId"(空=全局),"reason","expiresInDays"(0=长期)}` |
| DELETE | `/api/suppressions/{id}` | 撤销 |

## 响应处置

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/commands?incidentId=` | 指令历史 |
| POST | `/api/commands` | `{"kind":"kill_process\|isolate_host\|unisolate_host","assetId","incidentId","pid","dryRun"}` |

需 server 配置 `RESPONSE_ENABLED=true`；隔离要求 `ISOLATION_ALLOW` 包含 server
的 gRPC 端点，否则 agent 拒绝执行。

## 资产与管理

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/assets` | 资产清单 |
| GET | `/api/assets/{id}/config` | 该主机的采集配置 |
| PUT | `/api/assets/{id}/config` | 设置采集配置：`{"fileWatchDirs":[...],"collectFiles":true,"collectAuth":true,"collectPersist":true,"collectNetwork":true}`。随 agent 下次注册（重连或重启）生效；`collectNetwork` 在 Linux eBPF 与 Windows ETW 路径生效 |
| GET | `/api/users` | 用户列表（admin） |
| POST | `/api/users` | 建号：`{"username","password","role"}`（admin） |
| POST | `/api/users/{id}/password` | 重置密码（admin） |
| DELETE | `/api/users/{id}` | 删号（admin） |
| GET | `/api/audit` | 审计日志（admin） |

## 对接示例：定时同步情报源

```bash
# 登录拿 cookie
curl -c cookie.txt -X POST http://xdr:8080/api/login \
  -d '{"username":"feeds-bot","password":"..."}'

# 把情报源导出的清单灌进去，30 天有效期
curl -b cookie.txt -X POST http://xdr:8080/api/intel/import \
  -H 'Content-Type: application/json' \
  -d "{\"text\": \"$(tr '\n' '\\n' < feed.txt)\", \"source\": \"feed-x\", \"expiresInDays\": 30}"
```

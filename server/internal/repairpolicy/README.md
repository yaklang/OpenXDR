# 有限运维修复委托

`Store.Handler()` 挂在 `/api/settings/repair-policy`，只允许当前仍有效的真实全局管理员 GET/PUT。
策略在 `settings` 的 `repair-policy` 键保存，缺省为空；不会自动给生产资产填入服务名单。
每次修改与预留动作都有审计。执行模型只能读任务上下文，不能写此策略。

每条授权包括唯一 `id`、`action=restart_failed_service`、`group_id`、精确 `asset_ids`、
精确 `units`、`expires_at`（最多30天）与 `cooldown_minutes`（60至10080分钟）。
服务名必须是无路径、无转义、无实例参数的规范 `.service` 名称；核心平台、数据库、网络、SSH、
采集、安全防护、容器运行时等服务禁止授权。它不支持任意命令、正则、重启主机、删除或补丁安装。

启动时绑定：

```go
store := &repairpolicy.Store{DB: db}
pi.AuthorizeFindingRepair = store.Authorize
pi.RecordFindingProbe = store.RecordProbe
mux.Handle("/api/settings/repair-policy", store.Handler())
```

一条修复只允许精确形式 `systemctl restart -- worker-app.service`。执行前须：

1. 真实的 `ops-followup` TaskRun、活跃任务租约、同组且已领取的 Finding/资产、未耗尽预算；
2. 服务端实际下发并绑定本会话的固定诊断：
   `systemctl show --property=Id,ActiveState,UnitFileState -- worker-app.service`；
3. 最近10分钟的完整成功回执：`Id=worker-app.service`、`ActiveState=failed`、`UnitFileState=enabled`，
   字段缺失/重复、别名指向关键服务、截断、失败或未知回执均拒绝；
4. 当前资产没有尚未确认的写动作，当前策略未过期且未处于服务冷却期；
5. 事务锁定策略并持久预留动作，随后仍走现有 commandgate 权限、名单、审计与全局响应开关。

预留不代表已执行。Gate拒绝、进程退出或投递未知都不能删除预留后重发；后续只读检查和回执查询仍可继续。
同会话不重复预留，同资产/精确服务的冷却不因更新策略而消失。诊断绑定只保留每资产/服务的最近记录，
并在使用时核对真实 session ID，避免按每次巡检无界积累配置行。

修复指令 `succeeded` 也不会直接关闭 Finding；执行者必须另取独立只读效果证据，交 `findingreview` 复核，
通过后再以原状态/观察时间 CAS 结案并记录 `finding_ai_review` 审计。未配置复核、无模型、无直接正面证据
或复核期间出现新的写动作，均保留 open，由平台继续跟进。

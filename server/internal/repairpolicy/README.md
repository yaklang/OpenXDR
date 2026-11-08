# 有限运维修复委托

`Store.Handler()` 挂在 `/api/settings/repair-policy`，只允许当前仍有效的真实全局管理员 GET/PUT。
策略在 `settings` 的 `repair-policy` 键保存，缺省为空；不会自动给生产资产填入服务名单。
每次修改与预留动作都有审计。执行模型只能读任务上下文，不能写此策略。

每条授权包括唯一 `id`、`action`（`restart_failed_service` 或 `reclaim_disk`）、`group_id`、精确 `asset_ids`、
服务重启的精确 `units` 或磁盘回收的精确 `paths`、`expires_at`（最多30天）与 `cooldown_minutes`（60至10080分钟）。
服务名必须是无路径、无转义、无实例参数的规范 `.service` 名称；核心平台、数据库、网络、SSH、
采集、安全防护、容器运行时等服务禁止授权。它不支持任意命令、正则、重启主机或补丁安装。

这里的模板只是带管理员授权、冷却与效果核验的那两类动作。其他修复命令不需要模板：`ops-followup` 会话的写命令归属到待办后
交通用命令闸门（硬拒绝清单 → 组黑名单 → AI 审计员），见 `docs/pi-backend.md`。

启动时绑定：

```go
store := &repairpolicy.Store{DB: db}
pi.AuthorizeFindingRepair = store.Authorize
pi.RevalidateFindingRepair = store.Revalidate
pi.RecordFindingProbe = store.RecordProbe
pi.VerifyFindingRepair = store.VerifyDisk
mux.Handle("/api/settings/repair-policy", store.Handler())
```

一条服务重启只允许精确形式 `systemctl restart -- worker-app.service`。执行前须：

1. 真实的 `ops-followup` TaskRun、活跃任务租约、同组且已领取的 Finding/资产、未耗尽预算；
2. 服务端实际下发并绑定本会话的固定诊断：
   `systemctl show --property=Id,ActiveState,UnitFileState -- worker-app.service`；
3. 最近10分钟的完整成功回执：`Id=worker-app.service`、`ActiveState=failed`、`UnitFileState=enabled`，
   字段缺失/重复、别名指向关键服务、截断、失败或未知回执均拒绝；
4. 当前资产没有尚未确认的写动作，当前策略未过期且未处于服务冷却期；
5. 事务锁定策略并持久预留动作，随后仍走现有 commandgate 权限、名单、审计与全局响应开关；
6. 审批等待结束后、Hub真正下发前通过内部 BeforeIssue 再验当前授权、租约、原诊断和原预留；
   撤销/到期/转组/新未知动作均阻断下发，原预留只消费一次，不因再次检查而重新预留。

预留不代表已执行。Gate拒绝、进程退出或投递未知都不能删除预留后重发；后续只读检查和回执查询仍可继续。
同会话不重复预留，同资产/精确服务的冷却不因更新策略而消失。诊断绑定只保留每资产/服务的最近记录，
并在使用时核对真实 session ID，避免按每次巡检无界积累配置行。

修复指令 `succeeded` 也不会直接关闭 Finding；执行者必须另取独立只读效果证据，交 `findingreview` 复核，
通过后再以原状态/观察时间 CAS 结案并记录 `finding_ai_review` 审计。未配置复核、无模型、无直接正面证据
或复核期间出现新的写动作，均保留 open，由平台继续跟进。

调查与修复分开计数：`work_attempts` / `work.investigation_attempts` 是领取轮次，不是修复预算。
`work.repair_attempts` 仅在写动作预留与审计同事务成功时增加；拒绝、冷却、重复与事务失败不增加。
第三次已预留动作仍可完成审批后复核，但不能再创建第四次预留。预留绑定原始问题摘要与精确授权版本，
其它授权的修改不改变本动作身份。`legacy_decommission_confirm`、`manual_business_decision`、
`external_dependency` 阻止自动重启；不能把旧失败服务当作仍需运行的服务。

`HasGrant` / `HasAssetGrant` 仅查询实际持久策略与当前资产归组，不签发授权。未配置有效维护范围时，
平台可记录 `policy_required` 并继续 AI 跟进；不会为取得失败证据先执行危险命令。
本版本不支持泛化清理、删除卷/备份、安装补丁或重启主机；候选方案不等于授权。

## 磁盘回收

`reclaim_disk` 只适用于 key/title 明确包含磁盘/文件系统及容量、空间、满或使用率问题的待办；
磁盘 I/O 故障与内存问题不属于此动作。沿用同一组、明确资产、租约、有效期、预算、
预留、审批后复核与审计流程。服务授权不能借作磁盘回收授权。

封闭模板（空格、参数顺序、大小写须精确一致，不支持 sudo、shell 拼接或额外参数）：

- `docker image prune -f`
- `docker builder prune -f`
- `apt-get clean`
- `find -- <DIR> -xdev -type f -mtime +<N> -delete`

`N` 是7至3650的规范十进制整数。`DIR` 必须精确出现在本条 grant 的 `paths` 中，
不隐含子目录或父目录权限。`paths` 最多20项，须为无空格/转义/变量的规范绝对路径，
不含 `..`，不允许根目录、不自动清理路径。
禁止 `/etc /bin /sbin /usr /lib* /boot /proc /sys /dev /root/.ssh /var/lib/postgresql
/var/lib/docker /var/log/audit /opt/openxdr*` 及其子目录；也拒绝可递归覆盖这些目录的祖先，
例如 `/var`、`/var/log`、`/root` 与 `/opt`。管理员应仅列出已确认用途的真实缓存目录。
`paths` 可以为空，此时仅允许前三种缓存回收模板；`units` 必须为空。

授权示例（ID、组、资产和有效期须由管理员填入真实值）：

```json
{"grants":[{"id":"<uuid>","action":"reclaim_disk","group_id":"<uuid>","asset_ids":["<uuid>"],"paths":["/srv/app-cache"],"expires_at":"<30天内的RFC3339时间>","cooldown_minutes":1440}]}
```

冷却在核查固定诊断前返回真实截止时间，避免旧会话探针错误掩盖冷却；同会话仍禁止重复预留。冷却不等于缺授权，不清空预留或重放动作。

先执行单条 `df -P <mount>`（例如 `df -P /`），引用由服务端实际下发的探针，要求
最近10分钟成功、无截断/错误、规范 POSIX 容量和精确挂载。一次性预留绑定原问题、授权版本、
精确回收命令与前探针。所有模板共享每资产的回收冷却，更换目录、模板或 grant 不重置冷却。
Gate 的内部 `AuthorizedRepair` 标记只在授权预留成功后设置；通用 AI exec 对受保护路径（系统目录、`/var/lib`、备份等）
上的删除仍硬拒绝，普通目录的删除与缓存回收交 AI 审计员评审。内部例外只接受上述精确模板，仍核对组权限、
高风险名单/审批、RESPONSE_ENABLED、指令签名与下发前复核，不增加演练模式。

服务端另外关联实际回收指令 ID。`FinalizedAt` 仍仅表示审批后的预留消费；
`VerifiedAt`/`AfterProbeID` 只在独立效果检查成功后保存，并写 `repair_action_verified` 审计。
回收完成后重新执行相同 `df -P <mount>`，`track status=resolved` 的 `evidence_commands`
必须引用该后探针。回收指令必须成功，后探针必须晚于回收完成、属于当前会话、新鲜且完整，
文件系统标识与总容量必须和前探针一致，可用空间必须增加。未增加、失败、未知、换挂载
或只引用回收前探针均拒绝确认；仍保留预留和冷却，不能自动重放。
效果验证通过后仍须独立 `findingreview` 确认原问题已经恢复才关闭待办；空间增加本身不等于问题解决。
当前没有维护范围 Web UI，真实管理员通过既有 GET/PUT 接口维护 `paths`。

## 动作能力、阻塞与唤醒

`Capabilities` 只读返回同组实际资产上待办的支持模板、精确授权、所需固定探针及冷却/窗口时间，不创建预留。
精确命令的状态分别为 `action_required`、`action_unsupported`、`policy_required`、`maintenance_window_required`、
`cooldown`、`probe_invalid`、`budget_exhausted` 或 `ready`；业务/上游/人工阻塞继续保留。
`ready` 只是查询时的前置条件快照，授权、审批后复核、全局开关、签名、租约、预算和审计照旧执行。

管理员 grant 可带 `not_before`（RFC3339，早于 `expires_at`）指定窗口开始。字段缺省即原有有效期行为。
维护窗口阻塞中的待办需要带明确 `not_before` 的有效授权；模型自己的 `wake_at` 只安排重评估，不授权写操作。
`RepairError` 仅用于预留前可确定的拒绝；未知 COMMIT 与投递结果不归为可重试前置条件。

正常 `ops-followup` 领取前，通过实际维护策略指纹、服务端冷却截止、计划复查时间与同组依赖待办的状态重新评估。
依赖恢复仅认已经独立复核或人工标为 resolved 的待办，不把删除、转组、忽略或没有输出当成恢复。
条件变化只把 `work_next_check_at` 提前并记录 `finding_work_woken` 审计；不提升人工负责人、不减少修复次数、不结案。
没有新条件时沿用原有退避，不反复唤醒。同一条件核实与计划更新用 CAS 防止覆盖并发预留；依赖登记按组串行防止并发形成环。
无事件订阅或额外探测进程：唤醒延迟上限受既有自治任务调度周期与排队影响，默认每30分钟检查。

上游依赖仅在登记的同组依赖全部确认 resolved 且精确动作前置条件 ready 后，可重新评估并清除旧依赖阻塞；下发前仍重查依赖，重新打开即拒绝。人工负责人、业务决定和退役确认不得由模型改成机器阻塞来绕过。

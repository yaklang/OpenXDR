# 结案审计的实际边界

良性分支只接受 `verified_platform_readonly -> false_positive`。服务端逐条核验告警与原始事件的资产、时间、来源、平台指令标记及精确命令正文；所有相关指令均须确认执行成功且为只读。报告、模型意见、无新增告警或等待天数都不能替代这些核验。

这一分支是保守的存量来源链守卫，不是生产普通事件的通用自动结案能力。正常采集时，`grpcsvc.detect` 先核验平台指令来源并给告警绑定 `CommandID`；`correlate.Engine.batchTx` 只关联 `CommandIDIsNil` 的告警。因此新产生的平台指令告警通常不会成为 incident，而本包的正例夹具显式关联了这两者。当前生产代码没有将普通事件告警回填为平台指令来源的路径；包内正例通过不代表从采集到自动结案的端到端路径可达。不能通过降低证据要求或伪造来源来使数量下降。

## 处置成功与整体恢复

仍不开放 `verified_remediation_recovered -> closed`（整体恢复不同于下述遏制结案）：

- `commands.status=succeeded` 只表示执行回执成功。
- 机器 `command_verifications.outcome=effective` 当前只支持核验 `kill_process` 的同资产、同 GUID/PID 进程退出。它不能证明服务已恢复、持久化被清除、凭据已轮换、文件完整性已恢复或既有影响已消除。
- `containments` 可以关联单条触发告警，但没有覆盖事件全部告警及风险的修复证明清单。单个目标的处置成功不能扩展成整起事件已恢复。
- 没有新增告警不等于观察窗口内采集完整，也不是整体恢复的正面证据。

只有存在可信、结构化、绑定当前事件证据版本与全部受影响资产/目标的覆盖及恢复证明，才能新增精确的 `closed` 路径；仍须校验真实效果事件、观察覆盖、期间的新证据以及最终事务 CAS。当前 `closed` 提案保持待处理，不调用模型自动批准。`TestEffectiveProcessExitDoesNotProveIncidentRecovered` 使用真实机器效果验证写入链路守住此边界。

## 已遏制威胁结案

新增 contained 路径不需要 Pi 提案：服务端按当前 evidence key、verdict hash 和完整材料指纹绑定独立审查，串行化事务内重新加载全部门禁，变化即作废。仅接受最新证据后的 suspicious/malicious 研判；每条告警均须有处置记录，事件或告警关联的所有处置必须 active/executed/expired/lifted 且原始指令回执 succeeded。目标、来源和告警资产均不得 core。pending/held/skipped/failed 或缺回执一律拒绝。

最后处置创建、成功回执或结束时间中的最晚时刻起至少六小时安静。相关资产上任意新增告警（含 last_ts）均阻止结案；原始事件按进程 GUID、父子关系、连接、命令、映像、文件、域名与地址比较实体。原始事件查询超过 1000 条或实体无法识别时拒绝，宁可保留事件。该窗口只说明没有观察到相关新增证据，不宣称采集完整或系统恢复。

独立审计使用单独提示词检查攻击链、全部告警、处置及回执与窗口。批准仍须引用全部原始事件和真实字段。拒绝、非法回复或模型错误均保持打开。成功写 closed、ai_review、处置列表和审计；不解除或续期租约。关联批次检查该类结案后的新增告警或实体证据并重开；人也可随时重开。

IncidentWork.manual_owner / manual_lock 区分明确人工接管和系统自动 escalated。人工重开写入 manual_owner，后续研判保持该标记，禁止再次自动结案；现有系统升级不等于人工接管。当前不增加独立锁定 UI。

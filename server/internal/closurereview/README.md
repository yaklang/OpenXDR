# 结案审计的实际边界

当前实现只接受 `verified_platform_readonly -> false_positive`。服务端逐条核验告警与原始事件的资产、时间、来源、平台指令标记及精确命令正文；所有相关指令均须确认执行成功且为只读。报告、模型意见、无新增告警或等待天数都不能替代这些核验。

这一分支是保守的存量来源链守卫，不是生产普通事件的通用自动结案能力。正常采集时，`grpcsvc.detect` 先核验平台指令来源并给告警绑定 `CommandID`；`correlate.Engine.batchTx` 只关联 `CommandIDIsNil` 的告警。因此新产生的平台指令告警通常不会成为 incident，而本包的正例夹具显式关联了这两者。当前生产代码没有将普通事件告警回填为平台指令来源的路径；包内正例通过不代表从采集到自动结案的端到端路径可达。不能通过降低证据要求或伪造来源来使数量下降。

## 处置成功与整体恢复

目前不开放 `verified_remediation_recovered -> closed`：

- `commands.status=succeeded` 只表示执行回执成功。
- 机器 `command_verifications.outcome=effective` 当前只支持核验 `kill_process` 的同资产、同 GUID/PID 进程退出。它不能证明服务已恢复、持久化被清除、凭据已轮换、文件完整性已恢复或既有影响已消除。
- `containments` 可以关联单条触发告警，但没有覆盖事件全部告警及风险的修复证明清单。单个目标的处置成功不能扩展成整起事件已恢复。
- 没有新增告警不等于观察窗口内采集完整，也不是整体恢复的正面证据。

只有存在可信、结构化、绑定当前事件证据版本与全部受影响资产/目标的覆盖及恢复证明，才能新增精确的 `closed` 路径；仍须校验真实效果事件、观察覆盖、期间的新证据以及最终事务 CAS。当前 `closed` 提案保持待处理，不调用模型自动批准。`TestEffectiveProcessExitDoesNotProveIncidentRecovered` 使用真实机器效果验证写入链路守住此边界。

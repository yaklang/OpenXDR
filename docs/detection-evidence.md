# 补充检测规则与证据采集

这组规则补充 Linux/Windows 安全事件的具体检测场景，同时完善来源 IP 关联和可选 Windows 证据采集。规则中的 ATT&CK 标签只表示关联技术，不代表完整覆盖该技术，也不证明告警行为一定是攻击。

## 规则与数据前提

- `rules/wazuh-gap/`：关键路径变更、Windows LOLBin/PowerShell、认证结果与应用日志等场景。规则由 OpenXDR 的现有字段模型重新实现；Wazuh 规则族仅作为场景参考。
- `rules/wazuh-phase2/`：sudo 成功信号、systemd 服务单元删除、本地账号创建及 WinRM 网络活动信号。
- `rules/wazuh-attack3/`：PowerShell 屏幕捕获、Office 启动 Verclsid、Sysmon 远程线程/LSASS 访问/映像替换、NTLM 网络登录线索、auditd 审计规则删除及 root 执行关联信号。
- 新增的 `temporal-rules/wazuh-gap-*.yml` 和 `linux-auth-source-burst.yml` 使用计数或先后关系组合证据。时序规则仍需配置 `TEMPORAL_RULES_PATH` 才加载。

这里共补充 35 条基础规则/信号和 7 条时序规则。原有时序规则继续保留。标有 `openxdr_signal: true` 的规则只提供关联候选，不单独告警；不能把这类信号的标签计作独立检测覆盖。

正常维护、安全软件、软件安装及经授权的自动化可能触发这些 experimental 规则。部署前应在自己的历史事件上回测，并根据有证据支持的业务范围调优，避免按安装目录或所有管理员操作直接放行。

## 按来源 IP 关联

新增时序维度 `group_by: asset_source_ip`，按组、目标资产和规范化后的来源 IP 分桶，避免多个不同来源各自的少量失败登录累加成同源暴破。

- 来源使用认证事件的 `src_endpoint.ip`；IPv4、IPv4-mapped IPv6 与 IPv6 按统一口径规范化。
- 缺失或无效来源不进入这一关联维度，不用 syslog 传输对端地址冒充攻击来源。
- SSH syslog 在识别的失败登录格式中提取来源 IP，转发代理的地址不会覆盖日志内来源。
- 候选表增加可空 `source_entity` 和部分索引；告警去重键和只读历史回测采用同一维度。
- 跨来源、跨资产、跨组、缺来源与重复投递均有反例测试。

## Windows Sysmon：显式开启

更新 Windows Agent 后，在资产详情的“采集配置”中启用“Sysmon 注入与内存访问”，对应 `collectSysmon: true`。默认关闭，下次 Agent 注册时应用。

目标主机必须预先安装可信 Sysmon，并配置以下事件。该开关只订阅日志，不会安装 Sysmon 或改动其策略。

| 事件 | 证据 | 检测边界 |
|---|---|---|
| 8 CreateRemoteThread | 源/目标映像、PID、进程 GUID、起始函数等 | 向指定系统进程创建远程线程；不单凭此事件断言线程劫持或镂空 |
| 10 ProcessAccess | 源/目标映像和规范化的 GrantedAccess | 访问 LSASS 的指定敏感权限掩码；不证明凭据已被导出，安全软件也可能命中 |
| 25 ProcessTampering | 映像和 Type | 仅对明确的 `Image is replaced` 匹配进程映像替换规则 |

证据位于 `raw.sysmon`，使用独立活动编号，不伪装为新进程启动，不编造进程 GUID 归属。订阅成功只说明日志订阅建立，仍需通过原始事件验证实际送达；未安装或无读取权限会报告 unavailable。

已有的 Windows 登录采集补充认证包、登录进程、工作站、NTLM 包及密钥长度字段。NTLM 网络登录规则仅为低危核查线索，正常认证也可命中，不能单凭它确认 Pass-the-Hash 或域账号被盗。

## Linux auditd：单记录归一化

服务端 syslog 对 auditd/audit/audispd/audisp-syslog 的 `SYSCALL` 和 `CONFIG_CHANGE` 单记录提取 `audit` 对象，保留 auid、uid/euid、syscall、结果、exe、时间和审计序号，同时保留原始消息。重复键、截断引号、非法片段和超长记录被拒绝。

需要自己配置可信 auditd 日志转发和接入来源。启用 Agent 文件监控并不会自动产生这些审计字段。此实现尚未关联 SYSCALL/EXECVE/PATH 多条记录；`audit.record_scope=single_record` 明确标示这一边界。root 执行信号仅覆盖 x86_64 成功的 execve/execveat，不作为单条攻击告警。

## 验证与实机验收

`validation/wazuh-gap-cases.json`、`wazuh-phase2-cases.json`、`wazuh-attack3-cases.json` 按指定规则 ID 对拍正反例；`wazuh-gap-temporal.json` 验证关联维度和序列边界。Go 集成测试检查 syslog 入队、资产归属、持久候选和告警行为。Windows 解析测试不依赖真实攻击命令。

```sh
cd server
go run ./cmd/sigmacheck --strict ../rules
go run ./cmd/detectcheck --strict
go test ./...
# INTEGRATION_DATABASE_URL 必须指向独立测试库；测试会清表。
go test -tags integration -p 1 ./...
```

编译与合成事件测试不等同于端点可见性验收。部署后还需验证：

1. Windows Agent 已更新、Sysmon 通道已配置，8/10/25 的原始字段及主机归属真实送达。
2. NTLM 日志上下文字段、PowerShell 4104 内容及父子进程路径真实可见。
3. auditd 转发没有把中继主机当成源主机，且 auid/uid/euid 与原文一致。
4. 在真实历史日志上核查命中量和时序候选上限；无历史样本不能视为零误报证明。

这些规则不会自动启用响应处置，也不更改命令审批策略。

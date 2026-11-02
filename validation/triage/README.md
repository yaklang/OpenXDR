# 研判证据回归

六类脱敏证据快照：共享 CDN 与未知客户端、仅 AI 记忆、查询截断/超时、多客户端混淆、
人工授权维护、明确攻击链。域名和地址均为测试数据，不是生产事件。

每类独立检查 verdict、事实依据、限制说明和处置建议。每类另有一份 verdict 正确但
事实或建议错误的基础负对照；另有 15 个针对单一问题或平台语义的正反对照，以及上一轮 3 条完整失败输出。
合计 31 个评分校准项：20 个负对照、11 个正对照。负对照指定维度必须判 fail，
正对照三个维度均须 pass；uncertain 或漏判/误拒均使整轮失败，避免只检查结论标签或一律拒绝。

`cases.json` 的 `controls` 支持具名校准项；`reject: []` 表示正对照，非空列表表示必须判失败的维度。
JSONL 的 `calibration` 行记录 control 标识与 expected_reject，summary 的 calibration_controls 记录总数。

较早运行：[2026-10-29 续测报告](runs/2026-10-29-followup/README.md)。14 个负对照全部识别，但 2 个正对照有评分分歧，生成结果仍有真实事实扩写，候选提示词未上线。
历史：[首轮报告](runs/2026-10-29/README.md)。

## 校准样本修正（2026-10-29）

`mixed_clients` 的 `weak_branch_investigate` 原标记为三维度全部通过，但正文未明确记录计数的有限范围，建议也未满足逐客户端核实要求。此前不能将其失败一概归为评分器误判。现将它与 `weak_branch_response` 的公共摘要和第一条调查建议对齐：明确保留记录非全量，并逐个客户端核实；仅保留末条建议“弱线索触发补证”与“弱线索触发申请隔离”的差别。负对照仍要求 actions 失败，正对照仍要求三维度通过，没有放宽 rubric。

历史 runs 下的快照和结果保持不变；旧校准通过率不适用于修订后的语料。此次修正尚待真实模型校准。

修订语料后的固定答案实验又发现：评分理由承认遗漏其他客户端核实，却认为“不越权即可通过”。完整评分与建议评分现明确同时要求安全性和 rubric 指定的必要调查覆盖，不增加案例之外的调查要求。将实验中第二组固定答案纳入 `advice_scope_incomplete`（actions 应失败）与 `advice_scope_complete`（三维度应通过）对照，二者只差一条核实建议。当时合计 29 项；既有 27 项实验不算新版评分器校准。“没有记录/未采集”的漏判仍未解决，提示词变更本身不代表验收通过。

### 完整回归后的校准与授权范围修正

29项完整回归暴露一条真实生成错误：精确的操作批准被扩写为“精确业务归属”。生产提示词此前将业务归属作为单次结案和长期放行的共同前提；现明确按主机、时间、动作核对的人工批准可以支持本次操作结案，但不证明应用或业务归属，长期放行标准不随之放宽。新增实际失败答案与仅修正这一归属短语的正对照（approval_invents_business_owner / approval_scoped_to_operation），当前共31项；真实复测尚未完成。

platform_semantics、record_absence_unknown 及其事实负对照 record_absence_invented 统一改用人工原始来源补正文、真实 process_guid 查询血缘的建议，避免工具能力歧义干扰事实校准。verified_refs_actual_1_scoped 改为说明本次快照未提供字段、原因未知，不再由裁剪推导缺失原因。历史 runs 下的所有语料、报告和失败计数保持不变。

评测 CLI 的报告完整性测试已去除旧版27项数量常量，按输入语料计算预期行数、调用次数和失败数；31项版本以 `go test -count=1` 验证，避免沿用旧测试缓存。真实模型语义结论仍须另行取得。

## 最新收尾记录

[授权范围修正与16K预算回归](runs/2026-10-29-authorization-budget16k/README.md)按用户要求中止：
完成27/31项校准（25项匹配预期），保存8/12次生成，无终态 summary。
新增授权范围正负对照均匹配；新提示词下的授权维护生成仍未完成。
独立程序和临时文件已清理，报告与冻结源码保留；两项校准争议和生成评分分歧待独立复核。
这不是整轮通过，也不构成生产部署验收。

## 离线检查

在 `server/` 执行：

```sh
go test ./internal/triage ./internal/triageeval ./cmd/triagecheck
go run ./cmd/triagecheck
```

普通 CI 的 `go test ./...` 会检查样本、评分结构、格式修复、失败留存和禁止覆盖报告。
这只验证程序和语料，不调用模型，不代表研判质量通过。

## 真实模型评测

通过安全环境注入 `AI_BASE_URL`、`AI_MODEL`、`AI_API_KEY`，不要把密钥写进命令、报告或仓库。
可用 `TRIAGE_EVAL_JUDGE_MODEL` 指定同一端点上的独立评分模型，默认使用待测模型。

```sh
go run ./cmd/triagecheck -live -repeats 2 \
  -revision "$(git rev-parse HEAD)" -out /tmp/triage-run-001.jsonl
```

有未提交改动时，在 revision 中明确注明，并另存 diff。报告路径必须不存在，文件权限为 0600。
报告记录代码标识、生产提示词/评分提示词/语料摘要、模型、思考开关、输出预算、调用用量、
各次答案与分项评分。每行立即写盘；失败也继续执行后续样本，不挑选最好一次。
未出现 `kind=summary, complete=true` 的运行属于中断，不算完整回归。

生成沿用生产研判的提示词和一次格式修复，不覆盖供应商默认思考与输出预算（报告中预算 0 表示不发送该字段）。
评分单独调用模型，默认保留供应商思考，输出预算 8192。可用 `-judge-max-tokens 16384` 显式选择另一预算，本工具允许 1024–32768；完整评分与独立建议评分使用同一预算并分别写入报告。生成预算不变，现有超时不变，不因截断自动重试或升档。预算变化必须另建报告、重新校准，不能将旧报告失败改为成功，也不保证提高预算即可消除截断或语义误判。可显式传入 `-judge-no-thinking`，仅对完整评分与独立 actions 评分请求关闭思考，不改变生成器；报告分别记录两个评分阶段的实际配置。该请求按已有 GLM / DeepSeek 兼容规则发送，其他模型不保证支持；更换评分模式需要单独校准，不能因输出较短就认定更准确。actions 另作一次独立审查，同样使用所选思考模式与预算（默认 8192）；两份评分保存在 actions.reviews，取更严格的结论，
正常运行的 judge_usage 汇总两次评分用量。缺项、无效 JSON、非正常结束、虚构失败引用或
`uncertain` 均不能算通过。接口或格式失败记录阶段与用量，不保存供应商错误正文以免泄密；
因此此报告不是完整 HTTP 调试追踪。

退出码：0 为自动检查全部通过，1 为存在失败，2 为配置/语料/报告错误。
自动通过仍需人工逐项复核：特别是同模型生成与评分可能有共同盲区。
人工复核另存结果，不改写原始 JSONL；至少记录 case/repeat、复核结论、依据和审核日期。
不要把六个固定样本的通过率宣传为总体准确率。

## 验收边界

这里不连接数据库、不注册调查工具、不触发处置或通知，不能覆盖采集可见性、实际查询、
调度、重试及生产延迟。它用于稳定复现推理边界；完整工具链仍需独立测试库回放，
生产自然事件需单独对账。调整提示词后，应完整重跑并保留修改前后的全部结果。

### 查询元数据校验边界

生产调查将实际工具返回的覆盖信息写入 `query_evidence`，有工具证据时必须提交非空 `evidence_claims`，只能引用查询或事件记录中存在且值一致的字段。
服务端覆盖模型自填的台账，修正一次后仍不匹配则失败；不把缺失字段变成 false。
`go test ./internal/triage` 覆盖省略/空/null 引用、伪造编号、篡改值、错误类型、未知状态与修正失败；未调用工具仍允许无引用。
`TestMissingEvidenceClaimsDoNotPersistOrNotify` 使用真实测试库和 HTTP 模型 mock，验证失败后不落库、不触发通知/处置回调并安排退避重试。
纯文本快照评测没有工具台账；显式 `tool_snapshots` 可重放台账校验，但没有执行真实工具，不能作为完整调查链路验收。
既有模型运行工件保持不变，不能作为此次代码或提示词的真实模型验收结果。

查询台账还区分 `truncated`（条数）与 `raw_truncated_records` / `dns_omitted_records`
（已返回事件中的正文裁剪/字段省略计数）。查询失败或告警列表不提供后两项，不能当作零。
`TestInvestigationRetainsFailedToolEvidence` 通过实际工具分发触发非法 GUID 错误，验证下一轮收到失败台账、
错误“未截断”引用触发修正且最终保存失败状态；模型使用 HTTP mock，不代表真实模型或数据库验收。

事件级 `records` 带独立引用编号（例如 `query-1/items-1`），字段直接来自事件的归一化列。
`process_guid` / `parent_process_guid` 不从 raw 正文补写，也不从返回顺序推断；缺失字段不可引用。
`TestBriefUsesNormalizedProcessIdentity` 验证正文裁剪和伪造 raw 不影响归一化标识；
`TestRecordClaimsCannotBorrowParentFromAnotherEvent` 验证正确父进程引用、错误父进程、跨记录借用、
未知当作无父进程和伪造首次出现。前端展示服务端记录；自由文本摘要仍不是确定性校验对象。

`host_alerts` 附带最近一次 `collector_health` 的接收时间、组件状态与采集路径，
台账字段为 `collection_status` / `collection_received_at` / `collection_states` / `collection_paths`。
没有快照或快照缺少有效接收时间时仅报告 unknown；查询资产失败则整个工具调用报错。
组件缺失不是 disabled；active 不是没有漏采；旧快照不改写成当前状态，不证明事发时覆盖。
`TestCollectionEvidencePreservesUnknownAndSnapshotTime` 验证缺失、坏时间、旧快照、
篡改组件状态与伪造缺失组件；尚未完成真实数据库与真实模型端到端验收。

`process_baseline` 按 `asset_id` + `exe_path` 查询 UEBA 基线，复用检测器的路径归一化与旧版别名，
命中返回 `baseline_id` / `baseline_path` / `baseline_first_recorded_at`，未命中返回 `baseline_status=unknown`。
这不证明安装时间、实际首次执行或恶意性。数据库错误不能退化为未命中。
单测覆盖完整路径输入与禁止引用安装/执行时间；集成测试覆盖资产隔离、旧版路径、
多个别名取最早已有基线记录、未命中和断库失败。

2026-10-29 本地独立 PostgreSQL 17 验证：`go test -tags integration -p 1 ./internal/triage ./internal/ueba` 通过，
包含上述基线隔离/别名/断库用例及研判工具链、落库相关既有测试。测试库已删除；模型为 mock，未作为真实模型验收。

### 带工具结果的离线回放

样本可提供 `tool_snapshots`（每项 `tool` 与 JSON 对象 `result`），限 24 项、单项 128 KiB，
仅接受四个只读调查工具名。评测器将其作为已有调查结果回放，重新生成生产格式的证据台账，
模型结论仍经 `finishVerdict` / `bindEvidence` 校验与单次修正。不会执行这些工具。
评分器同时收到文字证据与同一份结构化快照，避免生成器与评分器依据不同。
没有快照的旧样本保持原行为。此模式验证模型对给定证据的使用，不代表工具实际执行、数据库实时查询或生产验收。

### 工具能力一致性

生成器与两个评分器共享 `InvestigationContract()`，生产提示词摘要包含该说明，报告另记
`tool_contract_sha256`。query_events 的 raw 模式只改变搜索范围，不取消 300 字节正文裁剪；
process_lineage 只接受 process_guid，不支持时间窗口或额外进程筛选。查询台账保留
`raw_mode_scope=search_only` 与 `raw_excerpt_limit_bytes`。
新增两个错误能力反例和一个人工从其他原始日志来源补证的正对照。完整六类、23项校准与12次生成
真实模型复测工件存于 `runs/2026-10-29-tool-contract/`；结果产生前不能视为通过。

### 失败诊断

新报告保留原 `error_stage`，并新增 `error_detail`：`stage` 区分 `full_review` /
`actions_review` / `generation`；固定 `code` 区分 `incomplete_output`、`unexpected_tool_call`、
`invalid_json`、`invalid_schema`、`invalid_quote`、`invalid_answer`、`http_error`、
`timeout`、`canceled` 等。完整结束检查失败时记录白名单内的 `finish_reason`，HTTP 失败只记录数值状态码。
未能进一步分类的生成/格式错误保持 `generation_or_format`，不推测原因。
诊断不保存原始错误文本、请求 URL、响应正文或凭据；第二层评分失败仍保留第一层结果。
历史报告缺失诊断的记录保持原样，不能仅凭 token 计数倒填 finish_reason。
对应测试涵盖完整/独立评分截断、坏 JSON、缺字段、引用伪造、429、超时/取消、未知完成原因及敏感错误脱敏；
CLI 测试确认全部失败尝试落入报告且不会泄露测试凭据。

### 结构化建议

新生成输出必须含非空 `action_codes`，代码和固定文案定义于 `triage/actions.go`，
同一目录进入生产与离线生成提示词（因此计入 prompt SHA-256）。服务端生成兼容的 `actions` 字符串数组。
未知/重复代码、对象参数、自由文本 actions、与 verdict 不匹配的结案/响应建议均拒绝；只允许一次修正。
历史评分对照仍保留旧答案，不因新格式改写；这用于继续检查语义评分器能否识别已知坏建议。
单测覆盖上述拒绝路径与一次修正上限；数据库集成验证无效建议不会落结论或触发 OnVerdict。
这只约束建议字段，不证明 summary 或 kill_chain 中的自由文本正确。
[真实模型生成验证](runs/2026-10-29-action-codes/README.md)的 12 次输出均一次通过结构校验；工程复核 11 通过、1 项措辞待核，整体语义门禁未完成。

### 非空引用与摘要来源边界验证（2026-10-29，本地）

有工具台账时省略、空数组或 null 引用都拒绝；允许修正一次，仍无效则退避。
无工具时不强迫伪造引用，历史存档读取不变。重研判明确上次摘要不是独立证据或人工确认，
前端与 IM 通知将自由文本标为模型判断；这些标记不能替代摘要的语义验证。

本轮 Go 全量单测、build、vet、前端 build/lint 通过（lint 存在既有警告）。
独立临时 PostgreSQL 17 上的 triage、ueba 集成测试通过，测试库已删除。
首次集成回归暴露运行计量测试的旧 mock 未提供引用，更新 mock 后完整重跑通过。
新增缺引用反例验证拒绝落库、不触发 OnVerdict 回调、清理运行标记并安排退避。
此次仅使用 HTTP 模型 mock；尚未重跑真实模型与浏览器验收，未部署生产。

### 逐次生成输出存档

`triagecheck -live` 的每条 evaluation 现在附 `generation_attempts`：原始 Message、finish_reason 和 structural_valid，保留首次输出及唯一一次修正。最终失败也保留已收到的输出；传输失败没有模型输出则不伪造记录。仅用于显式离线评测，不接入生产事件或日志；输入须为脱敏样本。结构通过不等于语义通过。

对应 mock 测试覆盖错误引用修正成功、两次无效输出、CLI 报告实际写入，以及 HTTP 错误不泄露凭据。旧工件缺失的首次输出不可回填。
[非空引用真实复测](runs/2026-10-29-required-claims/README.md)：12/12 最终结构通过，工程复核 10 pass / 2 fail；该运行早于逐次输出存档改动。

### 历史人工案例来源回归（2026-10-29，本地）

检查生产上下文发现旧查询允许 `resolved_by IS NULL` 的结案记录进入“分析师人工结论”。现已要求结案人、时间和非空独立备注，并排除系统结案及 `resolution_source` 标记为 AI 来源的记录。历史记录不删除；来源不完整时不作为人工确认。

历史参考改为结构化 JSON，携带事件 ID、结案人、时间、状态、备注摘录与裁剪标志，单列 `previous_ai_verdict`。同时注明同规则/主机、近 90 天相关告警、最多 8 条的检索边界；空结果和查询失败分别表达，均不得推导为不存在人工确认或工单。

`TestCaseHistoryRequiresRecordedHumanProvenance` 覆盖正常人工记录，以及缺/空/空白结案人、缺时间、缺/空白备注、系统结案、采纳 AI 研判和建议；`TestCaseHistoryQueryFailureIsUnknown` 覆盖断库不能变成“无人工记录”。原有同规则/同主机和空结果用例已适配结构化来源。
Go 全量单测、build、vet 通过；独立临时 PostgreSQL 17 的 triage、ueba 集成测试通过，临时库已删除。该修复尚未部署，也不代表纯文本离线失败样本已通过真实模型复测。

### 自由文本与服务端台账的评分边界

完整语义评分只审查 `verdict`、`confidence`、`summary`、`kill_chain`、`actions`，保留这些字段原文；不把服务端生成的 `query_evidence` 或结构引用当作模型自由文本，也不接受只出现在台账里的失败引文。台账和引用继续由确定性校验验证。

新增两条真实“引用正确但摘要扩写”的负对照，以及两条收窄范围的正对照。截断样本同时携带原工具快照，常规回归现在也验证非空引用路径。评分规则明确“无 A”不能推出“无 A 或 B”；本次未提供、仍未知应按语义接受，不要求固定措辞。
新样本与评分变更仍需完整校准，专项重复结果见 [否定事实范围专项校准](runs/2026-10-29-facts-audit/README.md)。

最新专项三版校准均完成：原规则 2/8 符合预期且有 2 次错误放行；范围规则版 7/8；结论字段分离版 7/8，剩余一次输出截断。默认思考模式的完整 27 项校准与新生成答案尚未重跑，不能由专项结果宣布语义门禁通过。全部报告与失败见上方专项链接。

### 显式评分模式完整回归

[关闭评分思考的完整回归](runs/2026-10-29-judge-no-thinking/README.md)已完成 27 项校准和 12 次生成：校准 25/27、自动语义 10/12，评分接口/格式错误为 0。工程复核仍有真实事实扩写及待核表述；两个危险反例被漏判，不能将此模式设为默认或宣布语义门禁通过。
`TestFailedControlPreservesAllAttempts` 同时验证默认和关闭评分思考两种模式：完整评分与独立建议评分配置一致，生成器配置不变，metadata 与实际请求一致；失败仍完整保留并返回失败状态。

### 历史案例范围隔离（2026-10-29，本地）

`TestHistoryCannotBorrowAnotherGroupsHumanConfirmation` 在修复前复现：同规则能取回组外、混合组、未分组、未知归属、混合未知五类案例，且资产转组后仍使用全局范围。修复后先按当前事件全部资产的现有归组限定案例，并要求历史案例的全部告警均在范围内；组外告警即使超过 90 天、规则不同，也不能被藏在同组匹配告警后面。

同一测试验证资产转组即时生效、只传部分告警明细时仍使用完整事件范围、无资产归属时不回退到全局搜索。既有同组/未分组正常参考、空查询、来源缺失与断库用例通过。
Go 全量单测、build、vet，以及独立临时 PostgreSQL 17 的 triage/ueba 集成测试均通过；临时库已删除，未部署生产。这不是完整调查工具隔离或模型语义质量的验收。

### 四个调查工具范围绑定（2026-10-29，本地）

`TestInvestigationToolsRespectIncidentGroups` 修复前复现事件检索、祖先/子进程血缘、主机告警、基线均可越组读取，且未绑定事件会全局搜索。修复后四工具共用与历史案例相同的资产组范围计算，范围取完整 incident、每次重新核对；模型参数不能覆盖内部事件绑定。

该测试验证 indexed/raw、组外祖先与子进程、未分组与无资产记录、伪造 group_id/incident_id 参数、无绑定/不存在的 incident、同组基线可用和调用之间转组刷新。
`TestTriageToolScopeDoesNotCarryAcrossIncidents` 经真实测试库及 HTTP 模型 mock 调用两次 triageOne，验证共享 Engine 连续研判两组事件只收到各自结果，绑定不留在共享实例。
旧工具测试补充了实际资产与事件绑定，原有条数截断、血缘完整性、基线路径兼容和运行计量仍通过。
Go 全量单测、build、vet 与临时 PostgreSQL 17 的 triage/ueba 集成测试通过；库已清理，未部署。每轮研判记录事件资产与归组快照，在后续模型调用、工具范围查询及落库前复核；发现变化则本轮失败，不保存旧结论、不触发结果回调。最终落库事务依次锁定事件、既有关联告警及其资产，再核对快照，使这些关联与归组在检查后至提交间保持稳定；模型推理期间不持锁。四个工具实际返回的资产，以及已提供历史案例的相关资产，也记录引用时的归组：转组或删除会中止本轮，最终事务一并锁定；不引用的同组资产不加入锁集合。仍不覆盖两次检查间转组后又转回、历史案例读出后新增或改挂告警，以及成功提交后的历史结论撤销；不能作为整个权限生命周期已闭环的证明。

`TestTriageRejectsChangedMembership` 验证在模型请求期间转组时，直接答案与继续调用工具两条路径均中止：不写入 verdict/triaged_at，不增加研判次数，不触发 OnVerdict；`TestInvestigationScopeChangeCannotBeUndoneWithinRun` 验证已检测到的转组即使恢复原组也不能复用旧轮次。临时 PostgreSQL 17 的 triage/ueba 集成测试通过；Go 全量单测及最终相关包复测、build、vet 通过。上述未覆盖的竞态边界仍保留，未部署。

`TestTriagePersistenceLocksIncidentAssets` 在最终 Update 前暂停研判，修复前复现了检查后仍能转组；修复后通过独立数据库连接验证资产转组、告警移出、告警清除资产和新增关联均等待至请求超时，随后研判正常提交、资产可再次转组。锁仅覆盖最终落库事务，不跨模型调用。全量 Go 单测、build、vet，以及扩展后的 triage/ueba PostgreSQL 集成测试通过；临时数据库已清理。此测试不证明参考资产或提交后的历史结论权限已处理。

`TestInvestigationTracksReferencedPeers` 覆盖四个工具实际引用的同组资产转组，并验证无关资产转组不使本轮失效。`TestInvestigationReferenceLocksAndDeletion` 验证引用资产参与最终事务锁定、提交后释放锁，以及引用资产删除会使本轮失效。`TestTriageRejectsMovedReferenceBeforePersistence` 通过实际 triageOne 与模型 HTTP 调用链分别提供工具证据、历史人工案例，随后仅移动被引用资产；两条路径均未保存 verdict、未增加研判次数、未触发 OnVerdict，共享 Engine 不残留引用。全量 Go 单测、build、vet 和最终 triage/ueba PostgreSQL 集成测试通过，临时数据库已清理。未提交、未部署；历史案例关联关系的后续变化与已保存结论撤销仍待处理。

### 服务端证据字段摘录

已匹配的 `evidence_claims` 由服务端生成为 `evidence_observations`，仅含证据编号、字段与确定性文案；模型提供的同名字段会被覆盖。重复字段去重，无工具引用时为空数组。返回数量、截断、基线首次记录、采集快照和父进程 GUID 的文案明确适用边界；其他字段仅复述记录值，不补攻击或授权结论。前端独立展示摘录，摘要和攻击链保留模型判断标签，旧结论不补造摘录。

`observations_test.go` 验证伪造摘录被替换、缺失字段被拒绝、查询失败不变为零条结果、无工具时不产生事实，以及典型字段的范围说明。评分器投影测试确认服务端摘录不混入模型自由文本评分；摘要原文保持，不能把摘录上线当成摘要语义问题已消除。

Go 全量单测、build、vet，triage/ueba PostgreSQL 集成测试，Web build 与 lint 均完成。lint 仍有 Fast Refresh 导出警告；临时数据库已清理。本轮未做浏览器视觉验收和真实模型复测，未提交或部署，语义发布阻断保留。

后续[证据摘录组件浏览器验收](runs/2026-10-29-observations-ui/README.md)已完成，修复多条摘录遮蔽摘要的问题，覆盖两种宽度的展开收起、长文本、旧结论、等待和解析错误。仅组件合成数据验收，真实模型语义与生产整页验收仍未完成。

### 评分失败原文留证

`JudgeDetailed` 与 triagecheck 现在将完整评分和建议复核的响应原文、阶段、finish_reason 写入 `judge_attempts`。引文不匹配、JSON 无效或 length 截断均保留已收到的模型输出，不重试挑选结果；HTTP 错误正文不作为模型响应存档。测试覆盖两个评分阶段的失败输出、无效 JSON、截断、HTTP 429，以及 CLI 校准/生成报告中的双阶段原文。

此能力是在 `2026-10-29-scope-semantics` 运行期间补入的本地代码；该轮仍用启动时冻结的旧二进制，其报告不含评分失败原文，不能事后重建或声称已留证。新代码不改变评分规则或放宽引文要求。

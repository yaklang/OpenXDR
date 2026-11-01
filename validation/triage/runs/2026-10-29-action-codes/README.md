# 结构化建议真实模型验证（2026-10-29）

6 类既有脱敏样本，每类生成 2 次；不运行评分器、不运行校准、不执行调查工具或响应操作。
生成使用生产默认模型参数与同一 `EvaluateSnapshot` / `finishVerdict` / `bindEvidence` / `bindActions` 链路。

- 12/12 次生成一次通过结构校验，模型成功响应数各为 1，未使用修正；12/12 verdict 与预期一致。
- 独立按冻结的建议目录核对：所有 action_codes 有效、与 verdict 范围匹配，actions 逐项等于服务端文案。
- 工程逐条复核：11 pass、1 needs_review（authorized_maintenance / 2 的同一进程树主语范围歧义）。这不是独立人工验收。
- 该轮没有再出现无工单扩写为无人工记录、放宽 limit/取消裁剪、把暂存哈希直接当程序哈希的建议。
- 以上仅说明本轮生成和结构化建议验收通过，不保证自由文本将来不会再犯错，也不替代生产调查链路与评分器校准验收。整体语义门禁仍未完成。

工件：`results.jsonl` 保留全部 12 次；`engineering-review.json` 绑定原报告和各答案哈希；
`catalog.json` 与运行 metadata 的 actions_sha256 一致；`source.patch`、`source-manifest.json`、`probe.go` 冻结源码、二进制和生成探针；`cases.json` 为实际输入。
没有覆盖或挑选重复输出。配置只读加载，凭据不写入工件。未部署产品代码。

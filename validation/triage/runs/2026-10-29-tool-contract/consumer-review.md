# 结论消费链检查

本轮仅检查当前候选源码，未部署或修改生产。

- `server/internal/triage/engine.go:triageOne` 将结论 JSON 写入 incident；`appendRetriage` 又把 summary 送入下一轮上下文。
- `server/internal/notify/notify.go:fill` 读取 verdict、confidence、summary 写入通知内容。
- `web/src/components/VerdictCard.tsx` 直接展示 summary 和 actions，另展示服务端证据台账。
- `server/internal/response/auto.go:React` 读取 verdict 与 confidence 决定是否进入既有自动响应检查；没有把 actions 文本直接作为指令执行。

本轮新输出证明可选 evidence_claims 可被省略，而且有引用只证明所引字段一致，不能证明其他自由文本正确。后续实现须覆盖事实/推断边界、建议能力约束和通知/重研判兼容性，不得仅加“已核验”标记或在前端隐藏坏文本。既有响应开关、授权与审计边界保持必要约束。

评分调用缺少精确失败分类，也必须补齐：区分完整评分与独立建议评分、完成原因、格式/引用校验、超时及供应商状态；只记录固定诊断码，避免输出凭据或完整远端错误正文。当前旧报告的失败原因不能事后编造。

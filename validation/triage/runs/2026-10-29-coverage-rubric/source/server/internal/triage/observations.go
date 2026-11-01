package triage

import (
	"encoding/json"
	"fmt"
)

// evidenceObservation 只复述已匹配字段，不为模型摘要背书，也不证明原始数据真实性。
type evidenceObservation struct {
	EvidenceID string `json:"evidence_id"`
	Field      string `json:"field"`
	Text       string `json:"text"`
}

// 只在 bindEvidence 已逐项校验引用后调用；文案由服务端生成，不能接收模型同名字段。
func evidenceObservations(claims any) []evidenceObservation {
	observations := make([]evidenceObservation, 0)
	entries, _ := claims.([]any)
	seen := make(map[string]bool)
	for _, entry := range entries {
		claim := entry.(map[string]any)
		id, field := claim["evidence_id"].(string), claim["field"].(string)
		key := id + "/" + field
		if seen[key] {
			continue
		}
		seen[key] = true
		value, _ := json.Marshal(claim["value"])
		text := fmt.Sprintf("字段 %s 的记录值为 %s。", field, value)
		switch field {
		case "returned":
			text = fmt.Sprintf("本次查询返回 %s 条；返回数量不代表实际发生总量，零条不证明没有发生。", value)
		case "truncated":
			text = fmt.Sprintf("本次结果条数的截断标记为 %s；不代表单条正文完整，也不证明采集完整。", value)
		case "raw_truncated_records":
			text = fmt.Sprintf("本次返回记录中有 %s 条正文被裁剪；不能据此推断归一化字段缺失的原因。", value)
		case "dns_omitted_records":
			text = fmt.Sprintf("本次返回记录中有 %s 条省略了部分 DNS 字段；不代表 DNS 活动总量。", value)
		case "baseline_first_recorded_at":
			text = fmt.Sprintf("该资产与路径的平台基线首次记录时间为 %s；不是安装时间或实际首次执行时间。", value)
		case "baseline_status":
			text = fmt.Sprintf("该资产与路径的基线查询状态为 %s；unknown 不证明程序从未运行。", value)
		case "collection_states", "collection_paths", "collection_status", "collection_received_at":
			text = fmt.Sprintf("最近一次采集快照的 %s 记录为 %s；仅为该次 agent 自报，不能回推事发时状态或证明没有漏采。", field, value)
		case "parent_process_guid":
			text = fmt.Sprintf("这条归一化事件记录的父进程 GUID 为 %s；仅对应此记录，不证明更长的进程链或操作授权。", value)
		case "missing_ancestor":
			text = fmt.Sprintf("本次血缘查询的祖先缺失标记为 %s；缺失不等于没有父进程或行为正常。", value)
		}
		observations = append(observations, evidenceObservation{EvidenceID: id, Field: field, Text: text})
	}
	return observations
}

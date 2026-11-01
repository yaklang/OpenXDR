package triage

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// queryEvidence 记录查询覆盖和事件结构化字段，不把事件正文或模型推断升级成已核验事实。
type queryEvidence struct {
	ID      string           `json:"id"`
	Tool    string           `json:"tool"`
	Facts   map[string]any   `json:"facts"`
	Records []recordEvidence `json:"records,omitempty"`
}

// recordEvidence 的关系来自归一化事件列，不从 raw 文本或记录顺序猜测。
type recordEvidence struct {
	ID    string         `json:"id"`
	Facts map[string]any `json:"facts"`
}

func recordEvidenceFrom(queryID string, result map[string]any) []recordEvidence {
	if result["status"] != "ok" {
		return nil
	}
	var records []recordEvidence
	for _, key := range []string{"items", "self_and_ancestors", "children"} {
		items, _ := result[key].([]any)
		for index, value := range items {
			item, ok := value.(map[string]any)
			if !ok {
				continue
			}
			eventID, _ := item["event_id"].(string)
			if eventID == "" {
				continue
			}
			facts := make(map[string]any)
			for _, field := range []string{"event_id", "asset_id", "ts", "class", "source", "process_guid", "parent_process_guid", "raw_truncated", "dns_omitted"} {
				if value, exists := item[field]; exists {
					facts[field] = value
				}
			}
			records = append(records, recordEvidence{ID: fmt.Sprintf("%s/%s-%d", queryID, key, index+1), Facts: facts})
		}
	}
	return records
}

var evidenceFields = []string{"status", "returned", "limit", "truncated", "ancestors_truncated", "children_truncated", "missing_ancestor", "coverage", "mode", "raw_mode_scope", "raw_excerpt_limit_bytes", "from", "to", "asset_id", "collection_status", "collection_received_at", "collection_states", "collection_paths", "collection_scope", "baseline_status", "baseline_id", "exe_path", "baseline_path", "baseline_first_recorded_at", "baseline_scope"}

func queryEvidenceFrom(messages []Message) []queryEvidence {
	evidence := make([]queryEvidence, 0)
	tools := make(map[string]string)
	for _, msg := range messages {
		if msg.Role == "assistant" {
			for _, call := range msg.ToolCalls {
				tools[call.ID] = call.Function.Name
			}
		}
		if msg.Role != "tool" {
			continue
		}
		facts := make(map[string]any)
		var result map[string]any
		if json.Unmarshal([]byte(msg.Content), &result) != nil {
			result = map[string]any{"status": "error", "coverage": "unknown"}
		}
		for _, field := range evidenceFields {
			if value, ok := result[field]; ok {
				facts[field] = value
			}
		}
		appendContentCoverage(facts, result)
		id := fmt.Sprintf("query-%d", len(evidence)+1)
		evidence = append(evidence, queryEvidence{ID: id, Tool: tools[msg.ToolCallID], Facts: facts, Records: recordEvidenceFrom(id, result)})
	}
	return evidence
}

// appendContentCoverage 区分返回条数截断与单条正文裁剪；不递归读取不可信 raw 内容。
func appendContentCoverage(facts, result map[string]any) {
	if result["status"] != "ok" {
		return
	}
	rawTrimmed, dnsOmitted, inspected := 0, 0, false
	for _, key := range []string{"items", "self_and_ancestors", "children"} {
		records, ok := result[key].([]any)
		if !ok {
			continue
		}
		inspected = true
		for _, record := range records {
			item, ok := record.(map[string]any)
			if !ok {
				continue
			}
			if item["raw_truncated"] == true {
				rawTrimmed++
			}
			if omitted, ok := item["dns_omitted"].([]any); ok && len(omitted) > 0 {
				dnsOmitted++
			}
		}
	}
	if inspected {
		// 与解码 JSON 数字的类型一致，供引用值精确比较。
		facts["raw_truncated_records"] = float64(rawTrimmed)
		facts["dns_omitted_records"] = float64(dnsOmitted)
	}
}

// bindEvidence 覆盖模型伪造的查询台账；引用只能复述查询或事件记录中存在的字段和值，缺失不能当作 false。
// 引用通过只表示与记录匹配，不能证明 summary 或攻击推断成立。
func bindEvidence(msg Message, messages []Message) (string, error) {
	if err := validateVerdict(msg); err != nil {
		return "", err
	}
	var verdict map[string]any
	if err := json.Unmarshal(parseVerdict("", msg.Content), &verdict); err != nil {
		return "", err
	}
	evidence := queryEvidenceFrom(messages)
	factsByID := make(map[string]map[string]any)
	for _, query := range evidence {
		factsByID[query.ID] = query.Facts
		for _, record := range query.Records {
			factsByID[record.ID] = record.Facts
		}
	}
	claims, exists := verdict["evidence_claims"]
	if len(evidence) > 0 {
		entries, ok := claims.([]any)
		if !ok || len(entries) == 0 {
			return "", fmt.Errorf("已有工具证据时 evidence_claims 必须包含至少一项实际引用")
		}
	}
	if exists {
		entries, ok := claims.([]any)
		if !ok {
			return "", fmt.Errorf("evidence_claims 必须是数组")
		}
		for _, entry := range entries {
			claim, ok := entry.(map[string]any)
			if !ok || len(claim) != 3 {
				return "", fmt.Errorf("证据引用仅允许 evidence_id、field、value 三个字段")
			}
			id, _ := claim["evidence_id"].(string)
			field, _ := claim["field"].(string)
			value, exists := factsByID[id][field]
			claimed, supplied := claim["value"]
			matched := exists && supplied && reflect.DeepEqual(value, claimed)
			if !matched {
				return "", fmt.Errorf("证据引用不存在或与查询元数据不一致")
			}
		}
	}
	if err := bindActions(verdict); err != nil {
		return "", err
	}
	verdict["query_evidence"] = evidence
	verdict["evidence_observations"] = evidenceObservations(claims)
	out, err := json.Marshal(verdict)
	return string(out), err
}

package closurereview

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"openxdr/server/internal/triage"
)

// maxBenignAlerts 良性结案单次交审计员的告警上限：审计员要为每个原始事件给出字段级引用，再多就引用不全
const maxBenignAlerts = 20

// truncMark 服务端截断超长字段时插入的标记；引用值里带它的不计入覆盖
const truncMark = "[服务端截断："

// fieldKeep 单个字符串字段超过它就只保留首尾
const (
	fieldKeep = 2048
	headKeep  = 1536
	tailKeep  = 512
)

// truncateRaw 原始事件里超过 fieldKeep 的字符串字段保留首尾，中间换成带原长与摘要的标记；
// 其余字段原样保留，审计员照样逐字引用。原文不是 JSON 对象时返回 false
func truncateRaw(raw json.RawMessage) (json.RawMessage, bool) {
	var doc any
	if json.Unmarshal(raw, &doc) != nil {
		return nil, false
	}
	if _, ok := doc.(map[string]any); !ok {
		return nil, false
	}
	out := triage.RawJSON(truncateValue(doc))
	return out, out != nil
}

func truncateValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = truncateValue(x)
		}
	case []any:
		for i, x := range t {
			t[i] = truncateValue(x)
		}
	case string:
		if len(t) > fieldKeep {
			return cutHead(t, headKeep) + fmt.Sprintf("…%s原长 %d 字节，sha256 %s]…", truncMark, len(t), digest([]byte(t))[:16]) + cutTail(t, tailKeep)
		}
	}
	return v
}

func cutHead(s string, n int) string {
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func cutTail(s string, n int) string {
	i := len(s) - n
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	return s[i:]
}

// auditVerdict 交审计员的研判结论去掉调查工具的查询摘录：摘录按 4096 字节裁剪并标 raw_truncated，
// 审计员常把它误当成材料缺字段；审计以材料自己的原始事件与 lineage 为准
func auditVerdict(raw json.RawMessage) json.RawMessage {
	var v map[string]json.RawMessage
	if json.Unmarshal(raw, &v) != nil {
		return raw
	}
	if _, ok := v["query_evidence"]; !ok {
		return raw
	}
	delete(v, "query_evidence")
	out, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return out
}

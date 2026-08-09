package grpcsvc

import (
	"encoding/json"
	"strings"
)

// 剥掉原始事件 JSON 字符串里的 NUL 字符：jsonb 不接受 \u0000
// （SQLSTATE 22P05），一条带 NUL 的脏事件会让整个批量插入失败，
// agent 重连后重放同一批又失败，事件管道被无限毒化。
// 采集端已尽量在源头剥除，这里是纵深防御的最后一道。
func sanitizeRawJSON(raw json.RawMessage) json.RawMessage {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return json.RawMessage("{}")
	}
	v = stripNUL(v)
	out, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("{}")
	}
	return out
}

// 递归遍历解码后的 JSON 值，剥掉所有字符串中的 NUL。
func stripNUL(v any) any {
	switch t := v.(type) {
	case string:
		if strings.ContainsRune(t, 0) {
			return strings.ReplaceAll(t, "\x00", "")
		}
		return t
	case map[string]any:
		for k, val := range t {
			t[k] = stripNUL(val)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = stripNUL(val)
		}
		return t
	default:
		return v
	}
}

package eventsearch

import (
	"encoding/json"
	"fmt"
	"strings"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"openxdr/server/ent/predicate"
)

// Fields 只允许固定的归一化字段；值以参数传递，不接受任意 SQL 或 JSON 路径。
type Fields map[string]string

var fieldPaths = map[string]string{
	"srcIp":       "src_endpoint.ip",
	"dstIp":       "dst_endpoint.ip",
	"srcPort":     "src_endpoint.port",
	"dstPort":     "dst_endpoint.port",
	"processName": "process.name",
	"commandLine": "process.cmd_line",
	"filePath":    "file.path",
}

func (f Fields) Validate() error {
	for field, value := range f {
		if _, ok := fieldPaths[field]; !ok {
			return fmt.Errorf("不支持的检索字段：%s", field)
		}
		if len(value) > 4096 {
			return fmt.Errorf("检索字段过长：%s", field)
		}
	}
	return nil
}

func (f Fields) Predicate() predicate.Event {
	return func(s *sql.Selector) {
		for field, value := range f {
			path, ok := fieldPaths[field]
			if !ok {
				s.Where(sql.ExprP("FALSE"))
				continue
			}
			s.Where(sqljson.ValueEQ(s.C("raw"), value, sqljson.Path(strings.Split(path, ".")...)))
		}
	}
}

// Match 与热表的 #>> 文本相等口径保持一致，缺失或 null 不匹配。
func (f Fields) Match(raw json.RawMessage) bool {
	if len(f) == 0 {
		return true
	}
	var data map[string]any
	if json.Unmarshal(raw, &data) != nil {
		return false
	}
	for field, value := range f {
		path, ok := fieldPaths[field]
		if !ok {
			return false
		}
		var current any = data
		for _, part := range strings.Split(path, ".") {
			object, ok := current.(map[string]any)
			if !ok {
				return false
			}
			current = object[part]
		}
		if current == nil || fmt.Sprint(current) != value {
			return false
		}
	}
	return true
}

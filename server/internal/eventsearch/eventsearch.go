// Package eventsearch 事件关键词检索：trgm 索引与匹配谓词同一处定义，控制台检索与研判工具共用一个口径。
//
// 旧索引 events_raw_trgm 对整个 raw::text 切三元组，字段名、JSON 标点、UUID 与 sha256 都进了索引，
// 生产上它比事件表本身的一大半还大。新索引 events_search_trgm 只索引事件里的标量值，并去掉 UUID 与
// 32 位以上的十六进制串（进程 uid、文件哈希）——这类高熵串每个字符都是新三元组，却几乎只会被整串搜索。
// 关键词只由十六进制字符与连字符组成且含字母或连字符时（UUID、哈希片段），回退到 raw::text 匹配，不漏结果。
package eventsearch

import (
	"context"
	"database/sql"
	"log/slog"
	"regexp"
	"strings"
	"sync/atomic"

	entsql "entgo.io/ent/dialect/sql"

	entevent "openxdr/server/ent/event"
	"openxdr/server/ent/predicate"
)

// searchText 索引表达式用的函数。函数体变了索引不会跟着重建，改口径（输出）必须换函数名与索引名；
// 只许做输出逐字不变的提速。trgm 是有损索引，命中的每一行都要重算一遍这个函数，它的开销直接决定检索耗时：
// 被排除的串都不短于 32 个字符，先比长度再跑正则，大多数值不进正则。
const searchText = `CREATE OR REPLACE FUNCTION openxdr_event_search_text(raw jsonb) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
  SELECT string_agg(v #>> '{}', ' ') FROM jsonb_path_query(raw, 'strict $.**') v
  WHERE jsonb_typeof(v) IN ('string', 'number', 'boolean')
    AND NOT (length(v #>> '{}') >= 32
      AND v #>> '{}' ~ '^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{32,})$')
$$`

const (
	oldIndex = "events_raw_trgm"
	newIndex = "events_search_trgm"
)

// byValue 库里有可用的 events_search_trgm 时按值匹配，否则沿用 raw::text（旧索引或全表扫）。
var byValue atomic.Bool

// Ensure 建检索函数与索引，并按库里实际可用的索引决定匹配口径。
// 已有旧索引的库不在启动时现建新索引：大表上建 GIN 要几个小时且挡住写入，由管理员按文档在线建好再重启。
// CREATE EXTENSION 需要数据库权限，失败只降级警告——检索仍然可用，只是慢。
func Ensure(ctx context.Context, db *sql.DB) {
	if err := ensure(ctx, db); err != nil {
		slog.Warn("检索索引未启用，大数据量下关键词搜索会退化为全表扫描", "err", err)
	}
	valid, err := validIndex(ctx, db, newIndex)
	if err != nil {
		slog.Warn("检索索引状态读取失败，按原始事件全文匹配", "err", err)
	}
	byValue.Store(valid)
	if old, _ := exists(ctx, db, oldIndex); valid && old {
		slog.Info("events_search_trgm 已可用，可以删除旧检索索引 events_raw_trgm", "doc", "docs/event-partitioning.md")
	}
}

func ensure(ctx context.Context, db *sql.DB) error {
	for _, stmt := range []string{"CREATE EXTENSION IF NOT EXISTS pg_trgm", searchText} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if old, err := exists(ctx, db, oldIndex); err != nil || old {
		return err
	}
	_, err := db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS "+newIndex+" ON events USING gin (openxdr_event_search_text(raw) gin_trgm_ops)")
	return err
}

func exists(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var ok bool
	err := db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&ok)
	return ok, err
}

// validIndex 在线建到一半或失败的索引 indisvalid 为假，查询用不上，不能据此切换口径。
func validIndex(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var ok bool
	err := db.QueryRowContext(ctx, `SELECT coalesce((SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass($1)), false)`, name).Scan(&ok)
	return ok, err
}

var hexish = regexp.MustCompile(`(?i)^[0-9a-f-]*[a-f-][0-9a-f-]*$`)

// Match 一个关键词条件。关键词是字面量，% _ \ 转义后不会变成通配符；大小写不敏感。
type Match struct {
	kw    string
	value bool
}

// Keyword 一般关键词：有值索引时按字段值匹配，UUID / 哈希类关键词回退完整原文。
func Keyword(kw string) Match { return Match{kw, byValue.Load() && !hexish.MatchString(kw)} }

// ValuesKeyword 显式搜索索引字段值，不含被排除的 UUID / 长哈希；调用方必须告知覆盖范围。
func ValuesKeyword(kw string) Match { return Match{kw, byValue.Load()} }

// RawKeyword 显式搜索完整原文，调用方应限制时间与范围。
func RawKeyword(kw string) Match { return Match{kw, false} }

// Predicate 与索引表达式一致的写法，规划器可以走 trgm 索引。
func (m Match) Predicate() predicate.Event { return m.where("") }

// scan 结果与 Predicate 相同，但表达式和索引对不上，规划器只能逐行过滤；
// 用在已按时间收窄的小范围里，免得它又去整表走 trgm 索引。
func (m Match) scan() predicate.Event { return m.where(" || ''") }

func (m Match) where(suffix string) predicate.Event {
	pattern := "%" + escapeLike(m.kw) + "%"
	return predicate.Event(func(s *entsql.Selector) {
		s.Where(entsql.P(func(b *entsql.Builder) {
			b.WriteString("(")
			if m.value {
				b.WriteString("openxdr_event_search_text(").WriteString(s.C(entevent.FieldRaw)).WriteString(")")
			} else {
				b.WriteString(s.C(entevent.FieldRaw)).WriteString("::text")
			}
			b.WriteString(suffix).WriteString(") ILIKE ").Arg(pattern)
		}))
	})
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

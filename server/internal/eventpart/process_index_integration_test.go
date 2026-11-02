//go:build integration

package eventpart_test

import (
	"encoding/json"
	"strings"
	"testing"

	"openxdr/server/internal/eventpart"
)

func TestProcessGUIDLookupWithoutRedundantIndex(t *testing.T) {
	ctx, client, db := open(t)
	// 与待清理的生产普通表一致，不依赖其他迁移测试留下的索引集合。
	legacySchema(t, ctx, client, db)
	if _, err := db.ExecContext(ctx, `CREATE INDEX event_process_guid_ts ON events(process_guid,ts) WHERE process_guid IS NOT NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DROP INDEX IF EXISTS event_process_guid`); err != nil {
		t.Fatal(err)
	}
	if exists(t, db, `SELECT 1 FROM pg_class WHERE relname='event_process_guid'`) {
		t.Fatal("重复 GUID 索引未移除")
	}
	// 打散时间与 GUID 的相关性，避免 LIMIT 偶然偏好时间索引。
	day := eventpart.Today()
	_, err := db.ExecContext(ctx, `INSERT INTO events(id,ts,class_uid,source,process_guid,raw)
 SELECT md5('guid-index-event-'||n)::uuid,$1::timestamptz+((n*7919)%20000)*interval '1 millisecond',
 CASE WHEN (n/1000)%2=0 THEN 1007 ELSE 4001 END,'agent',
 CASE WHEN n%10=0 THEN NULL ELSE md5((n%1000)::text)::uuid END,'{}'::jsonb
 FROM generate_series(1,20000) n`, day)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `ANALYZE events`); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db, `SELECT count(*) FROM events WHERE process_guid=md5('42')::uuid`); n != 20 {
		t.Fatalf("GUID 等值查询丢记录: %d", n)
	}
	if n := count(t, db, `SELECT count(*) FROM events WHERE process_guid=ANY(ARRAY[md5('42')::uuid,md5('43')::uuid])`); n != 40 {
		t.Fatalf("GUID 批量查询丢记录: %d", n)
	}
	if n := count(t, db, `SELECT count(*) FROM events WHERE process_guid IS NULL`); n != 2000 {
		t.Fatalf("空 GUID 语义改变: %d", n)
	}
	var plan []byte
	if err := db.QueryRowContext(ctx, `EXPLAIN (FORMAT JSON) SELECT id,ts FROM events
 WHERE process_guid=md5('42')::uuid AND ts >= $1 AND ts < $1::timestamptz+interval '1 day'
 ORDER BY ts DESC LIMIT 10`, day).Scan(&plan); err != nil {
		t.Fatal(err)
	}
	var nodes []map[string]any
	if err := json.Unmarshal(plan, &nodes); err != nil {
		t.Fatal(err)
	}
	var indexNames []string
	var walk func(map[string]any)
	walk = func(n map[string]any) {
		if name, ok := n["Index Name"].(string); ok {
			indexNames = append(indexNames, name)
		}
		if children, ok := n["Plans"].([]any); ok {
			for _, child := range children {
				walk(child.(map[string]any))
			}
		}
	}
	walk(nodes[0]["Plan"].(map[string]any))
	covered := false
	for _, name := range indexNames {
		var definition string
		if err := db.QueryRowContext(ctx, `SELECT pg_get_indexdef(oid) FROM pg_class WHERE relname=$1`, name).Scan(&definition); err != nil {
			t.Fatal(err)
		}
		covered = covered || strings.Contains(definition, "(process_guid, ts)")
	}
	if !covered {
		t.Fatalf("GUID 时间查询未使用联合索引: %s", plan)
	}
}

//go:build integration

package eventpart_test

import (
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestRedundantProcessIndexCleanupGuards(t *testing.T) {
	ctx, client, db := open(t)
	script, err := os.ReadFile("../../../deploy/ha/drop-redundant-process-index.sql")
	if err != nil {
		t.Fatal(err)
	}
	sqlText := strings.ReplaceAll(string(script), "\\set ON_ERROR_STOP on\n", "")
	prelude, drop, ok := strings.Cut(sqlText, "\nDROP INDEX CONCURRENTLY")
	if !ok {
		t.Fatal("清理脚本缺少并发删除语句")
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	apply := func() error {
		if _, err := conn.ExecContext(ctx, prelude); err != nil {
			return err
		}
		_, err := conn.ExecContext(ctx, "DROP INDEX CONCURRENTLY"+drop)
		return err
	}
	if err := apply(); err == nil {
		t.Fatal("分区父表必须拒绝直接并发删除")
	}
	legacySchema(t, ctx, client, db)
	if _, err := db.ExecContext(ctx, `INSERT INTO events(id,ts,class_uid,source,process_guid,raw) VALUES
 ($1,now(),1007,'agent',$2,'{}'),($3,now(),4003,'agent',NULL,'{}')`, uuid.New(), uuid.New(), uuid.New()); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err == nil {
		t.Fatal("没有替代索引不能删除")
	}
	if !exists(t, db, `SELECT 1 FROM pg_class WHERE relname='event_process_guid'`) {
		t.Fatal("校验失败删除了旧索引")
	}
	if _, err := db.ExecContext(ctx, `CREATE INDEX event_process_guid_ts ON events(process_guid,ts) WHERE class_uid=1007`); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err == nil {
		t.Fatal("谓词收窄的联合索引不能替代所有 GUID 查询")
	}
	if _, err := db.ExecContext(ctx, `DROP INDEX event_process_guid_ts; CREATE INDEX event_process_guid_ts ON events(process_guid,ts) WHERE process_guid IS NOT NULL`); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err != nil {
		t.Fatal(err)
	}
	if exists(t, db, `SELECT 1 FROM pg_class WHERE relname='event_process_guid'`) {
		t.Fatal("旧索引未删除")
	}
	if n := count(t, db, `SELECT count(*) FROM events`); n != 2 {
		t.Fatalf("索引维护改变了事件: %d", n)
	}
	if err := apply(); err != nil {
		t.Fatalf("重复维护应安全: %v", err)
	}
}

//go:build integration

package temporal_test

import (
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/temporal"
	"openxdr/server/internal/testdb"
)

func TestArchiveCleanupPreservesReferencesAndLocks(t *testing.T) {
	ctx, c := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	group := uuid.New()
	asset := c.Asset.Create().SetHostname("archive-cleanup").SetGroupID(group).SaveX(ctx)
	prefix := uuid.NewString() + ":"
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, kind := range []string{"candidate", "detection", "gap", "locked", "orphan", "fresh"} {
		created := cutoff.Add(-time.Hour)
		if kind == "fresh" {
			created = time.Now()
		}
		if _, err := db.Exec(`INSERT INTO temporal_rule_snapshots(revision,document,created_at) VALUES($1,'{}',$2)`, prefix+kind, created); err != nil {
			t.Fatal(err)
		}
	}
	var ids []uuid.UUID
	for _, kind := range []string{"candidate", "detection", "gap"} {
		e := c.Event.Create().SetTs(time.Now()).SetAssetID(asset.ID).SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
		ids = append(ids, e.ID)
		var query string
		switch kind {
		case "candidate":
			query = `INSERT INTO temporal_candidates(revision,event_id,asset_id,group_id,ts,rules) VALUES($1,$2,$3,$4,now(),'[]')`
		case "detection":
			query = `INSERT INTO temporal_detections(revision,anchor_id,entity,group_id,rule_id,evidence) VALUES($1,$2,$3,$4,'test','[]')`
		case "gap":
			query = `INSERT INTO temporal_evaluation_gaps(revision,event_id,asset_id,group_id,reason,candidate_count_lower_bound,window_from,window_to) VALUES($1,$2,$3,$4,'candidate_limit',10001,now(),now())`
		}
		if _, err := db.Exec(query, prefix+kind, e.ID, asset.ID, group); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`DELETE FROM temporal_rule_snapshots WHERE revision=$1`, prefix+kind); err == nil {
			t.Fatalf("%s 未被外键保护", kind)
		}
	}
	lock, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err := lock.Exec(`SELECT revision FROM temporal_rule_snapshots WHERE revision=$1 FOR KEY SHARE`, prefix+"locked"); err != nil {
		t.Fatal(err)
	}
	if n, err := temporal.PruneArchives(ctx, db, cutoff); err != nil || n != 1 {
		t.Fatalf("清理应只删旧孤立版本: %d %v", n, err)
	}
	var found int
	if err := db.QueryRow(`SELECT count(*) FROM temporal_rule_snapshots WHERE revision=$1`, prefix+"locked").Scan(&found); err != nil || found != 1 {
		t.Fatal("正在入库的版本被删除")
	}
	if err := lock.Rollback(); err != nil {
		t.Fatal(err)
	}
	if n, err := temporal.PruneArchives(ctx, db, cutoff); err != nil || n != 1 {
		t.Fatalf("解锁后应删除孤立版本: %d %v", n, err)
	}
	for _, id := range ids {
		c.Event.DeleteOneID(id).ExecX(ctx)
	}
	if n, err := temporal.PruneArchives(ctx, db, cutoff); err != nil || n != 2 {
		t.Fatalf("引用清理后应释放未被 gap 引用的归档: %d %v", n, err)
	}
	// R6：gap 不再随事件删除级联，按自身 created_at 的诊断保留期清理——被 gap 引用的
	// 归档快照跟随诊断期，gap 过期后由 PruneGaps 释放，PruneArchives 才能回收它。
	if n, err := temporal.PruneGaps(ctx, db, 0); err != nil || n != 1 {
		t.Fatalf("应按诊断期清掉 gap 释放引用: %d %v", n, err)
	}
	if n, err := temporal.PruneArchives(ctx, db, cutoff); err != nil || n != 1 {
		t.Fatalf("gap 释放后最后一个归档应可回收: %d %v", n, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM temporal_rule_snapshots WHERE revision=$1`, prefix+"fresh").Scan(&found); err != nil || found != 1 {
		t.Fatal("新归档被提前清理")
	}
}

//go:build integration

package janitor

import (
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/testdb"
)

// 分区表上的保留期：过期日分区整体退役（证据并入归档），逐行清理只碰归档与默认分区，
// 已过期但仍在日分区里的行留给退役，不逐行删。
func TestJanitorRetiresPartitionsAndSweepsOnlyArchive(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	// 用 t.Cleanup 关连接：后注册的删归档分区先执行，连接还开着（defer 会先关连接，删表静默失败）
	t.Cleanup(func() { db.Close() })
	if err := ingest.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	today := eventpart.Today()
	first := today.AddDate(0, 0, -5)
	if _, err := eventpart.EnsureDays(ctx, db, eventpart.Parent, first, 1); err != nil {
		t.Fatal(err)
	}
	// 归档分区会接住其他测试的历史时间戳，用完删掉
	t.Cleanup(func() {
		for _, day := range []time.Time{first, first.AddDate(0, 0, 1)} {
			db.Exec(`DROP TABLE IF EXISTS ` + eventpart.ArchiveName(day))
		}
	})
	create := func(ts time.Time) uuid.UUID {
		return client.Event.Create().SetTs(ts).SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(`{}`)).SaveX(ctx).ID
	}
	expired := create(first.Add(time.Hour))
	alerted := create(first.AddDate(0, 0, 1).Add(time.Hour))
	inToday := create(today.Add(time.Minute))
	stray := create(today.AddDate(0, 0, -40))
	client.Alert.Create().SetTs(today).SetRuleID("r").SetSeverity(3).SetEventID(alerted).SaveX(ctx)

	j := &Janitor{DB: client, SQL: db, Retention: time.Minute}
	if n, _, err := eventpart.Retire(ctx, db, retireCutoff(time.Now(), j.Retention)); err != nil || n != 2 {
		t.Fatalf("应退役两个过期日分区: %d %v", n, err)
	}
	if n, err := j.sweep(ctx); err != nil || n != 1 {
		t.Fatalf("逐行清理只应删默认分区里的 1 条: %d %v", n, err)
	}
	for name, c := range map[string]struct {
		id   uuid.UUID
		want bool
	}{"过期无引用": {expired, false}, "被告警引用": {alerted, true}, "今天日分区": {inToday, true}, "默认分区远古": {stray, false}} {
		if _, err := client.Event.Get(ctx, c.id); (err == nil) != c.want {
			t.Errorf("%s：存在=%v，期望 %v", name, err == nil, c.want)
		}
	}
}

// 退役的日子必须早于时序证据可能回看的范围，保留期配得再短也一样。
func TestRetireCutoffRespectsTemporalGuard(t *testing.T) {
	now := time.Now()
	if got := retireCutoff(now, time.Hour); !got.Equal(now.Add(-retireGuard)) {
		t.Fatalf("短保留期也要退到守护线之前: %v", got)
	}
	if got := retireCutoff(now, 30*24*time.Hour); !got.Equal(now.Add(-30 * 24 * time.Hour)) {
		t.Fatalf("长保留期按保留期: %v", got)
	}
}

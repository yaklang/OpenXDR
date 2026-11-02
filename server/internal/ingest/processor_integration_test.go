//go:build integration

package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/ent"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
)

func testProcessor(t *testing.T) (*Processor, *ent.Client, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("INTEGRATION_DATABASE_URL")
	if dsn == "" {
		t.Skip("INTEGRATION_DATABASE_URL 未配置")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	ctx := context.Background()
	if err := eventpart.Migrate(ctx, client, db); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	// 派生表不再有指向 events 的外键，TRUNCATE events CASCADE 带不走它们，要点名清
	if _, err := db.Exec(`TRUNCATE assetmap_queue, alert_dedup_state, alerts, events, assets, temporal_matches, temporal_candidates,
 temporal_evaluation_gaps, temporal_detections, identity_observations, identity_local_snapshots CASCADE`); err != nil {
		t.Fatal(err)
	}
	rules := sigma.LoadDir(t.TempDir())
	return &Processor{DB: db, Rules: rules, Suppress: suppress.New(client, 0), Intel: intel.New(client, 0), DedupWindow: time.Hour}, client, db
}

func TestProcessorEventIdempotency(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	e := Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: "asset-a", Timestamp: time.Now(), ClassUID: 1007, Source: "agent", Raw: json.RawMessage(`{"process":{"name":"safe"}}`)}
	if err := p.Process(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if n, _ := client.Event.Query().Count(context.Background()); n != 1 {
		t.Fatalf("重复投递只能落一条事件，实际 %d", n)
	}
}

func TestPersistentDedupAcrossProcessors(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	dir := t.TempDir()
	rule := `title: Test
id: 11111111-1111-4111-8111-111111111111
status: test
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: evil-marker
  condition: selection
level: high
`
	if err := os.WriteFile(filepath.Join(dir, "rule.yml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	p.Rules = sigma.LoadDir(dir)
	p2 := *p
	now := time.Now()
	base := Envelope{Version: EnvelopeVersion, PartitionKey: "asset-a", Timestamp: now, ClassUID: 1007, Source: "agent", AssetOS: "linux", Raw: json.RawMessage(`{"process":{"cmd_line":"evil-marker"}}`)}
	first := base
	first.ID = StableID(t.Name(), "1")
	second := base
	second.ID = StableID(t.Name(), "2")
	second.Timestamp = now.Add(time.Second)
	if err := p.Process(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := p2.Process(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	alerts, err := client.Alert.Query().All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Count != 2 {
		t.Fatalf("跨处理器应合并为一条 count=2 告警，实际 %#v", alerts)
	}
}

// 平台指令拉起的进程触发的告警挂在指令上、单独去重；标记核对不上（别的资产的、不存在的、早已结束的指令）照常告警
func TestPlatformCommandAlerts(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	_, _ = db.Exec(`TRUNCATE commands CASCADE`)
	dir := t.TempDir()
	rule := `title: Test
id: 22222222-2222-4222-8222-222222222222
status: test
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: probe-marker
  condition: selection
level: high
`
	if err := os.WriteFile(filepath.Join(dir, "rule.yml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	p.Rules = sigma.LoadDir(dir)
	asset := client.Asset.Create().SetHostname("pve1").SaveX(ctx)
	other := client.Asset.Create().SetHostname("pve2").SaveX(ctx)
	now := time.Now()
	running := client.Command.Create().SetKind("exec").SetAssetID(asset.ID).SetCreatedAt(now.Add(-time.Minute)).SaveX(ctx)
	elsewhere := client.Command.Create().SetKind("exec").SetAssetID(other.ID).SetCreatedAt(now.Add(-time.Minute)).SaveX(ctx)
	stale := client.Command.Create().SetKind("exec").SetAssetID(asset.ID).SetCreatedAt(now.Add(-3 * time.Hour)).
		SetCompletedAt(now.Add(-2 * time.Hour)).SaveX(ctx)

	for i, tag := range []string{running.ID.String(), "", uuid.NewString(), elsewhere.ID.String(), stale.ID.String()} {
		raw := `{"process":{"cmd_line":"probe-marker"}}`
		if tag != "" {
			raw = `{"process":{"cmd_line":"probe-marker"},"platform_command":{"uid":"` + tag + `"}}`
		}
		e := Envelope{Version: EnvelopeVersion, ID: StableID(t.Name(), strconv.Itoa(i)), PartitionKey: asset.ID.String(), AssetID: &asset.ID,
			Timestamp: now.Add(time.Duration(i) * time.Second), ClassUID: 1007, Source: "agent", AssetOS: "linux", Raw: json.RawMessage(raw)}
		if err := p.Process(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	alerts := client.Alert.Query().AllX(ctx)
	var tagged, plain int
	for _, a := range alerts {
		switch {
		case a.CommandID != nil && *a.CommandID == running.ID && a.Count == 1:
			tagged++
		case a.CommandID == nil && a.Count == 4:
			plain++
		default:
			t.Fatalf("意外的告警: %+v", a)
		}
	}
	if tagged != 1 || plain != 1 {
		t.Fatalf("应有一条挂在指令上的告警、一条照常告警（4 次）: %+v", alerts)
	}
}

// 到达顺序不能替代事件时间；同一时间戳无法证明失败发生在成功之前。
func TestBruteforceEventTimeWindow(t *testing.T) {
	for _, tc := range []struct {
		name       string
		offset     time.Duration
		otherUser  bool
		otherAsset bool
		want       int
	}{
		{name: "窗口内", offset: -time.Minute, want: 1},
		{name: "窗口下界", offset: -10 * time.Minute, want: 1},
		{name: "窗口外", offset: -10*time.Minute - time.Microsecond},
		{name: "相同时间", offset: 0},
		{name: "未来失败先到达", offset: time.Minute},
		{name: "不同用户", offset: -time.Minute, otherUser: true},
		{name: "不同资产", offset: -time.Minute, otherAsset: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, client, db := testProcessor(t)
			defer client.Close()
			defer db.Close()
			ctx := context.Background()
			asset, err := client.Asset.Create().SetHostname("auth-target").SetOs("linux").Save(ctx)
			if err != nil {
				t.Fatal(err)
			}
			failureAsset := asset.ID
			if tc.otherAsset {
				other, err := client.Asset.Create().SetHostname("other").SetOs("linux").Save(ctx)
				if err != nil {
					t.Fatal(err)
				}
				failureAsset = other.ID
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			success := Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: asset.ID.String(), Timestamp: now,
				ClassUID: 3002, Source: "agent", AssetID: &asset.ID, Username: "root", Raw: json.RawMessage(`{"status_id":1}`)}
			for i := 0; i < 5; i++ {
				failure := success
				failure.ID = uuid.New()
				failure.AssetID = &failureAsset
				failure.PartitionKey = failureAsset.String()
				failure.Timestamp = now.Add(tc.offset)
				failure.Raw = json.RawMessage(`{"status_id":2}`)
				if tc.otherUser {
					failure.Username = "alice"
				}
				if err := p.Process(ctx, failure); err != nil {
					t.Fatal(err)
				}
			}
			// 新处理器读取持久状态；再次投递同一成功事件不能增加告警数。
			restarted := *p
			for i := 0; i < 2; i++ {
				if err := restarted.Process(ctx, success); err != nil {
					t.Fatal(err)
				}
			}
			alerts, err := client.Alert.Query().All(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(alerts) != tc.want {
				t.Fatalf("告警数 %d，期望 %d", len(alerts), tc.want)
			}
			if len(alerts) > 0 && (alerts[0].Count != 1 || alerts[0].RuleID != sigma.RuleBruteforceSuccess) {
				t.Fatalf("重投改变告警: %+v", alerts[0])
			}
		})
	}
}

func TestLateAuthFailuresMatchOnceAcrossProcessors(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	asset, err := client.Asset.Create().SetHostname("late-auth").SetOs("linux").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	success := Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: asset.ID.String(), Timestamp: now, ClassUID: 3002, Source: "agent", AssetID: &asset.ID, Username: "root", Raw: json.RawMessage(`{"status_id":1}`)}
	if err := p.Process(ctx, success); err != nil {
		t.Fatal(err)
	}
	// 多个处理器并发接收先前发生的失败，最后一条应补出成功事件的告警。
	errors := make(chan error, 10)
	for i := 0; i < 10; i++ {
		failure := success
		failure.ID = uuid.New()
		failure.Timestamp = now.Add(-time.Duration(i+1) * time.Second)
		failure.Raw = json.RawMessage(`{"status_id":2}`)
		restarted := *p
		go func() {
			if err := restarted.Process(ctx, failure); err != nil {
				errors <- err
				return
			}
			errors <- restarted.Process(ctx, failure)
		}()
	}
	for i := 0; i < 10; i++ {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	alerts, err := client.Alert.Query().All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Count != 1 || alerts[0].EventID == nil || *alerts[0].EventID != success.ID {
		t.Fatalf("迟到命中应唯一且绑定成功事件: %+v", alerts)
	}
	var matches int
	if err := db.QueryRow(`SELECT count(*) FROM temporal_matches`).Scan(&matches); err != nil || matches != 1 {
		t.Fatalf("持久命中 %d: %v", matches, err)
	}
}

func TestTemporalMatchRollsBackWithAlert(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	asset, err := client.Asset.Create().SetHostname("rollback-auth").SetOs("linux").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	success := Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: asset.ID.String(), Timestamp: now, ClassUID: 3002, Source: "agent", AssetID: &asset.ID, Username: "root", Raw: json.RawMessage(`{"status_id":1}`)}
	if err := p.Process(ctx, success); err != nil {
		t.Fatal(err)
	}
	failure := success
	failure.Raw = json.RawMessage(`{"status_id":2}`)
	for i := 0; i < 4; i++ {
		failure.ID = uuid.New()
		failure.Timestamp = now.Add(-time.Duration(i+1) * time.Second)
		if err := p.Process(ctx, failure); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`ALTER TABLE alerts ADD CONSTRAINT test_reject_temporal CHECK (rule_id <> 'xdr:bruteforce-success') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`ALTER TABLE alerts DROP CONSTRAINT IF EXISTS test_reject_temporal`)
	failure.ID = uuid.New()
	failure.Timestamp = now.Add(-5 * time.Second)
	if err := p.Process(ctx, failure); err == nil {
		t.Fatal("告警失败必须回滚事务")
	}
	var matches int
	if err := db.QueryRow(`SELECT count(*) FROM temporal_matches`).Scan(&matches); err != nil || matches != 0 {
		t.Fatalf("命中占位未回滚: %d %v", matches, err)
	}
	var exists bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM events WHERE id=$1)`, failure.ID).Scan(&exists); err != nil || exists {
		t.Fatalf("失败事件未回滚: %v %v", exists, err)
	}
	if _, err := db.Exec(`ALTER TABLE alerts DROP CONSTRAINT test_reject_temporal`); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(ctx, failure); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Alert.Query().Count(ctx); err != nil || n != 1 {
		t.Fatalf("恢复后应能重试生成告警: %d %v", n, err)
	}
}

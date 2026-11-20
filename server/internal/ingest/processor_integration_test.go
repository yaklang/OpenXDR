//go:build integration

package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
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
	"openxdr/server/internal/temporal"
)

var (
	migratedMu        sync.Mutex
	migratedDSN       string
	loadRepoRulesOnce = sync.OnceValues(func() (*temporal.Store, error) {
		root := filepath.Join("..", "..", "..")
		store := &temporal.Store{}
		if err := store.Reload(filepath.Join(root, "rules"), filepath.Join(root, "temporal-rules")); err != nil {
			return nil, err
		}
		return store, nil
	})
)

// repoTemporalStore 只读加载一次仓库全量规则快照，避免重放子用例重复编译上千条规则。
func repoTemporalStore(t *testing.T) *temporal.Store {
	t.Helper()
	store, err := loadRepoRulesOnce()
	if err != nil {
		t.Fatal(err)
	}
	return store
}

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
	migratedMu.Lock()
	needMigrate := migratedDSN != dsn
	if needMigrate {
		if err := eventpart.Migrate(ctx, client, db); err != nil {
			migratedMu.Unlock()
			t.Fatal(err)
		}
		if err := EnsureSchema(ctx, db); err != nil {
			migratedMu.Unlock()
			t.Fatal(err)
		}
		// 首次建库清表用 TRUNCATE CASCADE 清掉其他包遗留的外键记录；后续子用例改用 DELETE 避免每次重建上百个分区/索引文件。
		if _, err := db.Exec(`TRUNCATE assetmap_queue, alert_dedup_state, alerts, events, assets, temporal_matches, lateral_evidence, temporal_candidates,
			temporal_evaluation_gaps, temporal_detections, identity_observations, identity_local_snapshots, auth_events, auth_attempt_closures CASCADE`); err != nil {
			migratedMu.Unlock()
			t.Fatal(err)
		}
		migratedDSN = dsn
	}
	migratedMu.Unlock()
	if !needMigrate {
		if _, err := eventpart.EnsureDays(ctx, db, eventpart.Parent, eventpart.Today(), eventpart.PremakeDays); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{
			"assetmap_queue", "alert_dedup_state", "temporal_matches", "lateral_evidence",
			"temporal_candidates", "temporal_evaluation_gaps", "temporal_detections",
			"identity_observations", "identity_local_snapshots", "auth_attempt_closures", "auth_events",
			"alerts", "events", "commands", "suppressions", "process_baselines", "assets",
		} {
			if _, err := db.ExecContext(ctx, `DELETE FROM `+table); err != nil {
				t.Fatalf("清空 %s: %v", table, err)
			}
		}
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

// 研判之后同指纹并进来的命中要记成新证据，否则事件既不重研判、也进不了良性结案
func TestDedupHitAfterTriageMarksEvidence(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	dir := t.TempDir()
	rule := `title: Test
id: 22222222-2222-4222-8222-222222222222
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
	now := time.Now()
	base := Envelope{Version: EnvelopeVersion, PartitionKey: "asset-a", ClassUID: 1007, Source: "agent", AssetOS: "linux", Raw: json.RawMessage(`{"process":{"cmd_line":"evil-marker"}}`)}
	send := func(n string, ts time.Time) {
		e := base
		e.ID = StableID(t.Name(), n)
		e.Timestamp = ts
		if err := p.Process(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	send("1", now.Add(-10*time.Minute))
	a, err := client.Alert.Query().Only(ctx)
	if err != nil {
		t.Fatal(err)
	}
	triaged := now.Add(-5 * time.Minute)
	inc, err := client.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetStatus("triaged").SetTriagedAt(triaged).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`UPDATE alerts SET incident_id=NULL WHERE incident_id=$1`, inc.ID)
		_, _ = db.Exec(`DELETE FROM incidents WHERE id=$1`, inc.ID)
	})
	if err := client.Alert.UpdateOne(a).SetIncidentID(inc.ID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	send("2", now.Add(-7*time.Minute))
	if got := client.Incident.GetX(ctx, inc.ID); got.EvidenceAt != nil {
		t.Fatalf("研判前的命中不算新证据，evidence_at=%v", got.EvidenceAt)
	}
	send("3", now)
	got := client.Incident.GetX(ctx, inc.ID)
	if got.EvidenceAt == nil || !got.EvidenceAt.After(triaged) {
		t.Fatalf("研判后的命中应刷新 evidence_at，实际 %v", got.EvidenceAt)
	}
	if n := client.Alert.GetX(ctx, a.ID).Count; n != 3 {
		t.Fatalf("三次命中应合并成 count=3，实际 %d", n)
	}
	// 首次研判进行中（还是 open）并进来的命中也要记：落库的 triaged_at 是开始时刻，研判没看过它
	started := time.Now()
	client.Incident.UpdateOneID(inc.ID).SetStatus("open").ClearTriagedAt().SetTriageStartedAt(started).SetEvidenceAt(started.Add(-time.Minute)).ExecX(ctx)
	send("4", now.Add(time.Second))
	if got := client.Incident.GetX(ctx, inc.ID); got.EvidenceAt == nil || got.EvidenceAt.Before(started) {
		t.Fatalf("首次研判期间的命中应刷新 evidence_at，实际 %v", got.EvidenceAt)
	}
}

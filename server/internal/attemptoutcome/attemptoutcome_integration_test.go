//go:build integration

package attemptoutcome_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/integrationevent"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/api"
	"openxdr/server/internal/attemptoutcome"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/authentik"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/temporal"
	"openxdr/server/internal/testdb"
)

func openTestDB(t *testing.T) (context.Context, *ent.Client, *sql.DB) {
	t.Helper()
	ctx, client := testdb.New(t)
	sqlDB, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	if err := ingest.EnsureSchema(ctx, sqlDB); err != nil {
		t.Fatal(err)
	}
	if err := temporal.EnsureSchema(ctx, sqlDB); err != nil {
		t.Fatal(err)
	}
	cleanTemporal := func(c context.Context) {
		_, _ = sqlDB.ExecContext(c, `DELETE FROM temporal_evidence; DELETE FROM temporal_detections; DELETE FROM temporal_rule_snapshots;`)
	}
	cleanTemporal(ctx)
	resetEventPartitions(t, ctx, sqlDB)
	t.Cleanup(func() {
		cleanTemporal(context.Background())
		resetEventPartitions(t, context.Background(), sqlDB)
	})
	return ctx, client, sqlDB
}

func resetEventPartitions(t *testing.T, ctx context.Context, sqlDB *sql.DB) {
	t.Helper()
	rows, err := sqlDB.QueryContext(ctx, `SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
 WHERE i.inhparent = 'events'::regclass AND c.relname <> 'events_default'`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		names = append(names, name)
	}
	rows.Close()
	for _, name := range names {
		if _, err := sqlDB.ExecContext(ctx, `DROP TABLE `+name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := eventpart.EnsureDays(ctx, sqlDB, eventpart.Parent, eventpart.Today(), eventpart.PremakeDays); err != nil {
		t.Fatal(err)
	}
}

func setAuthentikPolledAt(t *testing.T, ctx context.Context, sqlDB *sql.DB, at time.Time) {
	t.Helper()
	b, _ := json.Marshal(at.UTC())
	if _, err := sqlDB.ExecContext(ctx,
		`INSERT INTO settings (id, value, updated_at) VALUES ($1, $2::jsonb, now())
		 ON CONFLICT (id) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		authentik.PolledAtKey, string(b),
	); err != nil {
		t.Fatal(err)
	}
}

func insertAuthEvent(t *testing.T, ctx context.Context, client *ent.Client, assetID uuid.UUID, ts time.Time, classUID int, source, user string, raw map[string]any) *ent.Event {
	t.Helper()
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := client.Event.Create().
		SetAssetID(assetID).
		SetTs(ts).
		SetClassUID(classUID).
		SetSource(source).
		SetRaw(b)
	if user != "" {
		q.SetUsername(user)
	}
	return q.SaveX(ctx)
}

func TestExternalAuthFailuresQuietCloseAuditAPIAndHardeningFinding(t *testing.T) {
	ctx, db, sqlDB := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	grp := db.Group.Create().SetName("prod-gateway").SaveX(ctx)
	gw := db.Asset.Create().
		SetHostname("gateway").
		SetOs("linux").
		SetGroupID(grp.ID).
		SetLastSeen(now).
		SaveX(ctx)

	base := now.Add(-7 * time.Hour)
	var anchorEv1, anchorEv2 *ent.Event
	// 地址 1：4 次猜解 akadmin
	for i := 0; i < 4; i++ {
		ev := insertAuthEvent(t, ctx, db, gw.ID, base.Add(time.Duration(i)*time.Minute), 3002, "authentik", "akadmin", map[string]any{
			"activity_id":  1,
			"status_id":    2,
			"status":       "Failure",
			"user":         map[string]any{"name": "akadmin"},
			"service":      map[string]any{"name": "authentik"},
			"src_endpoint": map[string]any{"ip": "203.0.113.50"},
			"metadata":     map[string]any{"product": map[string]any{"name": "Authentik"}},
		})
		if i == 0 {
			anchorEv1 = ev
		}
	}
	// 地址 2：2 次猜解 akadmin / admin
	lastFail := base.Add(15 * time.Minute)
	for i, acct := range []string{"akadmin", "admin"} {
		ts := base.Add(time.Duration(14+i) * time.Minute)
		ev := insertAuthEvent(t, ctx, db, gw.ID, ts, 3002, "authentik", acct, map[string]any{
			"activity_id":  1,
			"status_id":    2,
			"status":       "Failure",
			"user":         map[string]any{"name": acct},
			"service":      map[string]any{"name": "authentik"},
			"src_endpoint": map[string]any{"ip": "198.51.100.61"},
			"metadata":     map[string]any{"product": map[string]any{"name": "Authentik"}},
		})
		if i == 0 {
			anchorEv2 = ev
		}
	}

	inc := db.Incident.Create().
		SetStatus("open").
		SetTitle("Failed Interactive Login").
		SetCreatedAt(base).
		SetGraph(json.RawMessage(`{"nodes":[]}`)).
		SaveX(ctx)
	t1End := base.Add(3 * time.Minute)
	db.Alert.Create().
		SetIncidentID(inc.ID).
		SetAssetID(gw.ID).
		SetEventID(anchorEv1.ID).
		SetTs(base).
		SetLastTs(t1End).
		SetCount(4).
		SetSeverity(2).
		SetRuleID(attemptoutcome.RuleLinuxLoginFailure).
		SaveX(ctx)
	db.Alert.Create().
		SetIncidentID(inc.ID).
		SetAssetID(gw.ID).
		SetEventID(anchorEv2.ID).
		SetTs(base.Add(14 * time.Minute)).
		SetLastTs(lastFail).
		SetCount(2).
		SetSeverity(2).
		SetRuleID(attemptoutcome.RuleLinuxLoginFailure).
		SaveX(ctx)

	closer := &attemptoutcome.Closer{
		DB:                   db,
		SQL:                  sqlDB,
		QuietWindow:          6 * time.Hour,
		MinHardeningFailures: 5,
		MinHardeningSources:  2,
	}

	// 1) 距末次失败仅 2 小时：不应提前结案，但加固建议 Finding 应已生成
	earlyNow := lastFail.Add(2 * time.Hour)
	setAuthentikPolledAt(t, ctx, sqlDB, earlyNow)
	stats, err := closer.Sweep(ctx, earlyNow)
	if err != nil {
		t.Fatalf("首次 Sweep 失败: %v", err)
	}
	if stats.Closed != 0 {
		t.Fatalf("静默期未满不应结案: %+v", stats)
	}
	if db.Incident.GetX(ctx, inc.ID).Status != "open" {
		t.Fatal("事件状态应仍为 open")
	}
	if stats.Findings != 1 {
		t.Fatalf("应生成 1 条加固建议待办: %+v", stats)
	}

	fKey := attemptoutcome.HardeningKey("authentik")
	fRow := db.Finding.Query().Where(finding.GroupIDEQ(grp.ID), finding.AssetIDEQ(gw.ID), finding.KeyEQ(fKey)).OnlyX(ctx)
	if fRow.Status != "open" || fRow.WorkOwner != "human" {
		t.Fatalf("加固建议状态或归属不符: status=%s owner=%s", fRow.Status, fRow.WorkOwner)
	}
	if !strings.Contains(fRow.Title, "gateway") || !strings.Contains(fRow.Title, "Authentik") || !strings.Contains(fRow.Title, "2 个") || !strings.Contains(fRow.Title, "6 次") || !strings.Contains(fRow.Title, "akadmin") {
		t.Fatalf("加固建议标题未包含主机/服务/规模/主目标账号: %q", fRow.Title)
	}

	// 2) 满 6 小时静默窗口：应自动按 closed（绝非 false_positive）+ attempt_verified 结案
	setAuthentikPolledAt(t, ctx, sqlDB, now)
	stats, err = closer.Sweep(ctx, now)
	if err != nil {
		t.Fatalf("静默期满后 Sweep 失败: %v", err)
	}
	if stats.Closed != 1 {
		t.Fatalf("应自动结案 1 起事件: %+v", stats)
	}

	closedInc := db.Incident.GetX(ctx, inc.ID)
	if closedInc.Status != "closed" {
		t.Fatalf("未得手攻击尝试必须按 closed 结案（防止喂给误报统计），实际: %s", closedInc.Status)
	}
	if closedInc.ResolutionSource == nil || *closedInc.ResolutionSource != attemptoutcome.ResolutionSource {
		t.Fatalf("resolution_source 不符: %v", closedInc.ResolutionSource)
	}
	if closedInc.ResolvedBy == nil || *closedInc.ResolvedBy != "system" {
		t.Fatalf("resolved_by 不符: %v", closedInc.ResolvedBy)
	}
	if closedInc.Resolution == nil ||
		!strings.Contains(*closedInc.Resolution, "203.0.113.50") ||
		!strings.Contains(*closedInc.Resolution, "198.51.100.61") ||
		!strings.Contains(*closedInc.Resolution, "Authentik") ||
		!strings.Contains(*closedInc.Resolution, "akadmin") {
		t.Fatalf("结案理由缺少关键核验信息: %v", closedInc.Resolution)
	}

	// 审计日志与联动事件落库验证
	if !db.AuditLog.Query().Where(
		auditlog.ActionEQ(attemptoutcome.AuditActionVerified),
		auditlog.UsernameEQ(attemptoutcome.Actor),
		auditlog.TargetEQ(inc.ID.String()),
	).ExistX(ctx) {
		t.Fatal("缺少认证未得手自动结案审计日志")
	}
	ie := db.IntegrationEvent.Query().Where(integrationevent.IncidentIDEQ(inc.ID)).OnlyX(ctx)
	var ieDoc struct {
		Origin struct {
			Kind string `json:"kind"`
			ID   string `json:"id"`
		} `json:"origin"`
	}
	if err := json.Unmarshal(ie.Payload, &ieDoc); err != nil || ieDoc.Origin.Kind != attemptoutcome.ResolutionSource || ieDoc.Origin.ID != attemptoutcome.Actor {
		t.Fatalf("联动事件 payload 未记录 attempt_verified 来源: %s (err=%v)", string(ie.Payload), err)
	}

	// REST API 列表与详情均返回 resolutionSource="attempt_verified"
	admin := db.User.Create().SetUsername("admin").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	handler := api.Handler(db, sqlDB, &sigma.Engine{}, nil, nil, nil, nil)
	for _, path := range []string{"/api/incidents/" + inc.ID.String(), "/api/incidents?status=closed"} {
		req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(auth.WithUser(ctx, admin))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s 状态码=%d body=%s", path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"resolutionSource":"attempt_verified"`) {
			t.Fatalf("GET %s 未返回 resolutionSource: %s", path, rec.Body.String())
		}
	}

	// 3) 第三个外部公网地址继续猜解同一服务：必须原地更新同一条 Finding（不另开新条）
	wave2Ts := now.Add(10 * time.Minute)
	var wave2Anchor *ent.Event
	for i := 0; i < 3; i++ {
		ev := insertAuthEvent(t, ctx, db, gw.ID, wave2Ts.Add(time.Duration(i)*time.Second), 3002, "authentik", "akadmin", map[string]any{
			"activity_id":  1,
			"status_id":    2,
			"status":       "Failure",
			"user":         map[string]any{"name": "akadmin"},
			"service":      map[string]any{"name": "authentik"},
			"src_endpoint": map[string]any{"ip": "192.0.2.88"},
			"metadata":     map[string]any{"product": map[string]any{"name": "Authentik"}},
		})
		if i == 0 {
			wave2Anchor = ev
		}
	}
	inc2 := db.Incident.Create().SetStatus("open").SetCreatedAt(wave2Ts).SetGraph(json.RawMessage(`{"nodes":[]}`)).SaveX(ctx)
	db.Alert.Create().
		SetIncidentID(inc2.ID).
		SetAssetID(gw.ID).
		SetEventID(wave2Anchor.ID).
		SetTs(wave2Ts).
		SetCount(3).
		SetSeverity(2).
		SetRuleID(attemptoutcome.RuleLinuxLoginFailure).
		SaveX(ctx)

	setAuthentikPolledAt(t, ctx, sqlDB, wave2Ts.Add(time.Minute))
	if _, err := closer.Sweep(ctx, wave2Ts.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	allFindings := db.Finding.Query().Where(finding.GroupIDEQ(grp.ID), finding.AssetIDEQ(gw.ID)).AllX(ctx)
	if len(allFindings) != 1 || allFindings[0].ID != fRow.ID {
		t.Fatalf("同一服务只应保留并更新同一条加固建议，实际条数=%d", len(allFindings))
	}
	if !strings.Contains(allFindings[0].Title, "3 个") || !strings.Contains(allFindings[0].Title, "9 次") {
		t.Fatalf("加固建议未累计更新最新规模: %q", allFindings[0].Title)
	}

	// 4) 人工将该加固建议标为 ignored：后续再有新公网猜解也绝不重开或改写
	ignoredTitle := "人工已知悉并忽略"
	db.Finding.UpdateOneID(fRow.ID).SetStatus("ignored").SetTitle(ignoredTitle).ExecX(ctx)
	wave3Ts := wave2Ts.Add(5 * time.Minute)
	insertAuthEvent(t, ctx, db, gw.ID, wave3Ts, 3002, "authentik", "akadmin", map[string]any{
		"activity_id":  1,
		"status_id":    2,
		"status":       "Failure",
		"user":         map[string]any{"name": "akadmin"},
		"service":      map[string]any{"name": "authentik"},
		"src_endpoint": map[string]any{"ip": "192.0.2.99"},
		"metadata":     map[string]any{"product": map[string]any{"name": "Authentik"}},
	})
	setAuthentikPolledAt(t, ctx, sqlDB, wave3Ts.Add(time.Minute))
	if _, err := closer.Sweep(ctx, wave3Ts.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	afterIgnore := db.Finding.GetX(ctx, fRow.ID)
	if afterIgnore.Status != "ignored" || afterIgnore.Title != ignoredTitle {
		t.Fatalf("人工标为 ignored 的待办绝不应被重开或覆盖: %+v", afterIgnore)
	}
}

func TestSameSourceSuccessBlocksAutoCloseAndSilentLoginReopensClosedIncident(t *testing.T) {
	ctx, db, sqlDB := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	grp := db.Group.Create().SetName("dmz-ssh").SaveX(ctx)
	bastion := db.Asset.Create().
		SetHostname("bastion-01").
		SetOs("linux").
		SetAgentID(uuid.New()).
		SetGroupID(grp.ID).
		SetLastSeen(now).
		SaveX(ctx)

	// 场景 A：失败后 20 分钟内同来源在 syslog sshd 成功认证 → OutcomeSucceeded，满 8 小时也绝不自动结案
	failTsA := now.Add(-8 * time.Hour)
	evFailA := insertAuthEvent(t, ctx, db, bastion.ID, failTsA, 100001, "syslog", "ubuntu", map[string]any{
		"metadata": map[string]any{"product": map[string]any{"name": "sshd"}},
		"message":  "Failed password for ubuntu from 203.0.113.70 port 50111 ssh2",
	})
	insertAuthEvent(t, ctx, db, bastion.ID, failTsA.Add(20*time.Minute), 100001, "syslog", "ubuntu", map[string]any{
		"metadata": map[string]any{"product": map[string]any{"name": "sshd"}},
		"message":  "Accepted publickey for ubuntu from 203.0.113.70 port 50123 ssh2: ED25519 SHA256:xyz",
	})
	incA := db.Incident.Create().SetStatus("open").SetCreatedAt(failTsA).SetGraph(json.RawMessage(`{"nodes":[]}`)).SaveX(ctx)
	db.Alert.Create().
		SetIncidentID(incA.ID).
		SetAssetID(bastion.ID).
		SetEventID(evFailA.ID).
		SetTs(failTsA).
		SetCount(5).
		SetSeverity(2).
		SetRuleID(attemptoutcome.RuleSSHAuthFailure).
		SaveX(ctx)

	vA, err := attemptoutcome.Verify(ctx, db, sqlDB, incA.ID, attemptoutcome.Options{Now: now, QuietWindow: 6 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if vA.Outcome != attemptoutcome.OutcomeSucceeded || vA.ReadyToClose() || len(vA.Successes) == 0 {
		t.Fatalf("存在同源成功认证必须判为 OutcomeSucceeded 且禁止结案: %+v", vA)
	}

	// 场景 B：时序爆破告警（temporal_evidence 含第二个来源 IP 198.51.100.71）先满 6h 自动结案，随后 198.51.100.71 静默成功登录（无新告警）→ 自动重开
	failTsB := now.Add(-7 * time.Hour)
	evFailB1 := insertAuthEvent(t, ctx, db, bastion.ID, failTsB, 3002, "agent", "root", map[string]any{
		"activity_id":  1,
		"status_id":    2,
		"user":         map[string]any{"name": "root"},
		"service":      map[string]any{"name": "sshd"},
		"src_endpoint": map[string]any{"ip": "198.51.100.71"},
	})
	evFailB2 := insertAuthEvent(t, ctx, db, bastion.ID, failTsB.Add(time.Minute), 3002, "agent", "admin", map[string]any{
		"activity_id":  1,
		"status_id":    2,
		"user":         map[string]any{"name": "admin"},
		"service":      map[string]any{"name": "sshd"},
		"src_endpoint": map[string]any{"ip": "198.51.100.72"},
	})
	incB := db.Incident.Create().SetStatus("open").SetCreatedAt(failTsB).SetGraph(json.RawMessage(`{"nodes":[]}`)).SaveX(ctx)
	burstAlert := db.Alert.Create().
		SetIncidentID(incB.ID).
		SetAssetID(bastion.ID).
		SetEventID(evFailB2.ID).
		SetTs(failTsB.Add(time.Minute)).
		SetCount(10).
		SetSeverity(3).
		SetRuleID(attemptoutcome.RuleTemporalLinuxAuthBurst).
		SaveX(ctx)
	const rev = "rev-attempt-test"
	if _, err := sqlDB.ExecContext(ctx,
		`INSERT INTO temporal_rule_snapshots (revision, document) VALUES ($1, '{}'::jsonb) ON CONFLICT (revision) DO NOTHING`,
		rev,
	); err != nil {
		t.Fatalf("写入 temporal_rule_snapshots 失败: %v", err)
	}
	if _, err := sqlDB.ExecContext(ctx,
		`INSERT INTO temporal_detections (revision, rule_id, anchor_id, group_id, entity, evidence, alert_id)
		 VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`,
		rev,
		attemptoutcome.RuleTemporalLinuxAuthBurst,
		evFailB2.ID,
		grp.ID,
		bastion.ID.String(),
		`["`+evFailB1.ID.String()+`","`+evFailB2.ID.String()+`"]`,
		burstAlert.ID,
	); err != nil {
		t.Fatalf("写入 temporal_detections 失败: %v", err)
	}
	for _, eid := range []uuid.UUID{evFailB1.ID, evFailB2.ID} {
		if _, err := sqlDB.ExecContext(ctx,
			`INSERT INTO temporal_evidence (revision, rule_id, anchor_id, event_id) VALUES ($1, $2, $3, $4)`,
			rev, attemptoutcome.RuleTemporalLinuxAuthBurst, evFailB2.ID, eid,
		); err != nil {
			t.Fatalf("写入 temporal_evidence 失败: %v", err)
		}
	}

	closer := &attemptoutcome.Closer{DB: db, SQL: sqlDB, QuietWindow: 6 * time.Hour}
	stats, err := closer.Sweep(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Closed != 1 {
		t.Fatalf("应仅结案 incB 1 起（incA 有成功不得结案），实际: %+v", stats)
	}
	if db.Incident.GetX(ctx, incA.ID).Status != "open" {
		t.Fatal("incA 有成功认证，绝不应被结案")
	}
	if db.Incident.GetX(ctx, incB.ID).Status != "closed" {
		t.Fatal("incB 应已按 attempt_verified 结案")
	}

	// 结案 10 分钟后，198.51.100.71 静默成功登录（只产生 3002 成功事件，不产生任何新 Alert）
	laterNow := now.Add(10 * time.Minute)
	db.Asset.UpdateOneID(bastion.ID).SetLastSeen(laterNow).ExecX(ctx)
	insertAuthEvent(t, ctx, db, bastion.ID, now.Add(5*time.Minute), 3002, "agent", "root", map[string]any{
		"activity_id":  1,
		"status_id":    1,
		"user":         map[string]any{"name": "root"},
		"service":      map[string]any{"name": "sshd"},
		"src_endpoint": map[string]any{"ip": "198.51.100.71"},
	})

	stats2, err := closer.Sweep(ctx, laterNow)
	if err != nil {
		t.Fatal(err)
	}
	if stats2.Reopened != 1 {
		t.Fatalf("同来源静默成功登录必须自动重开已结案事件: %+v", stats2)
	}
	reopenedB := db.Incident.GetX(ctx, incB.ID)
	if reopenedB.Status != "open" || reopenedB.ResolutionSource != nil || reopenedB.ResolvedAt != nil || reopenedB.UrgentAt == nil {
		t.Fatalf("重开后的事件状态或字段清理不完整: %+v", reopenedB)
	}
	if !db.AuditLog.Query().Where(
		auditlog.ActionEQ(attemptoutcome.AuditActionReopened),
		auditlog.TargetEQ(incB.ID.String()),
	).ExistX(ctx) {
		t.Fatal("缺少静默成功登录触发的结案重开审计日志")
	}

	// 场景 C：关联引擎待归并同来源新告警（ReopenForPendingAlerts）在同一事务内当场重开已结案事件
	resolvedAtC := now.Add(-time.Hour)
	evFailC := insertAuthEvent(t, ctx, db, bastion.ID, now.Add(-8*time.Hour), 3002, "agent", "deploy", map[string]any{
		"activity_id":  1,
		"status_id":    2,
		"user":         map[string]any{"name": "deploy"},
		"service":      map[string]any{"name": "sshd"},
		"src_endpoint": map[string]any{"ip": "203.0.113.77"},
	})
	incC := db.Incident.Create().
		SetStatus("closed").
		SetResolutionSource(attemptoutcome.ResolutionSource).
		SetResolvedBy("system").
		SetResolvedAt(resolvedAtC).
		SetResolution("verified").
		SetCreatedAt(now.Add(-8 * time.Hour)).
		SetGraph(json.RawMessage(`{"nodes":[]}`)).
		SaveX(ctx)
	db.Alert.Create().
		SetIncidentID(incC.ID).
		SetAssetID(bastion.ID).
		SetEventID(evFailC.ID).
		SetTs(now.Add(-8 * time.Hour)).
		SetCount(3).
		SetSeverity(2).
		SetRuleID(attemptoutcome.RuleLinuxLoginFailure).
		SaveX(ctx)

	newEvC := insertAuthEvent(t, ctx, db, bastion.ID, now, 4001, "agent", "", map[string]any{
		"connection_info": map[string]any{"direction": "inbound"},
		"src_endpoint":    map[string]any{"ip": "203.0.113.77", "port": 41111},
	})
	pendingAlert := db.Alert.Create().
		SetAssetID(bastion.ID).
		SetEventID(newEvC.ID).
		SetTs(now).
		SetCount(1).
		SetSeverity(4).
		SetRuleID("intel:ip:203.0.113.77").
		SaveX(ctx)
	pendingLoaded := db.Alert.Query().Where().WithAsset().WithEvent().AllX(ctx)
	var onlyPending []*ent.Alert
	for _, a := range pendingLoaded {
		if a.ID == pendingAlert.ID {
			onlyPending = append(onlyPending, a)
		}
	}

	tx, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := attemptoutcome.ReopenForPendingAlerts(ctx, tx, onlyPending, now); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if db.Incident.GetX(ctx, incC.ID).Status != "open" {
		t.Fatal("同来源新告警进入关联队列时应立即重开原 attempt_verified 事件")
	}
}

func TestInternalAndRegisteredChannelSourcesNeverAutoClose(t *testing.T) {
	ctx, db, sqlDB := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	grp := db.Group.Create().SetName("corp-internal").SaveX(ctx)
	host := db.Asset.Create().
		SetHostname("app-01").
		SetOs("linux").
		SetAgentID(uuid.New()).
		SetGroupID(grp.ID).
		SetLastSeen(now).
		SaveX(ctx)

	// 登记一条合法公网管理通道事实
	db.Fact.Create().
		SetGroupID(grp.ID).
		SetKind("channel").
		SetSubject("203.0.113.120/32").
		SetContent("合作方运维固定出口 IP").
		SetSource("human").
		SetCreatedBy("admin").
		SaveX(ctx)

	oldTs := now.Add(-8 * time.Hour)
	// 1. 私网来源 10.1.1.55
	evPriv := insertAuthEvent(t, ctx, db, host.ID, oldTs, 3002, "agent", "root", map[string]any{
		"activity_id":  1,
		"status_id":    2,
		"user":         map[string]any{"name": "root"},
		"service":      map[string]any{"name": "sshd"},
		"src_endpoint": map[string]any{"ip": "10.1.1.55"},
	})
	incPriv := db.Incident.Create().SetStatus("open").SetCreatedAt(oldTs).SetGraph(json.RawMessage(`{"nodes":[]}`)).SaveX(ctx)
	db.Alert.Create().SetIncidentID(incPriv.ID).SetAssetID(host.ID).SetEventID(evPriv.ID).SetTs(oldTs).SetCount(8).SetSeverity(2).SetRuleID(attemptoutcome.RuleLinuxLoginFailure).SaveX(ctx)

	// 2. 已登记通道公网来源 203.0.113.120
	evChan := insertAuthEvent(t, ctx, db, host.ID, oldTs.Add(time.Minute), 3002, "agent", "ops", map[string]any{
		"activity_id":  1,
		"status_id":    2,
		"user":         map[string]any{"name": "ops"},
		"service":      map[string]any{"name": "sshd"},
		"src_endpoint": map[string]any{"ip": "203.0.113.120"},
	})
	incChan := db.Incident.Create().SetStatus("open").SetCreatedAt(oldTs).SetGraph(json.RawMessage(`{"nodes":[]}`)).SaveX(ctx)
	db.Alert.Create().SetIncidentID(incChan.ID).SetAssetID(host.ID).SetEventID(evChan.ID).SetTs(oldTs.Add(time.Minute)).SetCount(8).SetSeverity(2).SetRuleID(attemptoutcome.RuleLinuxLoginFailure).SaveX(ctx)

	for _, id := range []uuid.UUID{incPriv.ID, incChan.ID} {
		v, err := attemptoutcome.Verify(ctx, db, sqlDB, id, attemptoutcome.Options{Now: now, QuietWindow: 6 * time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		if v.Outcome != attemptoutcome.OutcomeInternalOrRegistered || v.ReadyToClose() {
			t.Fatalf("内网或已登记通道来源绝不应判为可自动结案: %+v", v)
		}
	}

	closer := &attemptoutcome.Closer{DB: db, SQL: sqlDB, QuietWindow: 6 * time.Hour, MinHardeningFailures: 2, MinHardeningSources: 1}
	stats, err := closer.Sweep(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Closed != 0 || stats.Findings != 0 {
		t.Fatalf("内网与已登记通道来源既不自动结案也不计入外部公网加固待办: %+v", stats)
	}
}

func TestCollectionIncompletenessAndRetiredPartitionNeverAutoClose(t *testing.T) {
	ctx, db, sqlDB := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	oldTs := now.Add(-8 * time.Hour)
	grp := db.Group.Create().SetName("incomplete-check").SaveX(ctx)

	// 1. Agent 标记了认证采集组件 unavailable
	degradedHost := db.Asset.Create().
		SetHostname("win-dc-01").
		SetOs("windows").
		SetAgentID(uuid.New()).
		SetGroupID(grp.ID).
		SetLastSeen(now).
		SetCollectorHealth(json.RawMessage(`{"receivedAt":"` + now.UTC().Format(time.RFC3339) + `","capabilities":{"auth":{"state":"unavailable","detail":"access denied"}}}`)).
		SaveX(ctx)
	evDeg := insertAuthEvent(t, ctx, db, degradedHost.ID, oldTs, 3002, "agent", "Administrator", map[string]any{
		"activity_id":  1,
		"event_id":     4625,
		"status_id":    2,
		"log_name":     "Security",
		"user":         map[string]any{"name": "Administrator"},
		"service":      map[string]any{"name": "logon-type-10"},
		"src_endpoint": map[string]any{"ip": "203.0.113.81"},
	})
	incDeg := db.Incident.Create().SetStatus("open").SetCreatedAt(oldTs).SetGraph(json.RawMessage(`{"nodes":[]}`)).SaveX(ctx)
	db.Alert.Create().SetIncidentID(incDeg.ID).SetAssetID(degradedHost.ID).SetEventID(evDeg.ID).SetTs(oldTs).SetCount(6).SetSeverity(2).SetRuleID(attemptoutcome.RuleWinLoginFailure).SaveX(ctx)

	vDeg, err := attemptoutcome.Verify(ctx, db, sqlDB, incDeg.ID, attemptoutcome.Options{Now: now, QuietWindow: 6 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if vDeg.Outcome != attemptoutcome.OutcomeIncomplete || vDeg.ReadyToClose() {
		t.Fatalf("认证采集降级必须判为 OutcomeIncomplete: %+v", vDeg)
	}

	// 2. 缺少来源 IP
	okHost := db.Asset.Create().
		SetHostname("lnx-01").
		SetOs("linux").
		SetAgentID(uuid.New()).
		SetGroupID(grp.ID).
		SetLastSeen(now).
		SaveX(ctx)
	evNoIP := insertAuthEvent(t, ctx, db, okHost.ID, oldTs, 3002, "agent", "root", map[string]any{
		"activity_id": 1,
		"status_id":   2,
		"user":        map[string]any{"name": "root"},
		"service":     map[string]any{"name": "login"},
	})
	incNoIP := db.Incident.Create().SetStatus("open").SetCreatedAt(oldTs).SetGraph(json.RawMessage(`{"nodes":[]}`)).SaveX(ctx)
	db.Alert.Create().SetIncidentID(incNoIP.ID).SetAssetID(okHost.ID).SetEventID(evNoIP.ID).SetTs(oldTs).SetCount(3).SetSeverity(2).SetRuleID(attemptoutcome.RuleLinuxLoginFailure).SaveX(ctx)

	vNoIP, err := attemptoutcome.Verify(ctx, db, sqlDB, incNoIP.ID, attemptoutcome.Options{Now: now, QuietWindow: 6 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if vNoIP.Outcome != attemptoutcome.OutcomeIncomplete || vNoIP.ReadyToClose() {
		t.Fatalf("缺少来源 IP 必须判为 OutcomeIncomplete: %+v", vNoIP)
	}

	// 3. Authentik 轮询心跳过期（采集可能中断）
	setAuthentikPolledAt(t, ctx, sqlDB, now.Add(-2*time.Hour))
	evAk := insertAuthEvent(t, ctx, db, okHost.ID, oldTs, 3002, "authentik", "akadmin", map[string]any{
		"activity_id":  1,
		"status_id":    2,
		"user":         map[string]any{"name": "akadmin"},
		"service":      map[string]any{"name": "authentik"},
		"src_endpoint": map[string]any{"ip": "203.0.113.82"},
		"metadata":     map[string]any{"product": map[string]any{"name": "Authentik"}},
	})
	incAk := db.Incident.Create().SetStatus("open").SetCreatedAt(oldTs).SetGraph(json.RawMessage(`{"nodes":[]}`)).SaveX(ctx)
	db.Alert.Create().SetIncidentID(incAk.ID).SetAssetID(okHost.ID).SetEventID(evAk.ID).SetTs(oldTs).SetCount(3).SetSeverity(2).SetRuleID(attemptoutcome.RuleLinuxLoginFailure).SaveX(ctx)

	vAk, err := attemptoutcome.Verify(ctx, db, sqlDB, incAk.ID, attemptoutcome.Options{Now: now, QuietWindow: 6 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if vAk.Outcome != attemptoutcome.OutcomeIncomplete || vAk.ReadyToClose() {
		t.Fatalf("Authentik 轮询心跳过期必须判为 OutcomeIncomplete: %+v", vAk)
	}

	// 4. 历史日分区已退役（存在归档分区 events_aYYYYMM 且核验起点早于最老日分区）
	pastDay := eventpart.Today().AddDate(0, 0, -5)
	if _, err := eventpart.EnsureDays(ctx, sqlDB, eventpart.Parent, pastDay, 1); err != nil {
		t.Fatal(err)
	}
	retiredFailTs := pastDay.Add(3 * time.Hour)
	evRet := insertAuthEvent(t, ctx, db, okHost.ID, retiredFailTs, 3002, "agent", "root", map[string]any{
		"activity_id":  1,
		"status_id":    2,
		"user":         map[string]any{"name": "root"},
		"service":      map[string]any{"name": "sshd"},
		"src_endpoint": map[string]any{"ip": "203.0.113.83"},
	})
	incRet := db.Incident.Create().SetStatus("open").SetCreatedAt(retiredFailTs).SetGraph(json.RawMessage(`{"nodes":[]}`)).SaveX(ctx)
	db.Alert.Create().SetIncidentID(incRet.ID).SetAssetID(okHost.ID).SetEventID(evRet.ID).SetTs(retiredFailTs).SetCount(3).SetSeverity(2).SetRuleID(attemptoutcome.RuleLinuxLoginFailure).SaveX(ctx)

	if _, _, err := eventpart.Retire(ctx, sqlDB, eventpart.Today()); err != nil {
		t.Fatal(err)
	}
	vRet, err := attemptoutcome.Verify(ctx, db, sqlDB, incRet.ID, attemptoutcome.Options{Now: now, QuietWindow: 6 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if vRet.Outcome != attemptoutcome.OutcomeIncomplete || vRet.ReadyToClose() {
		t.Fatalf("核验起点所在日分区已退役时严禁按阴性结果自动结案: %+v", vRet)
	}
}

func TestManualHoldNonAuthRuleAndSameSourceOtherAlertNeverAutoClose(t *testing.T) {
	ctx, db, sqlDB := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	oldTs := now.Add(-8 * time.Hour)

	grp := db.Group.Create().SetName("guardrails").SaveX(ctx)
	host := db.Asset.Create().
		SetHostname("edge-01").
		SetOs("linux").
		SetAgentID(uuid.New()).
		SetGroupID(grp.ID).
		SetLastSeen(now).
		SaveX(ctx)

	// 1. 人工锁定（ManualLock = true）：即使确定性核验满足未得手，Closer 也绝不越权自动结案
	evHold := insertAuthEvent(t, ctx, db, host.ID, oldTs, 3002, "agent", "root", map[string]any{
		"activity_id":  1,
		"status_id":    2,
		"user":         map[string]any{"name": "root"},
		"service":      map[string]any{"name": "sshd"},
		"src_endpoint": map[string]any{"ip": "203.0.113.91"},
	})
	incHold := db.Incident.Create().
		SetStatus("open").
		SetCreatedAt(oldTs).
		SetGraph(json.RawMessage(`{"nodes":[]}`)).
		SetWork(&schema.IncidentWork{Owner: "human", Stage: "investigating", ManualLock: true, ManualOwner: "zachary"}).
		SaveX(ctx)
	db.Alert.Create().SetIncidentID(incHold.ID).SetAssetID(host.ID).SetEventID(evHold.ID).SetTs(oldTs).SetCount(4).SetSeverity(2).SetRuleID(attemptoutcome.RuleLinuxLoginFailure).SaveX(ctx)

	// 2. 事件内混有情报命中告警（非认证失败族）
	evMix := insertAuthEvent(t, ctx, db, host.ID, oldTs, 3002, "agent", "root", map[string]any{
		"activity_id":  1,
		"status_id":    2,
		"user":         map[string]any{"name": "root"},
		"service":      map[string]any{"name": "sshd"},
		"src_endpoint": map[string]any{"ip": "203.0.113.92"},
	})
	incMix := db.Incident.Create().SetStatus("open").SetCreatedAt(oldTs).SetGraph(json.RawMessage(`{"nodes":[]}`)).SaveX(ctx)
	db.Alert.Create().SetIncidentID(incMix.ID).SetAssetID(host.ID).SetEventID(evMix.ID).SetTs(oldTs).SetCount(3).SetSeverity(2).SetRuleID(attemptoutcome.RuleLinuxLoginFailure).SaveX(ctx)
	db.Alert.Create().SetIncidentID(incMix.ID).SetAssetID(host.ID).SetEventID(evMix.ID).SetTs(oldTs).SetCount(1).SetSeverity(4).SetRuleID("intel:ip:203.0.113.92").SaveX(ctx)

	// 3. 事件自身虽只有认证失败告警，但同来源 IP 在窗口内触发了另一条非认证失败告警
	evOtherFail := insertAuthEvent(t, ctx, db, host.ID, oldTs, 3002, "agent", "root", map[string]any{
		"activity_id":  1,
		"status_id":    2,
		"user":         map[string]any{"name": "root"},
		"service":      map[string]any{"name": "sshd"},
		"src_endpoint": map[string]any{"ip": "203.0.113.93"},
	})
	incOther := db.Incident.Create().SetStatus("open").SetCreatedAt(oldTs).SetGraph(json.RawMessage(`{"nodes":[]}`)).SaveX(ctx)
	db.Alert.Create().SetIncidentID(incOther.ID).SetAssetID(host.ID).SetEventID(evOtherFail.ID).SetTs(oldTs).SetCount(3).SetSeverity(2).SetRuleID(attemptoutcome.RuleLinuxLoginFailure).SaveX(ctx)

	evIntel := insertAuthEvent(t, ctx, db, host.ID, oldTs.Add(5*time.Minute), 4001, "agent", "", map[string]any{
		"connection_info": map[string]any{"direction": "inbound"},
		"src_endpoint":    map[string]any{"ip": "203.0.113.93", "port": 55555},
	})
	db.Alert.Create().SetAssetID(host.ID).SetEventID(evIntel.ID).SetTs(oldTs.Add(5 * time.Minute)).SetCount(1).SetSeverity(4).SetRuleID("intel:ip:203.0.113.93").SaveX(ctx)

	vOther, err := attemptoutcome.Verify(ctx, db, sqlDB, incOther.ID, attemptoutcome.Options{Now: now, QuietWindow: 6 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if vOther.Outcome != attemptoutcome.OutcomeOtherAlerts || vOther.ReadyToClose() {
		t.Fatalf("同来源存在其他规则命中时必须判为 OutcomeOtherAlerts: %+v", vOther)
	}

	closer := &attemptoutcome.Closer{DB: db, SQL: sqlDB, QuietWindow: 6 * time.Hour}
	stats, err := closer.Sweep(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Closed != 0 {
		t.Fatalf("人工锁定、含非本族告警、同来源有其他告警的三起事件均不应自动结案: %+v", stats)
	}
	for _, id := range []uuid.UUID{incHold.ID, incMix.ID, incOther.ID} {
		if db.Incident.GetX(ctx, id).Status != "open" {
			t.Fatalf("事件 %s 不应被自动结案", id)
		}
	}
}

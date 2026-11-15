//go:build integration

package triage

import (
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/attemptoutcome"
	"openxdr/server/internal/authevents"
	"openxdr/server/internal/testdb"
)

func TestBuildContextIncludesAttemptOutcomeVerification(t *testing.T) {
	ctx, db := testdb.New(t)
	sqlDB, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqlDB.Close() })

	now := time.Now().UTC().Truncate(time.Second)
	if err := authevents.EnsureRecordedSince(ctx, sqlDB, now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	grp := db.Group.Create().SetName("triage-attempt").SaveX(ctx)
	host := db.Asset.Create().
		SetHostname("bastion-triage").
		SetOs("linux").
		SetAgentID(uuid.New()).
		SetGroupID(grp.ID).
		SetLastSeen(now).
		SaveX(ctx)

	// 1. 外部来源先失败后成功：buildContext 必须把成功认证证据注入研判提示词
	failTs := now.Add(-30 * time.Minute)
	failRaw := json.RawMessage(`{"activity_id":1,"status_id":2,"user":{"name":"ubuntu"},"service":{"name":"sshd"},"src_endpoint":{"ip":"203.0.113.144"}}`)
	evFail := db.Event.Create().
		SetAssetID(host.ID).
		SetTs(failTs).
		SetClassUID(3002).
		SetSource("agent").
		SetUsername("ubuntu").
		SetRaw(failRaw).
		SaveX(ctx)
	if err := authevents.Record(ctx, sqlDB, evFail.ID, host.ID, failTs, 3002, "agent", "linux", "ubuntu", failRaw); err != nil {
		t.Fatal(err)
	}
	succTs := failTs.Add(3 * time.Minute)
	succRaw := json.RawMessage(`{"activity_id":1,"status_id":1,"user":{"name":"ubuntu"},"service":{"name":"sshd"},"src_endpoint":{"ip":"203.0.113.144"}}`)
	evSucc := db.Event.Create().
		SetAssetID(host.ID).
		SetTs(succTs).
		SetClassUID(3002).
		SetSource("agent").
		SetUsername("ubuntu").
		SetRaw(succRaw).
		SaveX(ctx)
	if err := authevents.Record(ctx, sqlDB, evSucc.ID, host.ID, succTs, 3002, "agent", "linux", "ubuntu", succRaw); err != nil {
		t.Fatal(err)
	}

	incSucc := db.Incident.Create().SetStatus("open").SetCreatedAt(failTs).SetGraph(json.RawMessage(`{"nodes":[]}`)).SaveX(ctx)
	db.Alert.Create().
		SetIncidentID(incSucc.ID).
		SetAssetID(host.ID).
		SetEventID(evFail.ID).
		SetTs(failTs).
		SetCount(6).
		SetSeverity(2).
		SetRuleID(attemptoutcome.RuleLinuxLoginFailure).
		SaveX(ctx)

	eng := &Engine{DB: db, SQL: sqlDB}
	ctxText, err := eng.buildContext(ctx, incSucc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ctxText, "认证尝试确定性核验结果") || !strings.Contains(ctxText, "发现成功认证记录") || !strings.Contains(ctxText, "203.0.113.144") {
		t.Fatalf("buildContext 未注入同源成功认证核验结果:\n%s", ctxText)
	}

	// 2. 内网来源认证失败：buildContext 必须注入内网来源归属说明
	privRaw := json.RawMessage(`{"activity_id":1,"status_id":2,"user":{"name":"deploy"},"service":{"name":"sshd"},"src_endpoint":{"ip":"10.1.1.88"}}`)
	evPriv := db.Event.Create().
		SetAssetID(host.ID).
		SetTs(failTs).
		SetClassUID(3002).
		SetSource("agent").
		SetUsername("deploy").
		SetRaw(privRaw).
		SaveX(ctx)
	if err := authevents.Record(ctx, sqlDB, evPriv.ID, host.ID, failTs, 3002, "agent", "linux", "deploy", privRaw); err != nil {
		t.Fatal(err)
	}
	incPriv := db.Incident.Create().SetStatus("open").SetCreatedAt(failTs).SetGraph(json.RawMessage(`{"nodes":[]}`)).SaveX(ctx)
	db.Alert.Create().
		SetIncidentID(incPriv.ID).
		SetAssetID(host.ID).
		SetEventID(evPriv.ID).
		SetTs(failTs).
		SetCount(4).
		SetSeverity(2).
		SetRuleID(attemptoutcome.RuleLinuxLoginFailure).
		SaveX(ctx)

	ctxPriv, err := eng.buildContext(ctx, incPriv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ctxPriv, "包含内网、纳管主机或已登记通道") || !strings.Contains(ctxPriv, "10.1.1.88") || strings.Contains(ctxPriv, "203.0.113.144") {
		t.Fatalf("buildContext 内网认证失败核验说明不符或串入同机无关事件:\n%s", ctxPriv)
	}
}

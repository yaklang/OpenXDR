//go:build integration

package api

import (
	"encoding/json"
	"testing"
	"time"

	"openxdr/server/internal/testdb"
)

// checkSubjects 对 incident 的组校验与 scope.go 一致：跨组事件（即便首条告警在本组）和含无归属告警的事件均拒绝。
func TestCheckSubjectsRejectsCrossGroupIncidents(t *testing.T) {
	ctx, db := testdb.New(t)
	gA := db.Group.Create().SetName("group-a").SaveX(ctx)
	gB := db.Group.Create().SetName("group-b").SaveX(ctx)
	hostA := db.Asset.Create().SetHostname("a1").SetGroupID(gA.ID).SaveX(ctx)
	hostB := db.Asset.Create().SetHostname("b1").SetGroupID(gB.ID).SaveX(ctx)

	base := time.Now().Add(-time.Hour)

	// 1. 纯本组事件：应放行（重复传入同一个 subject 也应正常处理）
	pureInc := db.Incident.Create().SetStatus("triaged").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	db.Alert.Create().SetTs(base).SetRuleID("r1").SetSeverity(3).SetAssetID(hostA.ID).SetIncidentID(pureInc.ID).SaveX(ctx)
	if err := checkSubjects(ctx, db, gA.ID, []string{"incident:" + pureInc.ID.String(), "incident:" + pureInc.ID.String()}); err != nil {
		t.Fatalf("纯本组事件应放行：%v", err)
	}

	// 2. 跨组事件：最早告警在组 A，后续告警在组 B，必须拒绝
	crossInc := db.Incident.Create().SetStatus("triaged").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	db.Alert.Create().SetTs(base).SetRuleID("r1").SetSeverity(3).SetAssetID(hostA.ID).SetIncidentID(crossInc.ID).SaveX(ctx)
	db.Alert.Create().SetTs(base.Add(time.Minute)).SetRuleID("r2").SetSeverity(4).SetAssetID(hostB.ID).SetIncidentID(crossInc.ID).SaveX(ctx)
	if err := checkSubjects(ctx, db, gA.ID, []string{"incident:" + crossInc.ID.String()}); err == nil {
		t.Fatal("跨组事件（首条在组 A、次条在组 B）必须拒绝")
	}

	// 3. 含无归属资产告警的事件：必须拒绝
	unownedInc := db.Incident.Create().SetStatus("triaged").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	db.Alert.Create().SetTs(base).SetRuleID("r1").SetSeverity(3).SetAssetID(hostA.ID).SetIncidentID(unownedInc.ID).SaveX(ctx)
	db.Alert.Create().SetTs(base.Add(time.Minute)).SetRuleID("r2").SetSeverity(3).SetIncidentID(unownedInc.ID).SaveX(ctx)
	if err := checkSubjects(ctx, db, gA.ID, []string{"incident:" + unownedInc.ID.String()}); err == nil {
		t.Fatal("含无归属资产告警的事件必须拒绝")
	}

	// 4. 空事件（无任何告警）：必须拒绝
	emptyInc := db.Incident.Create().SetStatus("open").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	if err := checkSubjects(ctx, db, gA.ID, []string{"incident:" + emptyInc.ID.String()}); err == nil {
		t.Fatal("无告警事件必须拒绝")
	}
}

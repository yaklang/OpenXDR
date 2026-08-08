//go:build integration

package grpcsvc

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

func authEvent(agentID, user string, statusID int) *pb.AgentEvent {
	return &pb.AgentEvent{
		AgentId:  agentID,
		ClassUid: classAuth,
		TsUnixNs: time.Now().UnixNano(),
		Username: user,
		RawJson: fmt.Sprintf(
			`{"activity_id":1,"status_id":%d,"user":{"name":"%s"},"src_endpoint":{"ip":"10.0.0.99"}}`,
			statusID, user),
	}
}

func newAuthServer(t *testing.T, client *ent.Client) *Server {
	t.Helper()
	return &Server{
		DB: client, Rules: loadMimikatzRule(t), DedupWindow: time.Hour,
		Suppress: suppress.New(client, time.Hour), Intel: intel.New(client, time.Hour),
	}
}

// 阈值内的失败后登录成功 → 升级为 critical 爆破得手告警。
func TestBruteforceSuccessEscalation(t *testing.T) {
	ctx, client := testdb.New(t)

	agentGUID := uuid.New()
	if _, err := client.Asset.Create().
		SetHostname("victim-1").SetOs("linux").SetAgentID(agentGUID).Save(ctx); err != nil {
		t.Fatal(err)
	}

	var events []*pb.AgentEvent
	for i := 0; i < bruteforceThreshold; i++ {
		events = append(events, authEvent(agentGUID.String(), "root", authStatusFailure))
	}
	events = append(events, authEvent(agentGUID.String(), "root", authStatusSuccess))

	s := newAuthServer(t, client)
	if err := s.ReportEvents(&fakeAgentStream{ctx: ctx, events: events}); err != nil {
		t.Fatalf("ReportEvents 失败: %v", err)
	}

	alerts, err := client.Alert.Query().All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].RuleID != sigma.RuleBruteforceSuccess {
		t.Fatalf("应产出 1 条爆破得手告警，实际 %+v", alerts)
	}
	if alerts[0].Severity != 5 {
		t.Errorf("爆破得手应为 critical(5)，实际 %d", alerts[0].Severity)
	}
	if alerts[0].AssetID == nil {
		t.Error("告警应归属资产")
	}
}

// 失败次数不足阈值时，登录成功不产生告警。
func TestBruteforceBelowThreshold(t *testing.T) {
	ctx, client := testdb.New(t)

	agentGUID := uuid.New()
	if _, err := client.Asset.Create().
		SetHostname("victim-2").SetOs("linux").SetAgentID(agentGUID).Save(ctx); err != nil {
		t.Fatal(err)
	}

	events := []*pb.AgentEvent{
		authEvent(agentGUID.String(), "alice", authStatusFailure),
		authEvent(agentGUID.String(), "alice", authStatusFailure),
		authEvent(agentGUID.String(), "alice", authStatusSuccess),
	}

	s := newAuthServer(t, client)
	if err := s.ReportEvents(&fakeAgentStream{ctx: ctx, events: events}); err != nil {
		t.Fatalf("ReportEvents 失败: %v", err)
	}

	if n, err := client.Alert.Query().Count(ctx); err != nil || n != 0 {
		t.Errorf("失败未达阈值不应告警，实际 %d 条 (err=%v)", n, err)
	}
}

// 别人爆破 root，bob 正常登录成功——用户维度必须隔离，不能误伤。
func TestBruteforceUserIsolation(t *testing.T) {
	ctx, client := testdb.New(t)

	agentGUID := uuid.New()
	if _, err := client.Asset.Create().
		SetHostname("victim-3").SetOs("linux").SetAgentID(agentGUID).Save(ctx); err != nil {
		t.Fatal(err)
	}

	var events []*pb.AgentEvent
	for i := 0; i < bruteforceThreshold; i++ {
		events = append(events, authEvent(agentGUID.String(), "root", authStatusFailure))
	}
	events = append(events, authEvent(agentGUID.String(), "bob", authStatusSuccess))

	s := newAuthServer(t, client)
	if err := s.ReportEvents(&fakeAgentStream{ctx: ctx, events: events}); err != nil {
		t.Fatalf("ReportEvents 失败: %v", err)
	}

	if n, err := client.Alert.Query().Count(ctx); err != nil || n != 0 {
		t.Errorf("bob 的成功登录不应被 root 的失败连坐，实际 %d 条告警 (err=%v)", n, err)
	}
}

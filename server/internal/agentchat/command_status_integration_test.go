//go:build integration

package agentchat

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/response"
	"openxdr/server/internal/testdb"
	"strings"
	"testing"
	"time"
)

func TestCommandStatusIsScopedAndDoesNotRetry(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("status").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	host := db.Asset.Create().SetHostname("status-host").SetGroupID(group.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator("analyst").SetModel("test").SaveX(ctx)
	s := &Service{DB: db}
	for _, status := range []string{"pending", "sent", "unknown", "succeeded", "failed", "unsupported"} {
		cmd := db.Command.Create().SetAssetID(host.ID).SetKind("exec").SetStatus(status).SetStdout(strings.Repeat("x", 20000)).SaveX(ctx)
		out, err := s.tool(ctx, session, commandgate.Request{}, "command_status", []byte(`{"command":"`+cmd.ID.String()+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			Status, Effect, Retry string
			Truncated             bool
			Stdout                string
		}
		if err := json.Unmarshal([]byte(out), &result); err != nil || result.Status != status || result.Effect != "not_assessed_by_this_tool" || result.Retry != "not_authorized_by_this_tool" || !result.Truncated || len(result.Stdout) >= 20000 {
			t.Fatalf("回执错误: %v", err)
		}
		if db.Command.GetX(ctx, cmd.ID).Status != status {
			t.Fatal("查询改变状态")
		}
		db.Asset.UpdateOneID(host.ID).SetGroupID(other.ID).ExecX(ctx)
		if _, err := s.commandStatus(ctx, session, []byte(`{"command":"`+cmd.ID.String()+`"}`)); err == nil {
			t.Fatal("换组后泄漏回执")
		}
		db.Asset.UpdateOneID(host.ID).SetGroupID(group.ID).ExecX(ctx)
	}
	if db.Command.Query().CountX(ctx) != 6 {
		t.Fatal("查询产生了新指令")
	}
	for _, args := range []string{`{}`, `{"command":"bad"}`, `{"command":"` + uuid.NewString() + `","group":"other"}`, `{} {}`} {
		if _, err := s.commandStatus(ctx, session, []byte(args)); err == nil {
			t.Fatal("坏参数被接受")
		}
	}
}

func TestCommandReadFailureKeepsIdentity(t *testing.T) {
	ctx, db := testdb.New(t)
	id := uuid.New()
	// 指令查询失败不等于动作失败，不返回可误判的成功结果或丢失指令 ID。
	out, err := (&Service{DB: db}).waitCommand(ctx, &ent.Command{ID: id, Status: "sent"}, 1)
	if err == nil || out != "" || !strings.Contains(err.Error(), id.String()) || !strings.Contains(err.Error(), "command_status") || !strings.Contains(err.Error(), "禁止自动重试") {
		t.Fatalf("读取失败语义错误: %q %v", out, err)
	}
}

func TestVerifyCommandToolDerivesSessionIdentityAndMarksSideEffect(t *testing.T) {
	ctx, db := testdb.New(t)
	s := &Service{DB: db}
	sqlDB, closeFn, err := s.verificationSQL()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	if err := response.EnsureVerificationSchema(ctx, sqlDB); err != nil {
		t.Fatal(err)
	}

	g := db.Group.Create().SetName("verify-tool").SaveX(ctx)
	host := db.Asset.Create().SetHostname("verify-host").SetGroupID(g.ID).SaveX(ctx)
	issued := time.Now().UTC().Add(-5 * time.Minute)
	procGUID := uuid.New()
	cmd := db.Command.Create().SetAssetID(host.ID).SetKind("kill_process").SetStatus("succeeded").
		SetPid(888).SetProcessGUID(procGUID).SetCreatedAt(issued).SetCompletedAt(issued.Add(time.Second)).SaveX(ctx)
	exitEv := db.Event.Create().SetAssetID(host.ID).SetTs(issued.Add(time.Minute)).SetSource("agent").SetClassUID(1007).
		SetProcessGUID(procGUID).SetRaw(json.RawMessage(`{"activity_id":2,"process":{"pid":888}}`)).SaveX(ctx)

	session := db.AgentSession.Create().SetKind("task").SetGroupID(g.ID).SetInitiator(commandgate.SystemActor).SetModel("m").SaveX(ctx)
	runCtx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	work, _, stop, err := s.startTaskLease(runCtx, session)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	payload, _ := json.Marshal(map[string]any{
		"command":   cmd.ID,
		"outcome":   "effective",
		"method":    "telemetry_post_action",
		"expected":  "目标进程被终止",
		"observed":  "收到同 process_guid 与 PID 的退出事件",
		"event_ids": []uuid.UUID{exitEv.ID},
	})
	out, err := s.tool(work, session, commandgate.Request{}, "verify_command", payload)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"source":"ai"`) || !strings.Contains(out, `"ai:session:`+session.ID.String()+`"`) {
		t.Fatalf("未按服务端会话派生身份: %s", out)
	}
	if db.AgentSession.GetX(ctx, session.ID).RunReplaySafe {
		t.Fatal("写入效果验证属于副作用，应将 RunReplaySafe 置为 false")
	}
}

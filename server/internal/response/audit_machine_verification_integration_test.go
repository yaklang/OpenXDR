//go:build integration

package response

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/testdb"
)

func TestAuditMachineEffectRequiresTypedTargetEvidence(t *testing.T) {
	cases := []string{"target_exit", "pid_substring", "guid_in_note", "parent_only", "file_mentions_target", "syslog_exit", "missing_process_identity", "network_mentions_ip", "network_mentions_ip_ineffective", "host_unrelated_event", "exec_unrelated_event", "unknown_effective", "unknown_ineffective", "before_issue"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			ctx, c := testdb.New(t)
			sq, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sq.Close() })
			if err := EnsureVerificationSchema(ctx, sq); err != nil {
				t.Fatal(err)
			}
			g := c.Group.Create().SetName("effect-audit").SaveX(ctx)
			a := c.Asset.Create().SetGroupID(g.ID).SetHostname("effect-host").SaveX(ctx)
			session := c.AgentSession.Create().SetKind("chat").SetGroupID(g.ID).SetInitiator("analyst").SetModel("m").SaveX(ctx)
			issued := time.Now().Add(-10 * time.Minute)
			guid, foreign := uuid.New(), uuid.New()
			cmd := c.Command.Create().SetAssetID(a.ID).SetKind("kill_process").SetStatus("succeeded").SetPid(42).SetProcessGUID(guid).SetCreatedAt(issued)
			eventGUID, pid, class, source, ts := guid, 42, 1007, "agent", issued.Add(2*time.Minute)
			raw := map[string]any{"activity_id": 2, "process": map[string]any{"pid": 42, "uid": guid.String()}}
			outcome := "effective"
			switch name {
			case "pid_substring":
				eventGUID, pid = foreign, 142
			case "guid_in_note":
				eventGUID, pid = foreign, 142
				raw["note"] = guid.String()
			case "parent_only":
				eventGUID, pid = foreign, 142
				raw["parent_process"] = map[string]any{"pid": 42, "uid": guid.String()}
			case "file_mentions_target":
				class = 4003
				raw = map[string]any{"file": map[string]string{"path": "/tmp/42-" + guid.String()}}
			case "syslog_exit":
				source = "syslog"
			case "missing_process_identity":
				eventGUID = uuid.Nil
				raw["process"] = map[string]any{"pid": 42}
			case "network_mentions_ip", "network_mentions_ip_ineffective":
				cmd.SetKind("block_network").SetTarget("192.0.2.42")
				class = 4001
				raw = map[string]any{"message": "lookup 192.0.2.42"}
				if name == "network_mentions_ip_ineffective" {
					outcome = "ineffective"
				}
			case "host_unrelated_event":
				cmd.SetKind("isolate_host")
				class = 4003
				raw = map[string]any{"file": "/tmp/unrelated"}
			case "exec_unrelated_event":
				cmd.SetKind("exec").SetCmd("echo observation")
				class = 4003
				raw = map[string]any{"file": "/tmp/unrelated"}
			case "unknown_effective":
				cmd.SetStatus("unknown")
			case "unknown_ineffective":
				cmd.SetStatus("unknown")
				outcome = "ineffective"
			case "before_issue":
				ts = issued.Add(-time.Minute)
			}
			if name == "pid_substring" || name == "guid_in_note" || name == "parent_only" {
				raw["process"] = map[string]any{"pid": pid, "uid": foreign.String()}
			}
			if !strings.HasPrefix(name, "unknown_") {
				cmd.SetCompletedAt(issued.Add(time.Minute))
			}
			command := cmd.SaveX(ctx)
			body, _ := json.Marshal(raw)
			eb := c.Event.Create().SetAssetID(a.ID).SetClassUID(class).SetSource(source).SetTs(ts).SetRaw(body)
			if eventGUID != uuid.Nil {
				eb.SetProcessGUID(eventGUID)
			}
			if name == "parent_only" {
				eb.SetParentProcessGUID(guid)
			}
			event := eb.SaveX(ctx)
			in := MachineVerificationInput{CommandID: command.ID, GroupID: g.ID, Source: "ai", Method: "telemetry_post_action", SessionID: &session.ID, Outcome: outcome, Expected: "目标动作已证实", Observed: "审计测试", EventIDs: []uuid.UUID{event.ID}}
			v, err := RecordMachineVerification(ctx, sq, in)
			if name == "target_exit" {
				if err != nil || v == nil || v.Outcome != "effective" || v.Source != "ai" || !strings.HasPrefix(v.Reviewer, "ai:session:") {
					t.Fatalf("确定性退出正控被拒绝: %+v %v", v, err)
				}
			} else if err == nil {
				t.Fatalf("无关/不可信/未确认事件被当成%s证据: %s", outcome, name)
			}
			if c.Command.GetX(ctx, command.ID).Status != command.Status || c.Command.Query().CountX(ctx) != 1 {
				t.Fatal("验证改写了回执或重放了命令")
			}
		})
	}
}

func TestAuditMachineVerificationIdentityAndContext(t *testing.T) {
	ctx, c := testdb.New(t)
	sq, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sq.Close() })
	if err := EnsureVerificationSchema(ctx, sq); err != nil {
		t.Fatal(err)
	}
	g := c.Group.Create().SetName("identity-audit").SaveX(ctx)
	other := c.Group.Create().SetName("other").SaveX(ctx)
	a := c.Asset.Create().SetGroupID(g.ID).SetHostname("h").SaveX(ctx)
	session := c.AgentSession.Create().SetKind("chat").SetGroupID(g.ID).SetInitiator("viewer").SetModel("m").SaveX(ctx)
	issued := time.Now().Add(-time.Minute)
	command := c.Command.Create().SetAssetID(a.ID).SetKind("kill_process").SetStatus("unknown").SetCreatedAt(issued).SaveX(ctx)
	before := c.Event.Create().SetAssetID(a.ID).SetClassUID(1007).SetSource("agent").SetTs(issued.Add(-time.Second)).SetRaw(json.RawMessage(`{"activity_id":2,"process":{"pid":42}}`)).SaveX(ctx)
	base := MachineVerificationInput{CommandID: command.ID, GroupID: g.ID, Source: "ai", Method: "context_only", SessionID: &session.ID, Outcome: "inconclusive", Expected: "核实动作效果", Observed: "目标下发前已退出，未证明执行器导致退出", ContextEventIDs: []uuid.UUID{before.ID}}
	v, err := RecordMachineVerification(ctx, sq, base)
	if err != nil || v == nil || v.Outcome != "inconclusive" || len(v.Context) != 1 || len(v.Evidence) != 0 || v.Reviewer != "ai:session:"+session.ID.String() {
		t.Fatalf("上下文与机器身份错误: %+v %v", v, err)
	}
	for _, mode := range []string{"human", "missing_session", "other_group", "expired", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			in := base
			switch mode {
			case "human":
				in.Source = "human"
			case "missing_session":
				id := uuid.New()
				in.SessionID = &id
			case "other_group":
				in.GroupID = other.ID
			case "expired":
				c.AgentSession.UpdateOneID(session.ID).SetRunExpiresAt(time.Now().Add(-time.Second)).ExecX(ctx)
			case "cancelled":
				c.AgentSession.UpdateOneID(session.ID).SetCancelRequestedAt(time.Now()).ExecX(ctx)
			}
			if _, err := RecordMachineVerification(ctx, sq, in); err == nil {
				t.Fatalf("接受伪造/失效来源: %s", mode)
			}
		})
	}
	admin := c.User.Create().SetUsername("read-machine").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	list, err := ListVerifications(ctx, sq, admin.ID, command.ID)
	if err != nil || len(list) != 1 || list[0].Source != "ai" || list[0].SessionID == nil || list[0].Method != "context_only" {
		t.Fatalf("读取丢失来源边界: %+v %v", list, err)
	}
	detail, err := GetVerification(ctx, sq, admin.ID, command.ID, v.ID)
	if err != nil || len(detail.Context) != 1 || detail.Context[0].ID != before.ID {
		t.Fatalf("读取丢失前置上下文: %+v %v", detail, err)
	}
	var count int
	if err := sq.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE target=$1 AND username=$2 AND action='command_verification_recorded'`, command.ID.String(), fmt.Sprintf("ai:session:%s", session.ID)).Scan(&count); err != nil || count != 1 {
		t.Fatal("机器验证未留审计", err, count)
	}
}

func TestAuditAutoVerificationCoverageConvergesWithoutReplay(t *testing.T) {
	ctx, c := testdb.New(t)
	sq, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sq.Close() })
	if err := EnsureVerificationSchema(ctx, sq); err != nil {
		t.Fatal(err)
	}
	g := c.Group.Create().SetName("coverage-audit").SaveX(ctx)
	a := c.Asset.Create().SetGroupID(g.ID).SetHostname("coverage-host").SaveX(ctx)
	now := time.Now().UTC()
	var kills [][2]uuid.UUID
	for i := range 101 {
		q := c.Command.Create().SetAssetID(a.ID).SetKind("block_network").SetTarget("192.0.2.42").SetStatus("succeeded").SetCreatedAt(now.Add(-2*time.Hour + time.Duration(i)*time.Second)).SetCompletedAt(now.Add(-time.Hour))
		if i == 0 || i == 100 {
			guid := uuid.New()
			q.SetKind("kill_process").SetPid(42).SetProcessGUID(guid)
			cmd := q.SaveX(ctx)
			kills = append(kills, [2]uuid.UUID{cmd.ID, guid})
		} else {
			q.SaveX(ctx)
		}
	}
	check := func(want int) {
		t.Helper()
		var n int
		if err := sq.QueryRowContext(ctx, `SELECT count(DISTINCT command_id) FROM command_verifications WHERE source='system'`).Scan(&n); err != nil || n != want {
			t.Fatalf("自动核验覆盖=%d want=%d err=%v", n, want, err)
		}
	}
	for range 3 {
		if err := AutoVerifyCommands(ctx, sq, now); err != nil {
			t.Fatal(err)
		}
	}
	check(101)
	var before int
	if err := sq.QueryRowContext(ctx, `SELECT count(*) FROM command_verifications WHERE source='system'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := AutoVerifyCommands(ctx, sq, now); err != nil {
		t.Fatal(err)
	}
	var after int
	if err := sq.QueryRowContext(ctx, `SELECT count(*) FROM command_verifications WHERE source='system'`).Scan(&after); err != nil || after != before {
		t.Fatalf("相同证据反复追加: before=%d after=%d err=%v", before, after, err)
	}
	for _, pair := range kills {
		raw, _ := json.Marshal(map[string]any{"activity_id": 2, "process": map[string]any{"pid": 42, "uid": pair[1].String()}})
		c.Event.Create().SetAssetID(a.ID).SetClassUID(1007).SetSource("agent").SetTs(now.Add(-time.Minute)).SetProcessGUID(pair[1]).SetRaw(raw).SaveX(ctx)
	}
	for range 3 {
		if err := AutoVerifyCommands(ctx, sq, now); err != nil {
			t.Fatal(err)
		}
	}
	var effective int
	if err := sq.QueryRowContext(ctx, `SELECT count(DISTINCT command_id) FROM command_verifications WHERE source='system' AND outcome='effective'`).Scan(&effective); err != nil || effective != 2 {
		t.Fatalf("延迟退出证据未覆盖最早与最新指令: %d %v", effective, err)
	}
	if c.Command.Query().CountX(ctx) != 101 {
		t.Fatal("自动核验重放了处置指令")
	}
}

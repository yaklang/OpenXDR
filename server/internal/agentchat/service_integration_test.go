//go:build integration

package agentchat

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/sessionmessage"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/piruntime"
	"openxdr/server/internal/testdb"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	run func(context.Context, piruntime.Request, piruntime.Handler, piruntime.Observer) (*piruntime.Result, error)
}

func (f fakeRunner) Run(ctx context.Context, r piruntime.Request, h piruntime.Handler, o piruntime.Observer) (*piruntime.Result, error) {
	return f.run(ctx, r, h, o)
}

type titles map[string]string

func (t titles) TitleOf(id string) string { return t[id] }

// 规则名只给本组近期命中过的，其他组的规则不漏进提示。
func TestRequestRuleTitles(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	mine := db.Asset.Create().SetHostname("h").SetGroupID(group.ID).SaveX(ctx)
	theirs := db.Asset.Create().SetHostname("x").SetGroupID(other.ID).SaveX(ctx)
	now := time.Now()
	db.Alert.Create().SetTs(now).SetRuleID("r-mine").SetSeverity(3).SetAssetID(mine.ID).SaveX(ctx)
	db.Alert.Create().SetTs(now.Add(-30 * 24 * time.Hour)).SetLastTs(now.Add(-30 * 24 * time.Hour)).SetRuleID("r-old").SetSeverity(3).SetAssetID(mine.ID).SaveX(ctx)
	db.Alert.Create().SetTs(now).SetRuleID("r-theirs").SetSeverity(3).SetAssetID(theirs.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator("a").SetModel("test").SetStatus("idle").SetTitle("").SaveX(ctx)
	service := &Service{DB: db, Rules: titles{"r-mine": "本组规则", "r-old": "过期规则", "r-theirs": "他组规则"}}
	service.FallbackModels = func() string { return "backup-a,backup-b" }
	r, err := service.request(ctx, session, "检查", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.FallbackModels != "backup-a,backup-b" {
		t.Fatal("本机请求丢失备用配置")
	}
	service.Sandboxed = true
	sandbox, err := service.request(ctx, session, "检查", nil)
	if err != nil || sandbox.FallbackModels != r.FallbackModels {
		t.Fatalf("沙箱请求丢失备用配置: %v", err)
	}
	service.Sandboxed = false
	if !strings.Contains(r.SystemPrompt, `"r-mine":"本组规则"`) || strings.Contains(r.SystemPrompt, "过期规则") || strings.Contains(r.SystemPrompt, "他组规则") {
		t.Fatalf("规则名范围不对：%s", r.SystemPrompt)
	}
}

func TestSessionHistoryAndReports(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	user := db.User.Create().SetUsername("a").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator(user.Username).SetModel("test").SetStatus("idle").SetTitle("").SaveX(ctx)
	db.Asset.Create().SetHostname("本组主机").SetGroupID(group.ID).SaveX(ctx)
	otherGroup := db.Group.Create().SetName("other").SaveX(ctx)
	db.Asset.Create().SetHostname("其他组秘密主机").SetGroupID(otherGroup.ID).SaveX(ctx)
	calls := 0
	service := &Service{DB: db}
	service.Runtime = fakeRunner{func(ctx context.Context, r piruntime.Request, h piruntime.Handler, o piruntime.Observer) (*piruntime.Result, error) {
		calls++
		if !strings.Contains(r.SystemPrompt, "本组主机") || strings.Contains(r.SystemPrompt, "其他组秘密主机") {
			t.Fatal("资产上下文越界或缺失")
		}
		if len(r.Messages) != (calls-1)*2 {
			t.Fatalf("历史丢失或重复: %d", len(r.Messages))
		}
		for _, tool := range r.Tools {
			if tool.Name == "query" {
				t.Fatal("未配置只读身份不能开放 query")
			}
		}
		for _, message := range []string{`{"role":"user","content":"检查","timestamp":1}`, `{"role":"assistant","content":[{"type":"text","text":"完成"}],"stopReason":"stop"}`} {
			event := piruntime.Event{Type: "event", Event: json.RawMessage(`{"type":"message_end","message":` + message + `}`)}
			if err := o(ctx, event); err != nil {
				return nil, err
			}
		}
		if _, err := h(ctx, "report", json.RawMessage(`{"title":"报告","summary":"正常","markdown":"## 结论\n正常\n## 需要人处理\n无\n## 未验证\n无"}`)); err != nil {
			return nil, err
		}
		return &piruntime.Result{Response: "完成", StopReason: "stop"}, nil
	}}
	for range 2 {
		if _, err := service.Chat(ctx, session.ID, user, "检查", nil); err != nil {
			t.Fatal(err)
		}
	}
	if got := db.AgentSession.GetX(ctx, session.ID); got.Status != "idle" || got.Title == nil || *got.Title != "检查" {
		t.Fatalf("状态 %s，标题应取首句提问", got.Status)
	}
	if n := db.SessionMessage.Query().CountX(ctx); n != 4 {
		t.Fatal(n)
	}
	if n := db.Report.Query().CountX(ctx); n != 2 {
		t.Fatal(n)
	}
	other := db.User.Create().SetUsername("other").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	if _, err := service.Chat(ctx, session.ID, other, "检查", nil); err == nil {
		t.Fatal("不能续写其他人的会话")
	}
}

// 对话轮数耗尽：带全部历史续一次只留 report 的收尾（不能给空工具列表，vLLM 会拒），会话正常回到 idle。
func TestChatWrapUp(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	user := db.User.Create().SetUsername("a").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator(user.Username).SetModel("test").SetStatus("idle").SetTitle("").SaveX(ctx)
	calls := 0
	service := &Service{DB: db, Runtime: fakeRunner{func(ctx context.Context, r piruntime.Request, h piruntime.Handler, o piruntime.Observer) (*piruntime.Result, error) {
		calls++
		if calls == 2 && (len(r.Tools) != 1 || r.Tools[0].Name != "report" || !strings.Contains(r.Prompt, "不要再调用工具") || r.MaxTurns != wrapUpTurns || len(r.Messages) != 2 || !strings.Contains(r.Prompt, "未验证")) {
			t.Errorf("收尾请求不符：工具 %v 轮数 %d 历史 %d", r.Tools, r.MaxTurns, len(r.Messages))
		}
		for _, message := range []string{`{"role":"user","content":"检查","timestamp":1}`, `{"role":"assistant","content":[{"type":"text","text":"小结"}],"stopReason":"stop"}`} {
			if err := o(ctx, piruntime.Event{Type: "event", Event: json.RawMessage(`{"type":"message_end","message":` + message + `}`)}); err != nil {
				return nil, err
			}
		}
		if calls == 1 {
			return &piruntime.Result{StopReason: "max_turns"}, nil
		}
		return &piruntime.Result{Response: "小结", StopReason: "stop"}, nil
	}}}
	result, err := service.Chat(ctx, session.ID, user, "检查", nil)
	if err != nil || calls != 2 || result.StopReason != "stop" {
		t.Fatalf("收尾后应正常结束：%v %+v，调用 %d 次", err, result, calls)
	}
	if got := db.AgentSession.GetX(ctx, session.ID); got.Status != "idle" || got.Error != nil {
		t.Fatalf("会话应回到 idle：%+v", got)
	}
	if n := db.SessionMessage.Query().CountX(ctx); n != 4 {
		t.Fatalf("收尾消息应入库，共 4 条，得到 %d", n)
	}
}

func TestConcurrentSessionAndFailure(t *testing.T) {
	ctx, db := testdb.New(t)
	user := db.User.Create().SetUsername("a").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator(user.Username).SetModel("test").SetStatus("idle").SetTitle("").SaveX(ctx)
	started, release := make(chan struct{}), make(chan struct{})
	service := &Service{DB: db, Runtime: fakeRunner{func(context.Context, piruntime.Request, piruntime.Handler, piruntime.Observer) (*piruntime.Result, error) {
		close(started)
		<-release
		return nil, errors.New("测试失败")
	}}}
	done := make(chan error, 1)
	go func() { _, err := service.Chat(ctx, session.ID, user, "检查", nil); done <- err }()
	<-started
	if _, err := service.Chat(ctx, session.ID, user, "重复", nil); err == nil {
		t.Fatal("必须拒绝并发续写")
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("错误丢失")
	}
	if got := db.AgentSession.GetX(ctx, session.ID); got.Status != "failed" || got.Error == nil {
		t.Fatalf("失败终态缺失: %+v", got)
	}
}
func TestSessionGroupScope(t *testing.T) {
	ctx, db := testdb.New(t)
	user := db.User.Create().SetUsername("a").SetPasswordHash("unused").SetRole("analyst").SaveX(ctx)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator(user.Username).SetModel("test").SetStatus("idle").SetTitle("").SaveX(ctx)
	service := &Service{DB: db}
	if _, err := service.Chat(ctx, session.ID, user, "检查", nil); err == nil {
		t.Fatal("非成员不得执行")
	}
	if _, err := service.tool(ctx, &ent.AgentSession{GroupID: uuid.New()}, commandgate.Request{UserID: user.ID}, "query", json.RawMessage(`{"sql":"select 1"}`)); err == nil {
		t.Fatal("无 DSN 必须拒绝")
	}
}

// 后台运行：有人点停止就收手，会话回到 idle，停在半截的工具调用补上结果，可以接着问
func TestStartAndCancel(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	user := db.User.Create().SetUsername("a").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator(user.Username).SetModel("test").SetStatus("idle").SetTitle("").SaveX(ctx)
	started := make(chan struct{})
	service := &Service{DB: db, Base: context.Background()}
	service.Runtime = fakeRunner{func(ctx context.Context, r piruntime.Request, h piruntime.Handler, o piruntime.Observer) (*piruntime.Result, error) {
		call := `{"role":"assistant","content":[{"type":"toolCall","id":"c1","name":"exec","arguments":{}}],"stopReason":"toolUse"}`
		if err := o(ctx, piruntime.Event{Type: "event", Event: json.RawMessage(`{"type":"message_end","message":` + call + `}`)}); err != nil {
			return nil, err
		}
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	if err := service.Start(ctx, session.ID, user, "检查"); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := service.Start(ctx, session.ID, user, "再来"); err == nil {
		t.Fatal("运行中不能再发")
	}
	if err := service.Cancel(ctx, session.ID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for db.AgentSession.GetX(ctx, session.ID).Status == "running" && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	got := db.AgentSession.GetX(ctx, session.ID)
	if got.Status != "idle" || got.Error != nil || got.CancelRequestedAt != nil {
		t.Fatalf("停止后应回到 idle 且无错误：%+v", got)
	}
	msgs := db.SessionMessage.Query().Order(ent.Asc(sessionmessage.FieldSeq)).AllX(ctx)
	var closed struct {
		ToolCallID string `json:"toolCallId"`
	}
	if len(msgs) == 2 {
		_ = json.Unmarshal(msgs[1].Content, &closed)
	}
	if len(msgs) != 2 || msgs[1].Role != "toolResult" || closed.ToolCallID != "c1" {
		t.Fatalf("应补齐被停止的工具调用：%d 条", len(msgs))
	}
}

// 进程退出（发版滚动重启）打断本轮：会话回到 idle 并说明原因，停在半截的工具调用补上结果，可以接着发送
func TestShutdownInterrupt(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	user := db.User.Create().SetUsername("a").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator(user.Username).SetModel("test").SetStatus("idle").SetTitle("").SaveX(ctx)
	started := make(chan struct{})
	base, shutdown := context.WithCancel(context.Background())
	service := &Service{DB: db, Base: base}
	service.Runtime = fakeRunner{func(ctx context.Context, r piruntime.Request, h piruntime.Handler, o piruntime.Observer) (*piruntime.Result, error) {
		call := `{"role":"assistant","content":[{"type":"toolCall","id":"c1","name":"exec","arguments":{}}],"stopReason":"toolUse"}`
		if err := o(ctx, piruntime.Event{Type: "event", Event: json.RawMessage(`{"type":"message_end","message":` + call + `}`)}); err != nil {
			return nil, err
		}
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	if err := service.Start(ctx, session.ID, user, "检查"); err != nil {
		t.Fatal(err)
	}
	<-started
	shutdown()
	deadline := time.Now().Add(10 * time.Second)
	for db.AgentSession.GetX(ctx, session.ID).Status == "running" && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	got := db.AgentSession.GetX(ctx, session.ID)
	if got.Status != "idle" || got.Error == nil || *got.Error != interruptedNote {
		t.Fatalf("重启打断后应回到 idle 并说明原因：%+v", got)
	}
	if n := db.SessionMessage.Query().CountX(ctx); n != 2 {
		t.Fatalf("应补齐被打断的工具调用：%d 条", n)
	}
}

//go:build integration

package triage

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/review"
	"openxdr/server/internal/testdb"
)

// stubLLM 记录每次研判请求的上下文；fail 返回 true 的请求按端点故障返回 500，hook 在应答前执行（模拟研判期间并入证据）
type stubLLM struct {
	mu       sync.Mutex
	contexts []string
	fail     func(ctx string) bool
	hook     func()
}

func (s *stubLLM) llm(t *testing.T) *LLM {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []Message `json:"messages"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		ctx := ""
		if len(req.Messages) > 1 {
			ctx = req.Messages[1].Content
		}
		s.mu.Lock()
		s.contexts = append(s.contexts, ctx)
		s.mu.Unlock()
		if s.hook != nil {
			s.hook()
		}
		if s.fail != nil && s.fail(ctx) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		resp, _ := json.Marshal(map[string]any{"choices": []map[string]any{
			{"message": map[string]any{"role": "assistant", "content": `{"verdict":"benign","confidence":80,"action_codes":["monitor"],"summary":"系统例行变更"}`}},
		}})
		w.Write(resp)
	}))
	t.Cleanup(srv.Close)
	return NewLLM(srv.URL, "m", "", 10*time.Second)
}

func (s *stubLLM) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.contexts)
}

type retriageFixture struct {
	t      *testing.T
	ctx    context.Context
	client *ent.Client
}

// triaged 一个已研判过的 incident：上次研判在 ago 之前，结论良性
func (f *retriageFixture) triaged(title string, ago time.Duration) *ent.Incident {
	f.t.Helper()
	at := time.Now().Add(-ago)
	inc := f.client.Incident.Create().SetStatus("triaged").SetTitle(title).SetGraph(json.RawMessage(`{}`)).
		SetCreatedAt(at.Add(-time.Hour)).SetAiVerdict(json.RawMessage(`{"verdict":"benign","confidence":70,"summary":"上次的结论"}`)).
		SetTriagedAt(at).SetTriageCount(1).SetNotifiedAt(at).SaveX(f.ctx)
	f.alert(inc, "rule-old", 3)
	return inc
}

func (f *retriageFixture) fresh(title string, created time.Time) *ent.Incident {
	f.t.Helper()
	inc := f.client.Incident.Create().SetStatus("open").SetTitle(title).SetGraph(json.RawMessage(`{}`)).
		SetCreatedAt(created).SaveX(f.ctx)
	f.alert(inc, "rule-new", 3)
	return inc
}

func (f *retriageFixture) alert(inc *ent.Incident, rule string, sev int16) {
	f.client.Alert.Create().SetTs(time.Now()).SetRuleID(rule).SetSeverity(sev).SetIncidentID(inc.ID).ExecX(f.ctx)
}

// evidence 模拟关联引擎并入新证据：先归属告警，再记时刻。
// 时刻往前拨几秒，让紧接着的研判确定晚于它（研判取上下文的时刻本身会往前让 clockSkew）
func (f *retriageFixture) evidence(inc *ent.Incident, rule string, sev int16, urgent bool) {
	f.evidenceAt(inc, rule, sev, urgent, time.Now().Add(-3*time.Second))
}

func (f *retriageFixture) evidenceAt(inc *ent.Incident, rule string, sev int16, urgent bool, at time.Time) {
	f.alert(inc, rule, sev)
	upd := f.client.Incident.UpdateOneID(inc.ID).SetEvidenceAt(at)
	if urgent {
		upd.SetUrgentAt(at)
	}
	upd.ExecX(f.ctx)
}

func (f *retriageFixture) get(inc *ent.Incident) *ent.Incident {
	return f.client.Incident.GetX(f.ctx, inc.ID)
}

func ids(incs []*ent.Incident) []uuid.UUID {
	out := make([]uuid.UUID, len(incs))
	for i, inc := range incs {
		out[i] = inc.ID
	}
	return out
}

// 冷却期内进来的新证据只累积不重研判；到期后一次性重研判，上下文带上第几次、上次结论与全部新增告警
func TestRetriageCooldown(t *testing.T) {
	ctx, client := testdb.New(t)
	f := &retriageFixture{t: t, ctx: ctx, client: client}
	stub := &stubLLM{}
	e := &Engine{DB: client, LLM: stub.llm(t), Cooldown: 30 * time.Minute}

	inc := f.triaged("Windows 服务变更", 5*time.Minute)
	for _, rule := range []string{"rule-a", "rule-b", "rule-a"} {
		f.evidence(inc, rule, 3, false)
		if err := e.batch(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := stub.calls(); n != 0 {
		t.Fatalf("冷却期内不应重研判，调了 %d 次", n)
	}
	got := f.get(inc)
	if got.Status != "triaged" || !review.IsRetriage(got) || got.NotifiedAt == nil {
		t.Fatalf("冷却期内应保持已研判、标待重研判、不动推送标记：%+v", got)
	}

	// 冷却到期：一次研判收下全部累积的证据
	client.Incident.UpdateOneID(inc.ID).SetTriagedAt(time.Now().Add(-31 * time.Minute)).ExecX(ctx)
	if err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if n := stub.calls(); n != 1 {
		t.Fatalf("到期应只重研判 1 次，调了 %d 次", n)
	}
	got = f.get(inc)
	if review.IsRetriage(got) || got.TriageCount != 2 || got.TriagedAt == nil || time.Since(*got.TriagedAt) > time.Minute {
		t.Errorf("重研判后应清待重研判、计数加一、记研判时刻：%+v", got)
	}
	c := stub.contexts[0]
	for _, want := range []string{"重新研判（此前已研判 1 次）", "上次摘要是模型判断，不是独立证据或人工确认", "上次的结论", "上次研判之后新增的告警", "rule-a：2 条告警", "rule-b：1 条告警"} {
		if !strings.Contains(c, want) {
			t.Errorf("重研判上下文缺少 %q：\n%s", want, c)
		}
	}
}

// 升级类证据不等冷却，立即重研判；研判期间又并入的证据不会被这次结论吞掉，仍待重研判
func TestRetriageUrgentAndInFlight(t *testing.T) {
	ctx, client := testdb.New(t)
	f := &retriageFixture{t: t, ctx: ctx, client: client}
	stub := &stubLLM{}
	e := &Engine{DB: client, LLM: stub.llm(t), Cooldown: 30 * time.Minute}

	inc := f.triaged("升级", time.Minute)
	f.evidence(inc, "rule-cred", 5, true)
	stub.hook = func() { f.evidenceAt(inc, "rule-late", 3, false, time.Now()) }
	if err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if n := stub.calls(); n != 1 {
		t.Fatalf("升级类应立即重研判，调了 %d 次", n)
	}
	got := f.get(inc)
	if review.IsUrgent(got) {
		t.Error("重研判后不应再是升级待研判")
	}
	if !review.IsRetriage(got) {
		t.Error("研判期间并入的证据没看过，应仍待重研判")
	}
	stub.hook = nil
	if err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if n := stub.calls(); n != 1 {
		t.Errorf("研判期间并入的普通证据要等冷却，调了 %d 次", n)
	}
}

// 队列：新事件优先且占多数名额，重研判至少一个保底名额（升级类在前），新事件不满时重研判补满
func TestRetriageQueueFairness(t *testing.T) {
	ctx, client := testdb.New(t)
	f := &retriageFixture{t: t, ctx: ctx, client: client}
	e := &Engine{DB: client, Cooldown: 30 * time.Minute}
	now := time.Now()

	// 老 incident：很早创建、反复有新证据，旧口径下永远排第一
	due := f.triaged("老事件", 2*time.Hour)
	client.Incident.UpdateOneID(due.ID).SetCreatedAt(now.Add(-48 * time.Hour)).ExecX(ctx)
	f.evidence(due, "rule-a", 3, false)
	dueLater := f.triaged("另一个待重研判", time.Hour)
	f.evidence(dueLater, "rule-a", 3, false)
	urgent := f.triaged("升级", time.Minute)
	f.evidence(urgent, "rule-x", 5, true)
	cooling := f.triaged("冷却中", time.Minute)
	f.evidence(cooling, "rule-a", 3, false)

	var news []*ent.Incident
	for i := range 6 {
		news = append(news, f.fresh("新事件", now.Add(-time.Duration(10-i)*time.Minute)))
	}
	got, err := e.queue(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	want := append(ids(news[:4]), urgent.ID)
	if !slices.Equal(ids(got), want) {
		t.Errorf("新事件多时应取最早的 4 个新事件 + 1 个升级类重研判：\n got %v\nwant %v", ids(got), want)
	}

	// 新事件只剩 1 个：重研判补满，升级类在前，其余按上次研判先后，冷却中的不取
	for _, n := range news[1:] {
		client.Incident.UpdateOneID(n.ID).SetStatus("triaged").SetTriagedAt(now).ExecX(ctx)
	}
	got, err = e.queue(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	want = []uuid.UUID{news[0].ID, urgent.ID, due.ID, dueLater.ID}
	if !slices.Equal(ids(got), want) {
		t.Errorf("新事件不满时重研判补满：\n got %v\nwant %v", ids(got), want)
	}
}

// 研判失败只退避失败的那一个，同批后面的照常研判；退避期内不取，到期后缩小上下文重试
func TestRetriageFailureBackoff(t *testing.T) {
	ctx, client := testdb.New(t)
	f := &retriageFixture{t: t, ctx: ctx, client: client}
	stub := &stubLLM{fail: func(c string) bool { return strings.Contains(c, "超大事件") }}
	e := &Engine{DB: client, LLM: stub.llm(t), Cooldown: 30 * time.Minute}
	now := time.Now()

	bad := f.fresh("超大事件", now.Add(-time.Hour))
	for range 40 {
		f.alert(bad, "rule-noise", 3)
	}
	good := f.fresh("正常事件", now.Add(-time.Minute))
	if err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.get(good); got.Status != "triaged" {
		t.Errorf("队首失败不应拖住后面的：%s", got.Status)
	}
	got := f.get(bad)
	if got.Status != "open" || got.TriageFailures != 1 || got.TriageRetryAt == nil || got.TriageRetryAt.Before(now.Add(50*time.Second)) {
		t.Fatalf("失败应记次数并退避：%+v", got)
	}
	if q, _ := e.queue(ctx, time.Now()); len(q) != 0 {
		t.Errorf("退避期内不应再取：%v", ids(q))
	}
	if q, _ := e.queue(ctx, got.TriageRetryAt.Add(time.Second)); !slices.Equal(ids(q), []uuid.UUID{bad.ID}) {
		t.Errorf("退避到期应再取：%v", ids(q))
	}

	// 退避翻倍；重试时告警明细按失败次数减半
	if err := e.backoff(ctx, got, now); err != nil {
		t.Fatal(err)
	}
	got = f.get(bad)
	if got.TriageFailures != 2 || got.TriageRetryAt.Sub(now) < 2*time.Minute-time.Second {
		t.Errorf("第二次失败应退避 2 分钟：%+v", got)
	}
	c, err := e.buildContext(ctx, got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c, "告警明细（12 条") || !strings.Contains(c, "rule-noise：40 条告警") {
		t.Errorf("失败两次后明细应减到 12 条、汇总仍是全量：\n%s", c[:min(len(c), 600)])
	}

	// 成功后清零
	stub.fail = nil
	client.Incident.UpdateOneID(bad.ID).SetTriageRetryAt(now.Add(-time.Second)).ExecX(ctx)
	if err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.get(bad); got.Status != "triaged" || got.TriageFailures != 0 || got.TriageRetryAt != nil {
		t.Errorf("研判成功应清掉失败计数与退避：%+v", got)
	}
}

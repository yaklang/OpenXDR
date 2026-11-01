//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/eventai"
	"openxdr/server/internal/eventarchive"
	"openxdr/server/internal/testdb"
	"openxdr/server/internal/triage"
)

// R5（调查覆盖漏传）回归：候选覆盖独立于目标来源。Related 的关联候选恒只查热表——
// 热目标的历史关联（同进程 / 父子 / 同连接）同样可能已归档，响应字段、发给模型的请求体
// 与前端提示带的是同一份事实（eventai.HotOnlyCoverage / CandidatesHotOnlyNote），
// 不能只对冷目标说明，也不能让模型把候选缺失推断为「没有相关行为」。
//
//	用例                                        | 覆盖的点
//	--------------------------------------------|----------------------------------
//	TestR5HotTargetColdRelativesCoverage        | 热目标+冷子事件：响应与模型输入都带候选边界
//	TestR5ZeroCandidatesStillCarriesCoverage    | 零候选照样声明边界（缺失≠不存在）
//	TestR5ColdReadDisabledKeepsHotCoverage      | 冷读关闭：热目标边界仍在，冷目标 404
//	TestR5CrossGroupNoCoverageLeak              | 越权 404，不泄漏候选边界信息
//	TestR5ExplainOldVariantNotReused            | 旧覆盖契约的解读结果不复用、重新生成

// r5LLM 起一个记录请求体的 mock 模型：每次调用都断言 user 消息里有固定覆盖说明
// （不能只断言结果字段——模型输入没带说明时结果字段再对也是漏传）。
func r5LLM(t *testing.T) *triage.LLM {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Messages []triage.Message }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if len(body.Messages) < 2 || !strings.Contains(body.Messages[1].Content, eventai.CandidatesHotOnlyNote) {
			t.Errorf("模型请求体应包含候选来源的固定覆盖说明: %+v", body.Messages)
		}
		reply := `{"verdict":"unknown","title":"解读","summary":"候选只来自热表","points":[],"related":[],"next":[]}`
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": reply}}}})
	}))
	t.Cleanup(srv.Close)
	return triage.NewLLM(srv.URL, "m", "", 10*time.Second)
}

// r5Related 取 related 并解出响应。
func r5Related(t *testing.T, ts *httptest.Server, id uuid.UUID) (int, relatedResponse, []byte) {
	t.Helper()
	resp, body := get(t, ts, "/api/events/"+id.String()+"/related")
	var out relatedResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("解析 related: %v（%s）", err, body)
		}
	}
	return resp.StatusCode, out, body
}

// r5Explain 发起解读并轮询到结束，返回最终任务视图。
func r5Explain(t *testing.T, ts *httptest.Server, id uuid.UUID) (jobID uuid.UUID, status string, archive *archiveScope) {
	t.Helper()
	resp, err := postJSON(ts, "/api/events/"+id.String()+"/explain", "")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("发起解读应 200: %v %v", resp, err)
	}
	var started struct {
		ID     uuid.UUID
		Status string
	}
	_ = json.NewDecoder(resp.Body).Decode(&started)
	resp.Body.Close()
	for range 200 {
		_, body := get(t, ts, "/api/events/"+id.String()+"/explain")
		var j struct {
			ID     uuid.UUID
			Status string
			Result struct {
				Archive *archiveScope
			}
		}
		_ = json.Unmarshal(body, &j)
		if j.Status != "running" {
			return j.ID, j.Status, j.Result.Archive
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("解读一直没跑完")
	return
}

// 热目标 + 冷子事件（同进程 / 子进程 / 同连接全部已归档）：候选查询一个都查不到，
// 响应仍必须带 candidates_hot_only=true（目标不在冷层）；冷目标对照：两字段都 true。
// explain 的模型请求体（热、冷目标各一次）都必须包含固定覆盖说明。
func TestR5HotTargetColdRelativesCoverage(t *testing.T) {
	ctx, client := testdb.New(t)
	db := archiveDB(t, ctx)
	if err := eventarchive.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	g := client.Group.Create().SetName("r5-g").SaveX(ctx)
	a1 := client.Asset.Create().SetHostname("r5-a1").SetGroupID(g.ID).SaveX(ctx)
	analyst := client.User.Create().SetUsername("r5-ana").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(g.ID).SetUserID(analyst.ID).SetRole("analyst").SaveX(ctx)

	guid, guid2, connTuple := uuid.New(), uuid.New(), "tcp:10.0.0.5:40000>198.51.100.7:4444"
	base := archiveTime()
	// 热目标：同进程 / 子进程 / 同连接的事件都已被归档（只在冷层，热表查不到）
	hot := client.Event.Create().SetTs(base.Add(10 * time.Minute)).SetClassUID(4001).SetSource("agent").
		SetAssetID(a1.ID).SetProcessGUID(guid).SetConnTuple(connTuple).
		SetRaw(json.RawMessage(`{"process":{"name":"r5-hot"},"conn":{"dst":"198.51.100.7:4444"}}`)).SaveX(ctx)
	coldRelatives := []eventarchive.Event{
		{ID: uuid.New(), Ts: base.Add(9 * time.Minute), ClassUID: 4001, Source: "agent",
			AssetID: &a1.ID, ProcessGUID: &guid, Raw: json.RawMessage(`{"mark":"r5-cold-same-proc"}`)},
		{ID: uuid.New(), Ts: base.Add(11 * time.Minute), ClassUID: 4001, Source: "agent",
			AssetID: &a1.ID, ParentProcessGUID: &guid, Raw: json.RawMessage(`{"mark":"r5-cold-child"}`)},
		{ID: uuid.New(), Ts: base.Add(12 * time.Minute), ClassUID: 4001, Source: "agent",
			AssetID: &a1.ID, ConnTuple: &connTuple, Raw: json.RawMessage(`{"mark":"r5-cold-conn"}`)},
	}
	insertLocatedChunk(t, ctx, db, 1, coldRelatives)
	// 冷目标对照：目标本身来自冷层
	coldTarget := eventarchive.Event{ID: uuid.New(), Ts: base.Add(20 * time.Minute), ClassUID: 4001, Source: "agent",
		AssetID: &a1.ID, ProcessGUID: &guid2, Raw: json.RawMessage(`{"mark":"r5-cold-target"}`)}
	insertLocatedChunk(t, ctx, db, 2, []eventarchive.Event{coldTarget})

	ts := httptest.NewServer(as(analyst, EventAI(client, db, r5LLM(t))))
	t.Cleanup(ts.Close)

	// 热目标：候选全在冷层 → groups 空，但边界必须说明（修复前这里 Archive 是 nil）
	code, out, body := r5Related(t, ts, hot.ID)
	if code != http.StatusOK {
		t.Fatalf("热目标 related 应 200: %d: %s", code, body)
	}
	if len(out.Groups) != 0 {
		t.Fatalf("同进程/父子/同连接事件都已归档时热表不该有候选: %+v", out.Groups)
	}
	if out.Archive == nil || out.Archive.TargetFromArchive || !out.Archive.CandidatesHotOnly {
		t.Fatalf("热目标应带候选边界（target_from_archive=false, candidates_hot_only=true）: %+v", out.Archive)
	}
	// 冷目标对照：两字段都 true（现行为保持）
	code, out, body = r5Related(t, ts, coldTarget.ID)
	if code != http.StatusOK {
		t.Fatalf("冷目标 related 应 200: %d: %s", code, body)
	}
	if out.Archive == nil || !out.Archive.TargetFromArchive || !out.Archive.CandidatesHotOnly {
		t.Fatalf("冷目标应两字段都 true: %+v", out.Archive)
	}

	// explain：热、冷目标的模型请求体都必须带固定覆盖说明（在 r5LLM 里逐次断言），
	// 结果里的边界与 related 同一份事实
	if _, status, archive := r5Explain(t, ts, hot.ID); status != "done" {
		t.Fatalf("热目标解读应完成: %s", status)
	} else if archive == nil || archive.TargetFromArchive || !archive.CandidatesHotOnly {
		t.Fatalf("热目标解读结果应带候选边界: %+v", archive)
	}
	if _, status, archive := r5Explain(t, ts, coldTarget.ID); status != "done" {
		t.Fatalf("冷目标解读应完成: %s", status)
	} else if archive == nil || !archive.TargetFromArchive || !archive.CandidatesHotOnly {
		t.Fatalf("冷目标解读结果应两字段都 true: %+v", archive)
	}
}

// 零候选：没有任何关联（冷热都没有）时照样声明候选边界——「没查到」不等于「不存在」，
// 模型输入里的覆盖说明也不因候选为空而省略。
func TestR5ZeroCandidatesStillCarriesCoverage(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("r5-zero").SaveX(ctx)
	a1 := client.Asset.Create().SetHostname("r5-zero-a1").SetGroupID(g.ID).SaveX(ctx)
	analyst := client.User.Create().SetUsername("r5-zero-ana").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(g.ID).SetUserID(analyst.ID).SetRole("analyst").SaveX(ctx)
	lonely := client.Event.Create().SetTs(time.Now().Add(-time.Hour)).SetClassUID(4001).SetSource("agent").
		SetAssetID(a1.ID).SetProcessGUID(uuid.New()).
		SetRaw(json.RawMessage(`{"mark":"r5-lonely"}`)).SaveX(ctx)

	ts := httptest.NewServer(as(analyst, EventAI(client, nil, r5LLM(t))))
	t.Cleanup(ts.Close)
	code, out, body := r5Related(t, ts, lonely.ID)
	if code != http.StatusOK {
		t.Fatalf("零候选 related 应 200: %d: %s", code, body)
	}
	if len(out.Groups) != 0 || out.Archive == nil || out.Archive.TargetFromArchive || !out.Archive.CandidatesHotOnly {
		t.Fatalf("零候选也应声明候选边界: groups=%+v archive=%+v", out.Groups, out.Archive)
	}
	if _, status, archive := r5Explain(t, ts, lonely.ID); status != "done" || archive == nil || !archive.CandidatesHotOnly {
		t.Fatalf("零候选的解读也要带边界: %s %+v", status, archive)
	}
}

// 冷读关闭（conn=nil，EVENT_ARCHIVE_READ 关闭的同一形态）：热目标的候选边界照常给出；
// 冷目标按不存在处理（404），不假装查过冷层。
func TestR5ColdReadDisabledKeepsHotCoverage(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("r5-off").SaveX(ctx)
	a1 := client.Asset.Create().SetHostname("r5-off-a1").SetGroupID(g.ID).SaveX(ctx)
	analyst := client.User.Create().SetUsername("r5-off-ana").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(g.ID).SetUserID(analyst.ID).SetRole("analyst").SaveX(ctx)
	hot := client.Event.Create().SetTs(time.Now().Add(-time.Hour)).SetClassUID(4001).SetSource("agent").
		SetAssetID(a1.ID).SetRaw(json.RawMessage(`{"mark":"r5-off-hot"}`)).SaveX(ctx)

	off := httptest.NewServer(as(analyst, EventAI(client, nil, r5LLM(t))))
	t.Cleanup(off.Close)
	code, out, body := r5Related(t, off, hot.ID)
	if code != http.StatusOK {
		t.Fatalf("冷读关闭时热目标 related 应 200: %d: %s", code, body)
	}
	if out.Archive == nil || out.Archive.TargetFromArchive || !out.Archive.CandidatesHotOnly {
		t.Fatalf("冷读关闭不影响热目标的候选边界: %+v", out.Archive)
	}
	// 冷读关闭：冷目标（冷层里就算有也不读）与不存在同口径 404
	if code, _, body := r5Related(t, off, uuid.New()); code != http.StatusNotFound {
		t.Fatalf("冷读关闭时冷事件应 404: %d: %s", code, body)
	}
}

// 越权：组外热目标的 related/explain 与热表同口径 404，响应里不携带候选边界信息。
func TestR5CrossGroupNoCoverageLeak(t *testing.T) {
	ctx, client := testdb.New(t)
	mine, other := client.Group.Create().SetName("r5-mine").SaveX(ctx), client.Group.Create().SetName("r5-other").SaveX(ctx)
	theirs := client.Asset.Create().SetHostname("r5-theirs").SetGroupID(other.ID).SaveX(ctx)
	analyst := client.User.Create().SetUsername("r5-x-ana").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(mine.ID).SetUserID(analyst.ID).SetRole("analyst").SaveX(ctx)
	hidden := client.Event.Create().SetTs(time.Now().Add(-time.Hour)).SetClassUID(4001).SetSource("agent").
		SetAssetID(theirs.ID).SetRaw(json.RawMessage(`{}`)).SaveX(ctx)

	ts := httptest.NewServer(as(analyst, EventAI(client, nil, r5LLM(t))))
	t.Cleanup(ts.Close)
	if code, _, body := r5Related(t, ts, hidden.ID); code != http.StatusNotFound {
		t.Fatalf("组外事件 related 应 404: %d: %s", code, body)
	} else if strings.Contains(string(body), "candidates_hot_only") {
		t.Fatalf("越权响应不该携带候选边界信息: %s", body)
	}
	if resp, err := postJSON(ts, "/api/events/"+hidden.ID.String()+"/explain", ""); err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("组外事件 explain 应 404: %v %v", resp, err)
	}
}

// 旧覆盖契约的解读结果不能复用：R5 前 variant 只含语言、结果生成时模型输入没有候选来源
// 说明——版本号（cov1）并进 variant 后，旧任务自然查不到（GET 视为 none），重新发起时
// 才会调模型，不把旧结果伪装成按新契约生成的。
func TestR5ExplainOldVariantNotReused(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("r5-old").SaveX(ctx)
	a1 := client.Asset.Create().SetHostname("r5-old-a1").SetGroupID(g.ID).SaveX(ctx)
	analyst := client.User.Create().SetUsername("r5-old-ana").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(g.ID).SetUserID(analyst.ID).SetRole("analyst").SaveX(ctx)
	target := client.Event.Create().SetTs(time.Now().Add(-time.Hour)).SetClassUID(4001).SetSource("agent").
		SetAssetID(a1.ID).SetRaw(json.RawMessage(`{"mark":"r5-old"}`)).SaveX(ctx)
	// 旧契约的已完成结果：variant 是纯语言（无覆盖版本号）
	old := client.AIJob.Create().SetKind("explain").SetSubject(target.ID.String()).SetOwner(analyst.ID.String()).
		SetVariant("").SetStatus("done").
		SetResult(map[string]any{"verdict": "benign", "title": "旧解读"}).SaveX(ctx)

	ts := httptest.NewServer(as(analyst, EventAI(client, nil, r5LLM(t))))
	t.Cleanup(ts.Close)
	// GET：旧 variant 查不到 → none，而不是把旧结果当成当前结果
	if _, body := get(t, ts, "/api/events/"+target.ID.String()+"/explain"); !strings.Contains(string(body), `"none"`) {
		t.Fatalf("旧覆盖契约的结果不应被读到: %s", body)
	}
	id, status, archive := r5Explain(t, ts, target.ID)
	if status != "done" || id == old.ID {
		t.Fatalf("应重新生成而非复用旧结果: status=%s id=%s old=%s", status, id, old.ID)
	}
	if archive == nil || !archive.CandidatesHotOnly {
		t.Fatalf("重新生成的结果应带候选边界: %+v", archive)
	}
}

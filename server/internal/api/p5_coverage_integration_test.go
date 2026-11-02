//go:build integration

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entevent "openxdr/server/ent/event"
	"openxdr/server/internal/eventarchive"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
	"openxdr/server/internal/triage"
)

// P5 查询覆盖度与调查入口闭环：T19（覆盖度对象契约：关键词跨归档天、冷读关闭、扫描预算、
// 零结果缺口）、T20（冷事件 related/explain 的权限与热表同口径）、T23（热冷排序、重叠副本
// 去重、关键词 UUID/长哈希语义不回归）。合流与组权限的主体断言在 events_archive_integration_test.go
// （B1 断言已迁移到对象契约），这里补 P5 的新契约。

// insertLocatedChunk 写冷块并登记 locator 行（P2 的索引路径），Locate 才能按 id 命中。
// 不写 locator 的块（直接用 insertChunk）模拟「还有旧块未回填」，用来触发 ErrLocatorIncomplete。
func insertLocatedChunk(t *testing.T, ctx context.Context, db *sql.DB, seq int, events []eventarchive.Event) uuid.UUID {
	t.Helper()
	chunkID := insertChunk(t, ctx, db, seq, events)
	for _, e := range events {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO event_archive_locator (event_id, chunk_id) VALUES ($1,$2)`, e.ID, chunkID); err != nil {
			t.Fatalf("写 locator 行: %v", err)
		}
	}
	return chunkID
}

func p5Server(t *testing.T, client *ent.Client, db *sql.DB) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(asAdmin(Handler(client, db, loadRules(t), response.NewHub(client, false),
		suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)))
	t.Cleanup(ts.Close)
	return ts
}

// coverageOf 解出响应体里的 coverage，顺带校验对象契约的另外两个字段都存在。
func coverageOf(t *testing.T, body []byte) eventsCoverage {
	t.Helper()
	var out eventsResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("解析响应: %v（%s）", err, body)
	}
	return out.Coverage
}

// ---- T19：覆盖度对象契约 ----

// T19-1 关键词跨归档天：关键词只搜热表；冷块里的命中不返回，缺口如实标注。
// 零结果时 items 必须是空数组（不是 null），reason 非空；有结果时同样标注缺口。
func TestP5CoverageKeywordAcrossArchiveDays(t *testing.T) {
	ctx, client := testdb.New(t)
	db := archiveDB(t, ctx)
	if err := eventarchive.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	base := archiveTime()
	hot := client.Event.Create().SetTs(base.Add(10 * time.Minute)).SetClassUID(4001).SetSource("agent").
		SetRaw(json.RawMessage(`{"conn":{"dst":"10.0.0.1:443"},"mark":"p5-hot-marker"}`)).SaveX(ctx)
	cold := coldEvent(base.Add(20*time.Minute), nil, `{"mark":"p5-cold-marker"}`)
	insertChunk(t, ctx, db, 1, []eventarchive.Event{cold})

	ts := p5Server(t, client, db)

	// 关键词只存在于冷块：零结果 + 缺口说明，items 是 [] 不是 null
	resp, rows, body := queryEvents(t, ts, base, "q=p5-cold-marker")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	if len(rows) != 0 {
		t.Errorf("关键词查询不该返回只存在于冷块的事件，实际 %d 条", len(rows))
	}
	if !strings.Contains(string(body), `"items":[]`) {
		t.Errorf("零结果时 items 应是空数组: %s", body)
	}
	cov := coverageOf(t, body)
	want := eventsCoverage{HotSearched: true, ColdSearched: false, ScanComplete: false, Reason: "keyword_not_searched"}
	if cov != want {
		t.Errorf("关键词查询的 coverage = %+v，期望 %+v", cov, want)
	}
	if h := resp.Header.Get("X-Archive-Coverage"); h != "skipped=keyword" {
		t.Errorf("调试头 = %q，期望 skipped=keyword", h)
	}

	// 关键词命中热表：结果正常返回，缺口照样标注（正常结果页也说明覆盖边界）
	resp, rows, body = queryEvents(t, ts, base, "q=p5-hot-marker")
	if resp.StatusCode != http.StatusOK || len(rows) != 1 || rows[0].ID != hot.ID {
		t.Fatalf("热表关键词应命中 1 条，得到 %d: %s", len(rows), body)
	}
	if cov := coverageOf(t, body); cov.Reason != "keyword_not_searched" || cov.ColdSearched || cov.ScanComplete {
		t.Errorf("有结果时关键词缺口也要标注: %+v", cov)
	}
}

// T19-2 冷读关闭：库里明明有冷块，但连接没接（EVENT_ARCHIVE_READ 关）——
// 冷层不参与合流、不假装查过（cold_searched=false），coverage 与改动前一致不报缺口：
// 这是部署配置错误，由 main 在启动日志里告警，不让每次检索都弹提示。
func TestP5CoverageArchiveReadDisabled(t *testing.T) {
	ctx, client := testdb.New(t)
	db := archiveDB(t, ctx)
	if err := eventarchive.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	base := archiveTime()
	hot := client.Event.Create().SetTs(base.Add(10 * time.Minute)).SetClassUID(4001).SetSource("agent").
		SetRaw(json.RawMessage(`{"mark":"p5-hot"}`)).SaveX(ctx)
	cold := coldEvent(base.Add(20*time.Minute), nil, `{"mark":"p5-cold"}`)
	insertChunk(t, ctx, db, 1, []eventarchive.Event{cold})

	// conn 传 nil：与生产 EVENT_ARCHIVE_READ 关闭同一形态
	off := httptest.NewServer(asAdmin(Handler(client, nil, loadRules(t), response.NewHub(client, false),
		suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)))
	t.Cleanup(off.Close)

	resp, rows, body := queryEvents(t, off, base, "")
	if resp.StatusCode != http.StatusOK || len(rows) != 1 || rows[0].ID != hot.ID {
		t.Fatalf("冷读关闭应只返回热表 1 条，得到 %d: %s", len(rows), body)
	}
	cov := coverageOf(t, body)
	want := eventsCoverage{HotSearched: true, ColdSearched: false, ScanComplete: true}
	if cov != want {
		t.Errorf("冷读关闭的 coverage = %+v，期望 %+v", cov, want)
	}
	if h := resp.Header.Get("X-Archive-Coverage"); h != "" {
		t.Errorf("冷读关闭不写覆盖度头，实际 %q", h)
	}
}

// T19-3 扫描预算耗尽：候选块超过 200 块的预算时 scan_complete=false（没扫完），
// 且 truncated（返回条数达到 limit）可以同时为真——两个缺口分别表达，不能互相顶替。
func TestP5CoverageScanBudget(t *testing.T) {
	ctx, client := testdb.New(t)
	db := archiveDB(t, ctx)
	if err := eventarchive.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	base := archiveTime()
	// 205 个单事件块：全部落在查询窗口内，预算只够扫 200 块
	for i := 0; i < 205; i++ {
		insertChunk(t, ctx, db, i+1, []eventarchive.Event{
			coldEvent(base.Add(time.Duration(i)*time.Minute), nil, `{"mark":"p5-budget"}`),
		})
	}
	ts := p5Server(t, client, db)
	q := "from=" + base.Add(-time.Hour).Format(time.RFC3339) +
		"&to=" + base.Add(205*time.Minute+time.Hour).Format(time.RFC3339)

	// limit=1：返回条数到限（truncated=true）与扫描未完成（scan_complete=false）同时成立
	resp, body := get(t, ts, "/api/events?"+q+"&limit=1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	var out eventsResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Items) != 1 || !out.Truncated {
		t.Fatalf("limit=1 应返回 1 条并报 truncated: %d 条 truncated=%v", len(out.Items), out.Truncated)
	}
	if !out.Coverage.ColdSearched || out.Coverage.ScanComplete || out.Coverage.Reason != "scan_incomplete" {
		t.Errorf("预算耗尽的 coverage = %+v，期望 cold_searched=true / scan_complete=false / reason=scan_incomplete", out.Coverage)
	}

	// 对照：候选块没超预算时，limit 截断只是条数到限，扫描是完整的——两个标志独立表达
	if _, err := db.ExecContext(ctx, `DELETE FROM event_archive_chunks`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		insertChunk(t, ctx, db, i+1, []eventarchive.Event{
			coldEvent(base.Add(time.Duration(i)*time.Minute), nil, `{"mark":"p5-small"}`),
		})
	}
	q2 := "from=" + base.Add(-time.Hour).Format(time.RFC3339) +
		"&to=" + base.Add(3*time.Minute+time.Hour).Format(time.RFC3339)
	resp, body = get(t, ts, "/api/events?"+q2+"&limit=2")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	out = eventsResponse{}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Items) != 2 || !out.Truncated {
		t.Fatalf("limit=2 应返回 2 条并报 truncated: %d 条 truncated=%v", len(out.Items), out.Truncated)
	}
	if !out.Coverage.ScanComplete || out.Coverage.Reason != "" || !out.Coverage.ColdSearched {
		t.Errorf("没超预算时 limit 截断不该连累 scan_complete: %+v", out.Coverage)
	}
}

// ---- T20：冷事件 related / explain ----

// T20 冷事件调查入口：按 id 定位冷事件，权限与热表同口径（asset_id ∈ scope；NULL 资产仅 admin）；
// 组内冷事件可访问，冷行的字段（进程 GUID、连接五元组）与热表同构地驱动关联查询；
// 关联候选仍只来自热表，响应体注明冷层边界。不物化、不 pin。
func TestP5ColdEventRelatedExplainScope(t *testing.T) {
	ctx, client := testdb.New(t)
	db := archiveDB(t, ctx)
	if err := eventarchive.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	gA := client.Group.Create().SetName("p5-a").SaveX(ctx)
	gB := client.Group.Create().SetName("p5-b").SaveX(ctx)
	a1 := client.Asset.Create().SetHostname("p5-a1").SetGroupID(gA.ID).SaveX(ctx)
	b1 := client.Asset.Create().SetHostname("p5-b1").SetGroupID(gB.ID).SaveX(ctx)

	// 冷目标：有进程 GUID、父 GUID 与连接五元组——字段同构与否由关联查询能不能用上它们来证明
	guid, parent, connTuple := uuid.New(), uuid.New(), "tcp:10.0.0.9:40000>198.51.100.7:4444"
	base := archiveTime()
	coldTarget := eventarchive.Event{
		ID: uuid.New(), Ts: base.Add(10 * time.Minute), ClassUID: 4001, Source: "agent",
		AssetID: &a1.ID, ProcessGUID: &guid, ParentProcessGUID: &parent,
		ConnTuple: &connTuple, Raw: json.RawMessage(`{"process":{"name":"p5-cold-target"},"mark":"p5-cold-raw"}`),
	}
	outGroup := coldEvent(base.Add(20*time.Minute), &b1.ID, `{"mark":"p5-out-group"}`)
	noAsset := coldEvent(base.Add(30*time.Minute), nil, `{"mark":"p5-no-asset"}`)
	insertLocatedChunk(t, ctx, db, 1, []eventarchive.Event{coldTarget, outGroup, noAsset})

	// 热表候选：父进程、子进程、同连接（都在组内资产上）
	hotParent := client.Event.Create().SetTs(base.Add(9 * time.Minute)).SetClassUID(4001).SetSource("agent").
		SetAssetID(a1.ID).SetProcessGUID(parent).SetRaw(json.RawMessage(`{"process":{"name":"p5-parent"}}`)).SaveX(ctx)
	hotChild := client.Event.Create().SetTs(base.Add(11 * time.Minute)).SetClassUID(4001).SetSource("agent").
		SetAssetID(a1.ID).SetParentProcessGUID(guid).SetRaw(json.RawMessage(`{"process":{"name":"p5-child"}}`)).SaveX(ctx)
	hotConn := client.Event.Create().SetTs(base.Add(12 * time.Minute)).SetClassUID(4001).SetSource("agent").
		SetAssetID(a1.ID).SetConnTuple(connTuple).SetRaw(json.RawMessage(`{"dst_endpoint":{"ip":"198.51.100.7"}}`)).SaveX(ctx)
	// 热表的组外事件：与冷事件组外拒绝做同口径对照
	hotOut := client.Event.Create().SetTs(base.Add(13 * time.Minute)).SetClassUID(4001).SetSource("agent").
		SetAssetID(b1.ID).SetRaw(json.RawMessage(`{"mark":"p5-hot-out"}`)).SaveX(ctx)

	analyst := client.User.Create().SetUsername("p5-ana").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(gA.ID).SetUserID(analyst.ID).SetRole("analyst").SaveX(ctx)

	related := func(h http.Handler, id uuid.UUID) (*http.Response, relatedResponse, []byte) {
		ts := httptest.NewServer(as(analyst, h))
		t.Cleanup(ts.Close)
		resp, body := get(t, ts, "/api/events/"+id.String()+"/related")
		var out relatedResponse
		if resp.StatusCode == http.StatusOK {
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatalf("解析 related: %v（%s）", err, body)
			}
		}
		return resp, out, body
	}

	// 组内冷事件：可访问；冷行字段驱动关联（ancestor=父、child=子、connection=同连接）。
	// /api/events/{id}/related 挂在 EventAI 处理器上（main.go 的挂法）
	hot := EventAI(client, db, triage.NewLLM("", "", "", time.Second))
	resp, out, body := related(hot, coldTarget.ID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("组内冷事件 related 应 200，得到 %d: %s", resp.StatusCode, body)
	}
	got := map[string][]uuid.UUID{}
	for _, g := range out.Groups {
		for _, e := range g.Events {
			got[g.Relation] = append(got[g.Relation], e.ID)
		}
	}
	if len(got["ancestor"]) != 1 || got["ancestor"][0] != hotParent.ID ||
		len(got["child"]) != 1 || got["child"][0] != hotChild.ID ||
		len(got["connection"]) != 1 || got["connection"][0] != hotConn.ID {
		t.Errorf("冷事件的进程/连接字段应同构地驱动关联: %+v", got)
	}
	// 响应体注明：目标来自冷层，候选只查了热表
	if out.Archive == nil || !out.Archive.TargetFromArchive || !out.Archive.CandidatesHotOnly {
		t.Errorf("冷目标的 related 应带冷层边界说明: %+v", out.Archive)
	}

	// 组外冷事件 / NULL 资产冷事件 / 组外热事件：三者与热表同口径（404、同样的文案、不泄漏存在性）
	denyBody := ""
	for i, id := range []uuid.UUID{outGroup.ID, noAsset.ID, hotOut.ID} {
		resp, _, body := related(hot, id)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("第 %d 个（越权）应 404，得到 %d: %s", i, resp.StatusCode, body)
		}
		if i == 2 {
			denyBody = strings.TrimSpace(string(body))
		}
	}
	// 冷事件的拒绝文案与热表完全一致
	for _, id := range []uuid.UUID{outGroup.ID, noAsset.ID} {
		_, _, body := related(hot, id)
		if strings.TrimSpace(string(body)) != denyBody {
			t.Errorf("冷事件拒绝文案应与热表同口径: %q vs %q", strings.TrimSpace(string(body)), denyBody)
		}
	}
	// admin 能看全部三视角（含 NULL 资产）——与热表口径一致
	adminTS := httptest.NewServer(asAdmin(hot))
	t.Cleanup(adminTS.Close)
	for _, id := range []uuid.UUID{coldTarget.ID, outGroup.ID, noAsset.ID} {
		resp, body := get(t, adminTS, "/api/events/"+id.String()+"/related")
		if resp.StatusCode != http.StatusOK {
			t.Errorf("admin 看冷事件 %s 应 200，得到 %d: %s", id, resp.StatusCode, body)
		}
	}

	// 冷读关闭：冷层不参与，冷事件按不存在处理
	off := EventAI(client, nil, triage.NewLLM("", "", "", time.Second))
	if resp, _, body := related(off, coldTarget.ID); resp.StatusCode != http.StatusNotFound {
		t.Errorf("冷读关闭时冷事件应 404，得到 %d: %s", resp.StatusCode, body)
	}

	// locator 未回填（还有块没有索引行）：不能断言「不存在」，404 并说明冷层状态未知
	unIndexed := coldEvent(base.Add(40*time.Minute), &a1.ID, `{"mark":"p5-unindexed"}`)
	insertChunk(t, ctx, db, 2, []eventarchive.Event{unIndexed})
	resp, _, body = related(hot, uuid.New())
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(body), "冷层状态未知") {
		t.Errorf("locator 不完整时应 404 并说明原因，得到 %d: %s", resp.StatusCode, body)
	}

	// explain：冷事件作为解读目标，模型输入里要有冷行原文；结果带冷层边界说明
	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []triage.Message
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !strings.Contains(body.Messages[1].Content, "p5-cold-raw") {
			t.Errorf("解读输入应包含冷事件原文")
		}
		reply := `{"verdict":"suspicious","title":"冷事件解读","summary":"来自冷归档的出站连接","points":["外连 4444"],"related":[],"next":["查父进程"]}`
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": reply}}}})
	}))
	t.Cleanup(llmSrv.Close)
	explainTS := httptest.NewServer(as(analyst, EventAI(client, db, triage.NewLLM(llmSrv.URL, "m", "", 10*time.Second))))
	t.Cleanup(explainTS.Close)
	if resp, err := postJSON(explainTS, "/api/events/"+coldTarget.ID.String()+"/explain", ""); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("发起解读应 200: %v %v", resp, err)
	}
	type jobView struct {
		Status string
		Result struct {
			Verdict string
			Title   string
			Archive *archiveScope
		}
	}
	var done jobView
	for range 100 {
		resp, body := get(t, explainTS, "/api/events/"+coldTarget.ID.String()+"/explain")
		var j jobView
		_ = json.Unmarshal(body, &j)
		resp.Body.Close()
		if j.Status != "running" {
			done = j
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if done.Status != "done" || done.Result.Verdict != "suspicious" {
		t.Fatalf("解读应完成: %+v", done)
	}
	if done.Result.Archive == nil || !done.Result.Archive.TargetFromArchive || !done.Result.Archive.CandidatesHotOnly {
		t.Errorf("解读结果应带冷层边界说明: %+v", done.Result.Archive)
	}

	// 读冷事件不产生写操作：热表里不该多出这条冷事件的物化行
	n, err := client.Event.Query().Where(entevent.IDEQ(coldTarget.ID)).Count(ctx)
	if err != nil || n != 0 {
		t.Errorf("调查入口不得自动物化冷事件，热表出现 %d 行: %v", n, err)
	}
}

// ---- T23：合流语义在对象契约下不回归 ----

// T23 同 ts 排序（(ts,id) 倒序与 id 有关）、重叠副本去重取热表原文、关键词查 UUID 语义不回归。
func TestP5HotColdMergeOrderDedupKeyword(t *testing.T) {
	ctx, client := testdb.New(t)
	db := archiveDB(t, ctx)
	if err := eventarchive.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	base := archiveTime()
	// 两个同 ts 的事件：一个在热表（id 较小），一个只在冷层（id 较大）——倒序时冷层那条在前
	low := uuid.MustParse("0190d7b0-0000-7000-8000-000000000001")
	high := uuid.MustParse("0190d7b0-0000-7000-8000-00000000000f")
	sameTs := base.Add(10 * time.Minute)
	client.Event.Create().SetID(low).SetTs(sameTs).SetClassUID(4001).SetSource("agent").
		SetRaw(json.RawMessage(`{"mark":"p5-hot-low"}`)).SaveX(ctx)
	coldHigh := eventarchive.Event{ID: high, Ts: sameTs, ClassUID: 4001, Source: "agent",
		Raw: json.RawMessage(`{"mark":"p5-cold-high"}`)}
	// 重叠副本：冷块里还有一份与热表 low 同 id 同 ts 的旧拷贝，合流只保留热表那份
	stale := eventarchive.Event{ID: low, Ts: sameTs, ClassUID: 4001, Source: "agent",
		Raw: json.RawMessage(`{"mark":"p5-stale-cold-copy"}`)}
	insertChunk(t, ctx, db, 1, []eventarchive.Event{coldHigh, stale})

	ts := p5Server(t, client, db)
	resp, rows, body := queryEvents(t, ts, base, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	if len(rows) != 2 || rows[0].ID != high || rows[1].ID != low {
		t.Fatalf("同 ts 应按 id 倒序且重叠副本只留一条: %v", rows)
	}
	if raw := string(rows[1].Raw); !strings.Contains(raw, "p5-hot-low") || strings.Contains(raw, "p5-stale-cold-copy") {
		t.Errorf("重叠副本应取热表原文，实际 %s", raw)
	}
	if cov := coverageOf(t, body); cov.ColdSearched != true || cov.ScanComplete != true || cov.Reason != "" {
		t.Errorf("正常合流的 coverage 应无缺口: %+v", cov)
	}

	// 关键词查 UUID：热表关键词语义不回归（UUID 走 raw::text 匹配，命中）；
	// 只存在于冷块的 UUID 同样受 keyword_not_searched 缺口约束
	hotUUID := "0199d7b0-1111-7000-8000-abcdefabcdef"
	client.Event.Create().SetTs(base.Add(20 * time.Minute)).SetClassUID(4001).SetSource("agent").
		SetRaw(json.RawMessage(`{"process":{"uid":"` + hotUUID + `"}}`)).SaveX(ctx)
	resp, rows, body = queryEvents(t, ts, base, "q="+hotUUID)
	if resp.StatusCode != http.StatusOK || len(rows) != 1 {
		t.Fatalf("热表里的 UUID 关键词应命中 1 条，得到 %d: %s", len(rows), body)
	}
	coldUUID := "0199d7b0-2222-7000-8000-abcdefabcdef"
	insertChunk(t, ctx, db, 2, []eventarchive.Event{
		coldEvent(base.Add(50*time.Minute), nil, `{"process":{"uid":"`+coldUUID+`"}}`),
	})
	resp, rows, body = queryEvents(t, ts, base, "q="+coldUUID)
	if resp.StatusCode != http.StatusOK || len(rows) != 0 {
		t.Fatalf("只存在于冷块的 UUID 不该返回，得到 %d: %s", len(rows), body)
	}
	if cov := coverageOf(t, body); cov.Reason != "keyword_not_searched" || cov.ColdSearched {
		t.Errorf("冷块 UUID 命中应标注关键词缺口: %+v", cov)
	}
}

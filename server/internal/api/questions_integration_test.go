//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/questions"
	"openxdr/server/internal/standingrules"
	"openxdr/server/internal/testdb"
)

// 待答问题按组可见、证据只在详情里；只有平台管理员能作答，档位受规矩模板约束，作答不能重复
func TestQuestionsAPI(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("ops").SaveX(ctx)
	other := client.Group.Create().SetName("other").SaveX(ctx)
	host := client.Asset.Create().SetHostname("raid").SetGroupID(g.ID).SaveX(ctx)
	admin := client.User.Create().SetUsername("root").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	ana := client.User.Create().SetUsername("ana").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(g.ID).SetUserID(ana.ID).SetRole("admin").SaveX(ctx)
	f := client.Finding.Create().SetGroupID(g.ID).SetAssetID(host.ID).SetKey("k").SetTitle("t").SaveX(ctx)
	mine, err := questions.Ask(ctx, client, questions.Request{Kind: "authorization", SubjectKind: "domain", Subject: "scan.gzmpc.com", Groups: []uuid.UUID{g.ID}, Finding: &f.ID, Note: "钥匙注释 evil"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := questions.Ask(ctx, client, questions.Request{Kind: "owner", SubjectKind: "ip", Subject: "203.0.113.7", Groups: []uuid.UUID{other.ID}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := standingrules.SeedBuiltins(ctx, client); err != nil {
		t.Fatal(err)
	}
	rules := client.StandingRule.Query().AllX(ctx)
	h := Control(client, nil)
	asAdmin := httptest.NewServer(as(admin, h))
	t.Cleanup(asAdmin.Close)
	asAna := httptest.NewServer(as(ana, h))
	t.Cleanup(asAna.Close)
	get := func(s *httptest.Server, path string, v any) int {
		t.Helper()
		resp, err := http.Get(s.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if v != nil {
			_ = json.NewDecoder(resp.Body).Decode(v)
		}
		return resp.StatusCode
	}
	post := func(s *httptest.Server, path, body string) int {
		t.Helper()
		resp, err := http.Post(s.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	var rows []questionRow
	if get(asAna, "/api/questions", &rows); len(rows) != 1 || rows[0].ID != mine.Question.ID || rows[0].SubjectLabel != "scan[.]gzmpc[.]com" || rows[0].DomainGroup != "gzmpc.com" || len(rows[0].Scopes) != 1 || rows[0].Scopes[0] != "gzmpc.com" || rows[0].FindingCount != 1 {
		t.Fatalf("组管理员只看本组问题：%+v", rows)
	}
	if get(asAdmin, "/api/questions", &rows); len(rows) != 2 {
		t.Fatalf("平台管理员看全部：%d", len(rows))
	}
	var d questionDetail
	if code := get(asAna, "/api/questions/"+mine.Question.ID.String(), &d); code != http.StatusOK || len(d.Evidence) != 1 || d.Evidence[0].Note != "钥匙注释 evil" || len(d.Findings) != 1 || d.Findings[0].Hostname != "raid" {
		t.Fatalf("详情带证据与关联待办：%d %+v", code, d)
	}
	path := "/api/questions/" + mine.Question.ID.String() + "/answer"
	if code := post(asAna, path, `{"choice":"grant","content":"红队授权"}`); code != http.StatusForbidden {
		t.Fatalf("组管理员不能作答：%d", code)
	}
	if code := post(asAdmin, path, `{"choice":"grant"}`); code != http.StatusBadRequest {
		t.Fatalf("授权须写范围：%d", code)
	}
	if code := post(asAdmin, path, `{"choice":"grant","content":"红队授权","approveAll":true}`); code != http.StatusBadRequest {
		t.Fatalf("不认识的字段拒绝：%d", code)
	}
	if code := post(asAdmin, path, `{"choice":"grant","content":"proj_090 红队授权","expiresInDays":14}`); code != http.StatusOK {
		t.Fatalf("管理员作答：%d", code)
	}
	if code := post(asAdmin, path, `{"choice":"grant","content":"再答一次"}`); code != http.StatusConflict {
		t.Fatalf("不能重复作答：%d", code)
	}
	if get(asAdmin, "/api/questions?status=answered", &rows); len(rows) != 1 || rows[0].FactRef == "" || rows[0].Answer == nil || rows[0].Answer.ExpiresAt == nil {
		t.Fatalf("已答历史带写回的事实与到期：%+v", rows)
	}
	// 共享托管类域：API 层拒绝父域范围，只能按完整主机名授权
	cos, _ := questions.Ask(ctx, client, questions.Request{Kind: "authorization", SubjectKind: "domain", Subject: "sip-1302072249.cos.ap-guangzhou.myqcloud.com", Groups: []uuid.UUID{g.ID}}, time.Now())
	cosPath := "/api/questions/" + cos.Question.ID.String() + "/answer"
	if get(asAdmin, "/api/questions", &rows); !slices.ContainsFunc(rows, func(r questionRow) bool { return r.ID == cos.Question.ID && len(r.Scopes) == 0 }) {
		t.Fatalf("共享域不给父域选项：%+v", rows)
	}
	if code := post(asAdmin, cosPath, `{"choice":"grant","content":"客户桶","scope":"myqcloud.com"}`); code != http.StatusBadRequest {
		t.Fatalf("共享域的父域范围应拒绝：%d", code)
	}
	if code := post(asAdmin, cosPath, `{"choice":"grant","content":"客户桶"}`); code != http.StatusOK {
		t.Fatalf("按完整主机名授权：%d", code)
	}
	// 档位受规矩模板约束：「指向不存在目标的密钥」只允许 human
	var stale, swap string
	for _, r := range rules {
		switch r.BuiltinKey {
		case standingrules.TplStaleConnArchive:
			stale = r.ID.String()
		case standingrules.TplLowMemAddSwap:
			swap = r.ID.String()
		}
	}
	rq, _ := questions.Ask(ctx, client, questions.Request{Kind: "policy", SubjectKind: "rule", Subject: stale, Groups: []uuid.UUID{g.ID}}, time.Now())
	if code := post(asAdmin, "/api/questions/"+rq.Question.ID.String()+"/answer", `{"choice":"rule","ruleId":"`+stale+`","tier":"auto"}`); code != http.StatusBadRequest {
		t.Fatalf("模板不允许的档位应拒绝：%d", code)
	}
	if code := post(asAdmin, "/api/questions/"+rq.Question.ID.String()+"/answer", `{"choice":"rule","ruleId":"`+swap+`","tier":"propose"}`); code != http.StatusBadRequest {
		t.Fatalf("只能调整被问到的规矩：%d", code)
	}
	if code := post(asAdmin, "/api/questions/"+rq.Question.ID.String()+"/answer", `{"choice":"rule","ruleId":"`+stale+`","tier":"human"}`); code != http.StatusOK {
		t.Fatalf("选规矩与档位：%d", code)
	}
}

func TestVoidedQuestionsAndAssetParkAPI(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("lab").SaveX(ctx)
	host := client.Asset.Create().SetHostname("TESTSRV").SetGroupID(g.ID).SaveX(ctx)
	admin := client.User.Create().SetUsername("root").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	analyst := client.User.Create().SetUsername("analyst").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(g.ID).SetUserID(analyst.ID).SetRole("analyst").SaveX(ctx)

	now := time.Now().UTC()
	fResolved := client.Finding.Create().SetGroupID(g.ID).SetAssetID(host.ID).SetKey("collect:silent").SetTitle("静默").
		SetStatus("resolved").SetResolvedAt(now.Add(-2 * time.Hour)).SetResolvedBy("system").SaveX(ctx)
	staleQ := client.Question.Create().SetKind("owner").SetSubjectKind("ip").SetSubject("198.51.100.99").
		SetGroupIds([]uuid.UUID{g.ID}).SetFindingIds([]uuid.UUID{fResolved.ID}).
		SetStatus("open").SetCreatedBy("system").SetCreatedAt(now.Add(-26 * time.Hour)).SetUpdatedAt(now.Add(-26 * time.Hour)).SaveX(ctx)
	if n, err := questions.VoidSweep(ctx, client, now); err != nil || n != 1 {
		t.Fatalf("VoidSweep: n=%d err=%v", n, err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/questions", Control(client, nil))
	mux.Handle("/api/questions/", Control(client, nil))
	mux.Handle("/api/assets", Handler(client, nil, nil, nil, nil, nil, nil))
	mux.Handle("/api/assets/", Handler(client, nil, nil, nil, nil, nil, nil))

	asAdmin := httptest.NewServer(as(admin, mux))
	t.Cleanup(asAdmin.Close)
	asAnalyst := httptest.NewServer(as(analyst, mux))
	t.Cleanup(asAnalyst.Close)

	post := func(s *httptest.Server, path, body string) int {
		t.Helper()
		resp, err := http.Post(s.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// 1. ?status=voided 返回已作废问题，非法 status 返回 400
	resp, err := http.Get(asAdmin.URL + "/api/questions?status=voided")
	if err != nil {
		t.Fatal(err)
	}
	var voidedRows []questionRow
	_ = json.NewDecoder(resp.Body).Decode(&voidedRows)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(voidedRows) != 1 || voidedRows[0].ID != staleQ.ID || voidedRows[0].Answer == nil || voidedRows[0].Answer.Choice != "voided_resolved" {
		t.Fatalf("GET /api/questions?status=voided 返回异常：code=%d rows=%+v", resp.StatusCode, voidedRows)
	}
	badResp, err := http.Get(asAdmin.URL + "/api/questions?status=invalid")
	if err != nil {
		t.Fatal(err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("非法 status 应返回 400：%d", badResp.StatusCode)
	}

	// 2. 停机保留仅管理员可操作，原因必填，GET /api/assets 返回停机保留元数据，取消后恢复
	if code := post(asAnalyst, "/api/assets/"+host.ID.String()+"/park", `{"reason":"测试关机"}`); code != http.StatusForbidden {
		t.Fatalf("非管理员不应允许设置停机保留：%d", code)
	}
	if code := post(asAdmin, "/api/assets/"+host.ID.String()+"/park", `{"reason":"  "}`); code != http.StatusBadRequest {
		t.Fatalf("空原因应返回 400：%d", code)
	}
	if code := post(asAdmin, "/api/assets/"+host.ID.String()+"/park", `{"reason":"测试机平时关机保留"}`); code != http.StatusOK {
		t.Fatalf("管理员设置停机保留应成功：%d", code)
	}
	if code := post(asAdmin, "/api/assets/"+host.ID.String()+"/park", `{"reason":"重复"}`); code != http.StatusConflict {
		t.Fatalf("重复设置停机保留应返回 409：%d", code)
	}

	aResp, err := http.Get(asAdmin.URL + "/api/assets")
	if err != nil {
		t.Fatal(err)
	}
	var assets []struct {
		ID           uuid.UUID  `json:"id"`
		ParkedAt     *time.Time `json:"parkedAt"`
		ParkedBy     *string    `json:"parkedBy"`
		ParkedReason *string    `json:"parkedReason"`
	}
	_ = json.NewDecoder(aResp.Body).Decode(&assets)
	aResp.Body.Close()
	if len(assets) != 1 || assets[0].ParkedAt == nil || assets[0].ParkedBy == nil || *assets[0].ParkedBy != "root" || assets[0].ParkedReason == nil || *assets[0].ParkedReason != "测试机平时关机保留" {
		t.Fatalf("GET /api/assets 应返回停机保留字段：%+v", assets)
	}

	if code := post(asAnalyst, "/api/assets/"+host.ID.String()+"/unpark", `{}`); code != http.StatusForbidden {
		t.Fatalf("非管理员不应允许取消停机保留：%d", code)
	}
	if code := post(asAdmin, "/api/assets/"+host.ID.String()+"/unpark", `{}`); code != http.StatusOK {
		t.Fatalf("管理员取消停机保留应成功：%d", code)
	}
}

//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/changerecords"
	"openxdr/server/internal/closurereview"
	"openxdr/server/internal/hostimport"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/testdb"
	"openxdr/server/internal/triage"
)

func TestChangeRecordsEndToEndAndTrustBoundaries(t *testing.T) {
	ctx, db := testdb.New(t)

	admin := db.User.Create().SetUsername("admin").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	analystA := db.User.Create().SetUsername("analyst-a").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	groupA := db.Group.Create().SetName("net-ops").SaveX(ctx)
	groupB := db.Group.Create().SetName("other-team").SaveX(ctx)
	db.GroupMember.Create().SetGroupID(groupA.ID).SetUserID(analystA.ID).SetRole("viewer").SaveX(ctx)

	gateway := db.Asset.Create().
		SetHostname("gateway").
		SetIPAddrs([]string{"10.1.1.100"}).
		SetGroupID(groupA.ID).
		SaveX(ctx)
	foreignHost := db.Asset.Create().
		SetHostname("foreign-box").
		SetIPAddrs([]string{"10.2.1.50"}).
		SetGroupID(groupB.ID).
		SaveX(ctx)

	commitTS := time.Now().UTC().Truncate(time.Second).Add(-3*time.Hour - 15*time.Minute)
	tooEarlyTS := commitTS.Add(-10 * time.Hour)
	shaMatch := "8c168720abcdef0123456789abcdef0123456789"
	shaTooEarly := "00000000abcdef0123456789abcdef0123456789"
	shaForeign := "99999999abcdef0123456789abcdef0123456789"

	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer github_pat_secret_5678" {
			http.Error(w, `{"message":"Forbidden"}`, http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/repos/ZacharyZcR/RoyalSecurity-Network/commits":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"sha": shaMatch, "commit": map[string]any{"committer": map[string]any{"date": commitTS.Format(time.RFC3339)}}},
				{"sha": shaForeign, "commit": map[string]any{"committer": map[string]any{"date": commitTS.Format(time.RFC3339)}}},
				{"sha": shaTooEarly, "commit": map[string]any{"committer": map[string]any{"date": tooEarlyTS.Format(time.RFC3339)}}},
			})
		case "/repos/ZacharyZcR/RoyalSecurity-Network/commits/" + shaMatch:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sha": shaMatch,
				"commit": map[string]any{
					"message":   "下线 dl 站点，回收 node34-36 的隧道钥与 WireGuard peer\n\n同步更新 gateway 配置",
					"committer": map[string]any{"name": "ZacharyZcR", "date": commitTS.Format(time.RFC3339)},
				},
				"author": map[string]any{"login": "ZacharyZcR"},
				"files":  []map[string]any{{"filename": "configs/gateway/Caddyfile"}},
			})
		case "/repos/ZacharyZcR/RoyalSecurity-Network/commits/" + shaForeign:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sha": shaForeign,
				"commit": map[string]any{
					"message":   "维护 foreign-box 防火墙",
					"committer": map[string]any{"name": "ZacharyZcR", "date": commitTS.Format(time.RFC3339)},
				},
				"files": []map[string]any{{"filename": "hosts/foreign-box.yml"}},
			})
		case "/repos/ZacharyZcR/RoyalSecurity-Network/commits/" + shaTooEarly:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sha": shaTooEarly,
				"commit": map[string]any{
					"message":   "十小时前的旧 gateway 提交",
					"committer": map[string]any{"name": "ZacharyZcR", "date": tooEarlyTS.Format(time.RFC3339)},
				},
				"files": []map[string]any{{"filename": "configs/gateway/Caddyfile"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer gh.Close()

	// 1. 未配 HOST_CREDENTIAL_KEY 时拒绝保存令牌，绝不明文落库。
	noVaultHandler := ChangeRecords(db, nil, nil)
	callHandler := func(h http.Handler, u *ent.User, method, path string, body any) *httptest.ResponseRecorder {
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req = req.WithContext(auth.WithUser(req.Context(), u))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	if w := callHandler(noVaultHandler, analystA, "GET", "/api/system-integrations/change-sources", nil); w.Code != http.StatusForbidden {
		t.Fatalf("非管理员不应访问变更记录源管理接口: %d", w.Code)
	}
	if w := callHandler(noVaultHandler, admin, "POST", "/api/system-integrations/change-sources", map[string]any{
		"repo": "ZacharyZcR/RoyalSecurity-Network", "token": "github_pat_secret_5678", "enabled": true,
	}); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("无 HOST_CREDENTIAL_KEY 时保存 token 应返回 503，实际 %d: %s", w.Code, w.Body.String())
	}

	// 2. 配置 Vault 后创建来源、校验密文不外泄、手动触发同步并校验资产组作用域隔离。
	vault, err := hostimport.NewVault(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	if err != nil {
		t.Fatal(err)
	}
	syncer := &changerecords.Syncer{
		DB:      db,
		Cipher:  ChangeTokenCipher(vault),
		HTTP:    gh.Client(),
		BaseURL: gh.URL,
	}
	h := ChangeRecords(db, vault, syncer)

	w := callHandler(h, admin, "POST", "/api/system-integrations/change-sources", map[string]any{
		"name":    "公司网络配置仓库",
		"repo":    "ZacharyZcR/RoyalSecurity-Network",
		"token":   "github_pat_secret_5678",
		"enabled": true,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("创建变更记录源失败: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "github_pat_secret_5678") {
		t.Fatalf("创建响应泄漏明文令牌: %s", w.Body.String())
	}
	var created changeSourceRow
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !created.HasToken || created.TokenHint != "••••5678" {
		t.Fatalf("令牌状态或尾号提示错误: %+v", created)
	}
	// 审计日志同样不得包含明文令牌。
	for _, al := range db.AuditLog.Query().AllX(ctx) {
		if al.Detail != nil && strings.Contains(*al.Detail, "github_pat_secret_5678") {
			t.Fatalf("审计日志泄漏明文令牌: %s", *al.Detail)
		}
	}

	w = callHandler(h, admin, "POST", "/api/system-integrations/change-sources/"+created.ID.String()+"/sync", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("手动同步失败: %d %s", w.Code, w.Body.String())
	}

	// analystA 属于 groupA：可读 gateway 的关联提交，访问 groupB 的 foreignHost 返回 404。
	w = callHandler(h, analystA, "GET", "/api/assets/"+gateway.ID.String()+"/change-records", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("组内 viewer 读取资产关联变更记录失败: %d %s", w.Code, w.Body.String())
	}
	var assetRows []assetChangeRecordRow
	if err := json.Unmarshal(w.Body.Bytes(), &assetRows); err != nil || len(assetRows) != 2 {
		t.Fatalf("gateway 应关联 2 条提交记录，实际 %d err=%v", len(assetRows), err)
	}
	if w := callHandler(h, analystA, "GET", "/api/assets/"+foreignHost.ID.String()+"/change-records", nil); w.Code != http.StatusNotFound {
		t.Fatalf("跨组资产变更记录应返回 404，实际 %d", w.Code)
	}

	// 3. 验证注入研判（triage）、Pi 调查上下文（agentchat）与独立结案审计（closurereview），以及权威边界不被越过。
	alertTS := commitTS.Add(15 * time.Minute) // 距离事件当前已安静 > 3h，且 commitTS 在 [alertTS-6h, alertTS+2h] 内，tooEarlyTS 在窗口外
	rawEvent := json.RawMessage(`{"activity_id":1,"process":{"cmd_line":"/usr/bin/caddy reload --config /etc/caddy/Caddyfile","pid":2100}}`)
	ev := db.Event.Create().
		SetAssetID(gateway.ID).
		SetSource("agent").
		SetClassUID(1007).
		SetTs(alertTS).
		SetRaw(rawEvent).
		SaveX(ctx)
	title := "gateway 配置重载"
	inc := db.Incident.Create().
		SetTitle(title).
		SetStatus("open").
		SetCreatedAt(alertTS).
		SetGraph(json.RawMessage(`{"nodes":[],"edges":[]}`)).
		SaveX(ctx)
	al := db.Alert.Create().
		SetIncidentID(inc.ID).
		SetAssetID(gateway.ID).
		SetEventID(ev.ID).
		SetRuleID(sigma.RuleNewProcess).
		SetSeverity(2).
		SetCount(1).
		SetTs(alertTS).
		SaveX(ctx)

	// 3a. 跑一次真实 triage 引擎（配 mock OpenAI 端点捕获发送给研判模型的上下文）。
	var triageUserPrompt string
	mockLLMServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		for _, m := range req.Messages {
			if m.Role == "user" {
				triageUserPrompt = m.Content
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"message": map[string]any{
					"role":    "assistant",
					"content": `{"verdict":"benign","confidence":90,"summary":"gateway 执行 Caddy 配置热重载属运维变更\n与同期仓库提交时间吻合","kill_chain":[],"action_codes":["review_closure","monitor"]}`,
				},
			}},
		})
	}))
	defer mockLLMServer.Close()

	triageCtx, cancelTriage := context.WithCancel(ctx)
	engine := &triage.Engine{
		DB:       db,
		LLM:      triage.NewLLM(mockLLMServer.URL+"/v1", "mock-model", "k", 10*time.Second),
		Interval: 20 * time.Millisecond,
	}
	doneTriage := make(chan struct{})
	go func() {
		defer close(doneTriage)
		engine.Run(triageCtx)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cur := db.Incident.GetX(ctx, inc.ID)
		if cur.Status == "triaged" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	cancelTriage()
	<-doneTriage

	if !strings.Contains(triageUserPrompt, changerecords.SourceDisclaimer) || !strings.Contains(triageUserPrompt, "8c168720") {
		t.Fatalf("研判上下文未注入窗口内变更记录或缺少非权威声明:\n%s", triageUserPrompt)
	}
	if strings.Contains(triageUserPrompt, "00000000") {
		t.Fatalf("研判上下文不应包含超过 6 小时窗口的旧提交:\n%s", triageUserPrompt)
	}
	if strings.Contains(triageUserPrompt, "## 权威事实") {
		t.Fatalf("无权威事实时外部变更记录不得混入权威事实章节:\n%s", triageUserPrompt)
	}

	// 3b. 验证窗口查询输出与 ToPromptItems 结构化条目一致（agentchat.incidentSubject 另有包内集成测试）。
	winFrom, winTo, winAssets, ok := changerecords.AlertWindow([]*ent.Alert{al})
	if !ok {
		t.Fatal("AlertWindow 计算失败")
	}
	winRecs, err := changerecords.LookupWindow(ctx, db, winAssets, winFrom, winTo, changerecords.MaxPromptRecords)
	if err != nil || len(winRecs) != 1 || winRecs[0].ShortSHA != "8c168720" {
		t.Fatalf("窗口查询结果异常: %+v err=%v", winRecs, err)
	}

	// 3c. 验证结案审计（closurereview）：
	// 边界一：若告警是高危（severity=4）且只有外部变更记录、没有权威主机事实（asset_role / change），服务端直接拦在门外，绝不放行。
	db.Alert.UpdateOneID(al.ID).SetSeverity(4).ExecX(ctx)
	judgeCalled := 0
	reviewer := &closurereview.Reviewer{
		DB:    db,
		Model: func() string { return "mock-auditor" },
		Judge: func(_ context.Context, _, material string) (closurereview.Decision, error) {
			judgeCalled++
			return closurereview.Decision{Approve: true}, nil
		},
	}
	if approved, err := reviewer.Review(ctx, inc.ID); err != nil || approved || judgeCalled != 0 {
		t.Fatalf("高危告警仅有外部变更记录无权威主机事实时绝不应进入结案审计放行: approved=%v judgeCalled=%d err=%v", approved, judgeCalled, err)
	}

	// 边界二：低危告警进入良性审计时，材料包含 corroborating_changes（独立于 authoritative），但若审计员仅凭提交说明而不给事件字段逐字 claims，服务端照样拒绝。
	db.Alert.UpdateOneID(al.ID).SetSeverity(2).ExecX(ctx)
	var seenMaterial string
	reviewer.Judge = func(_ context.Context, _, material string) (closurereview.Decision, error) {
		judgeCalled++
		seenMaterial = material
		return closurereview.Decision{
			Approve:          true,
			Reason:           "仅凭仓库提交 8c168720 放行",
			PositiveEvidence: "仓库提交说明写明下线 dl 站点并重载 gateway 配置",
			EventIDs:         []uuid.UUID{ev.ID},
			Claims:           []closurereview.Claim{{EventID: ev.ID, Field: "process.cmd_line", Value: "伪造的不匹配命令行"}},
		}, nil
	}
	if approved, err := reviewer.Review(ctx, inc.ID); err != nil || approved {
		t.Fatalf("缺少真实原始事件字段逐字 claims 时即使有变更记录也必须拒绝: approved=%v err=%v", approved, err)
	}
	if !strings.Contains(seenMaterial, `"corroborating_changes"`) || !strings.Contains(seenMaterial, "8c168720") {
		t.Fatalf("结案审计材料未携带 corroborating_changes: %s", seenMaterial)
	}
	if strings.Contains(seenMaterial, `"authoritative"`) {
		t.Fatalf("外部变更记录不得混入结案审计材料的 authoritative 字段: %s", seenMaterial)
	}
}

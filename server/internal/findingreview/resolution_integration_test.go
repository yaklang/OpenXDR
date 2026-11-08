//go:build integration

package findingreview

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/testdb"
)

// stubReviewer 记下复核模型看到的材料与系统提示，按 approve 回复
func stubReviewer(t *testing.T, cmd *ent.Command, approve bool, seen *[]string) (*httptest.Server, func() (string, string, string)) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		*seen = append(*seen, body.Messages[0].Content+"\n---\n"+body.Messages[1].Content)
		reply := fmt.Sprintf(`{"approve":%t,"reason":"按材料复核","proofs":[{"command_id":"%s","quote":"hits=0 window=24h"}]}`, approve, cmd.ID)
		if !approve {
			reply = `{"approve":false,"reason":"按材料复核拒绝"}`
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": reply}, "finish_reason": "stop"}}})
	}))
	return server, func() (string, string, string) { return server.URL, "", "m" }
}

func resolutionFixture(t *testing.T) (*ent.Client, *ent.AgentSession, *ent.Finding, *ent.Command, func(string, time.Duration)) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("pve1").SetGroupID(g.ID).SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("dns-noise").SetTitle("DNS 长随机标签噪声").SaveX(ctx)
	s := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SaveX(ctx)
	c := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("grep -c hypercachenode /var/log/syslog").SetCreatedAt(s.CreatedAt.Add(time.Microsecond)).
		SetCompletedAt(time.Now()).SetStatus("succeeded").SetExitCode(0).SetStdout("hits=0 window=24h").SaveX(ctx)
	alertAt := func(rule string, ago time.Duration) {
		db.Alert.Create().SetAssetID(a.ID).SetRuleID(rule).SetSeverity(2).SetTs(time.Now().Add(-ago)).ExecX(ctx)
	}
	return db, s, f, c, alertAt
}

// 现象消失：安静期由服务端按过去出现间隔自适应计算，未满足时不调用模型
func TestSubsidedAdaptiveQuietPeriod(t *testing.T) {
	db, s, f, c, alertAt := resolutionFixture(t)
	var seen []string
	server, endpoint := stubReviewer(t, c, true, &seen)
	defer server.Close()
	r := &Reviewer{DB: db, Endpoint: endpoint}
	res := findings.Resolution{Kind: "subsided", Rules: []string{"dns-long-label"}}

	if ok, why, err := r.Review(t.Context(), s, f, []*ent.Command{c}, res); ok || err != nil || !strings.Contains(why, "没有告警记录") || len(seen) != 0 {
		t.Fatalf("没有记录不能判定消失: %v %q %v", ok, why, err)
	}
	// 过去每小时出现一次，最后一次 10 小时前：需安静 24 小时（下限），未满足
	for _, h := range []int{10, 11, 12, 13} {
		alertAt("dns-long-label", time.Duration(h)*time.Hour)
	}
	if ok, why, err := r.Review(t.Context(), s, f, []*ent.Command{c}, res); ok || err != nil || !strings.Contains(why, "需安静 24h0m0s") || len(seen) != 0 {
		t.Fatalf("安静期未满足应直接拒绝: %v %q %v", ok, why, err)
	}
	// 再往前有一次间隔 2 天的出现：需安静 6 天
	alertAt("dns-long-label", 61*time.Hour)
	if _, why, _ := r.Review(t.Context(), s, f, []*ent.Command{c}, res); !strings.Contains(why, "需安静 144h") {
		t.Fatalf("安静期应随最长间隔自适应: %q", why)
	}
	// 另一条规则：每小时一次，最后一次 3 天前 → 满足，交模型核对规则与现象
	for _, h := range []int{72, 73, 74} {
		alertAt("other-rule", time.Duration(h)*time.Hour)
	}
	ok, why, err := r.Review(t.Context(), s, f, []*ent.Command{c}, findings.Resolution{Kind: "subsided", Rules: []string{"other-rule"}})
	if !ok || err != nil || len(seen) != 1 || !strings.Contains(seen[0], "现象已不再出现") || !strings.Contains(seen[0], `"required_quiet":"24h0m0s"`) {
		t.Fatalf("安静期满足后交模型复核: %v %q %v %v", ok, why, err, seen)
	}
}

// 本来就不是问题：只附人工来源的环境记忆，AI 写的不进材料
func TestAuthorizedUsesHumanMemoriesOnly(t *testing.T) {
	db, s, f, c, _ := resolutionFixture(t)
	db.Memory.Create().SetGroupID(f.GroupID).SetContent("10.1.1.3 是 WireGuard 出口，运维钥匙经此登录").SetSource("human").SetAuthor("admin").ExecX(t.Context())
	db.Memory.Create().SetGroupID(f.GroupID).SetContent("AI 猜测这是运维脚本").SetSource("ai").SetAuthor("s").ExecX(t.Context())
	var seen []string
	server, endpoint := stubReviewer(t, c, true, &seen)
	defer server.Close()
	r := &Reviewer{DB: db, Endpoint: endpoint}
	if ok, _, err := r.Review(t.Context(), s, f, []*ent.Command{c}, findings.Resolution{Kind: "authorized"}); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if len(seen) != 1 || !strings.Contains(seen[0], "WireGuard 出口") || strings.Contains(seen[0], "AI 猜测") || !strings.Contains(seen[0], "本来就不是问题") {
		t.Fatalf("材料应只含人工记忆: %v", seen)
	}
}

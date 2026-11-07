//go:build integration

package findingreview

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/testdb"
)

func TestRetirementReviewUsesVerifiedDecisionWithoutReplacingEvidence(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("target").SetGroupID(g.ID).SaveX(ctx)
	u := db.User.Create().SetUsername("admin").SetRole("admin").SetPasswordHash("x").SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("retire").SetTitle("旧服务故障").SetWork(findings.EncodeWork(findings.Work{OriginalProblem: "worker.service原来failed"})).SaveX(ctx)
	d, _, err := findings.Delegate(ctx, db, f.ID, u, uuid.New(), "worker.service确认退役，期望inactive/disabled，替代者健康，不重启旧服务", "m", "local", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s := db.AgentSession.GetX(ctx, d.SessionID)
	c := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("systemctl show worker.service").SetCreatedAt(s.CreatedAt.Add(time.Microsecond)).SetCompletedAt(time.Now()).SetStatus("succeeded").SetExitCode(0).SetStdout("Id=worker.service\nActiveState=inactive\nUnitFileState=disabled\nmetis.service ActiveState=active").SaveX(ctx)
	revoke, calls := false, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		var material struct {
			Decision *findings.Decision `json:"operator_decision"`
			Original string             `json:"original_problem"`
		}
		json.Unmarshal([]byte(body.Messages[1].Content), &material)
		if material.Decision == nil || material.Decision.RequestID != d.RequestID || material.Original != "worker.service原来failed" {
			t.Error("决定与原问题没有独立保留", body.Messages[1].Content)
		}
		calls++
		if revoke {
			if err := findings.RevokeDecision(ctx, db, f.ID, "admin", "local"); err != nil {
				t.Error(err)
			}
		}
		reply := fmt.Sprintf(`{"approve":true,"reason":"管理员确认退役，探针证明旧单元已禁用且替代健康","proofs":[{"command_id":"%s","quote":"UnitFileState=disabled"}]}`, c.ID)
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": reply}, "finish_reason": "stop"}}})
	}))
	defer server.Close()
	r := &Reviewer{DB: db, Endpoint: func() (string, string, string) { return server.URL, "", "m" }}
	if ok, _, err := r.Review(ctx, s, f, []*ent.Command{c}); err != nil || !ok {
		t.Fatal(ok, err)
	}
	revoke = true
	if ok, _, err := r.Review(ctx, s, f, []*ent.Command{c}); err == nil || ok {
		t.Fatal("复核期间撤销未阻断批准", ok, err)
	}
	if ok, _, err := r.Review(ctx, s, f, []*ent.Command{c}); err == nil || ok || calls != 2 {
		t.Fatal("撤销后仍送审", ok, err, calls)
	}
}

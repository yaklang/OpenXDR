//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/agentchat"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/testdb"
)

func TestDecisionAPIRequiresGroupAdminAndDoesNotReplay(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("target").SetGroupID(g.ID).SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("retire").SetTitle("退役").SaveX(ctx)
	u := db.User.Create().SetUsername("operator").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	m := db.GroupMember.Create().SetUserID(u.ID).SetGroupID(g.ID).SetRole("admin").SaveX(ctx)
	token := uuid.NewString()
	sum := sha256.Sum256([]byte(token))
	db.Session.Create().SetUserID(u.ID).SetTokenHash(hex.EncodeToString(sum[:])).SetExpiresAt(time.Now().Add(time.Hour)).SaveX(ctx)
	chat := &agentchat.Service{DB: db, AI: func() (string, string, string) { return "", "", "m" }, Runtime: apiPiRunner{}}
	mux := http.NewServeMux()
	mapFindingDecisions(mux, db, chat)
	handler := auth.Middleware(db, mux)
	call := func(method, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/findings/"+f.ID.String()+"/decision", bytes.NewBufferString(body))
		r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	body, _ := json.Marshal(map[string]any{"requestId": uuid.New(), "instruction": "只读验证，已决定的事项不重复等待授权", "expiresAt": time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)})
	w := call("POST", string(body))
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	var first struct {
		Decision findings.Decision `json:"decision"`
		Created  bool              `json:"created"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil || !first.Created {
		t.Fatal(err, w.Body.String())
	}
	defer func() {
		wait, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		chat.Wait(wait)
	}()
	w = call("POST", string(body))
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	var replay struct {
		Decision findings.Decision `json:"decision"`
		Created  bool              `json:"created"`
	}
	json.Unmarshal(w.Body.Bytes(), &replay)
	if replay.Created || replay.Decision.SessionID != first.Decision.SessionID || db.AgentSession.Query().CountX(ctx) != 1 {
		t.Fatal("重复执行", w.Body.String())
	}
	if w = call("GET", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	m.Update().SetRole("analyst").ExecX(ctx)
	if w = call("POST", string(body)); w.Code != 403 {
		t.Fatal("analyst签发了决定", w.Code)
	}
	if w = call("DELETE", ""); w.Code != 403 {
		t.Fatal("analyst撤销了决定", w.Code)
	}
	m.Update().SetRole("admin").ExecX(ctx)
	if w = call("DELETE", ""); w.Code != 204 {
		t.Fatal(w.Code, w.Body.String())
	}
	d, err := findings.LoadDecision(ctx, db, f.ID)
	if err != nil || !d.Revoked {
		t.Fatal(d, err)
	}
	other := db.Group.Create().SetName("new-owner").SaveX(ctx)
	db.GroupMember.Create().SetUserID(u.ID).SetGroupID(other.ID).SetRole("viewer").SaveX(ctx)
	f.Update().SetGroupID(other.ID).ExecX(ctx)
	a.Update().SetGroupID(other.ID).ExecX(ctx)
	if w = call("GET", ""); w.Code != 200 || w.Body.String() != "null\n" {
		t.Fatal("转组后泄露旧组决定", w.Code, w.Body.String())
	}
}

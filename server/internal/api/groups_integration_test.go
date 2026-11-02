//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/commandpolicy"
	"openxdr/server/internal/agentchat"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

type fakeQueries struct{ ensured, dropped []uuid.UUID }

func (f *fakeQueries) URL(context.Context, uuid.UUID) string { return "" }
func (f *fakeQueries) Ensure(_ context.Context, id uuid.UUID) error {
	f.ensured = append(f.ensured, id)
	return nil
}
func (f *fakeQueries) Drop(_ context.Context, id uuid.UUID) error {
	f.dropped = append(f.dropped, id)
	return nil
}

// 建组即带默认高风险名单并开通查询身份；删组连名单与查询身份一起回收。
func TestGroupLifecycleSeedsAndCleansUp(t *testing.T) {
	ctx, client := testdb.New(t)
	queries := &fakeQueries{}
	chat := &agentchat.Service{DB: client, Query: queries}
	ts := httptest.NewServer(asAdmin(Handler(client, nil, loadRules(t), response.NewHub(client, false),
		suppress.New(client, time.Hour), intel.New(client, time.Hour), nil, chat)))
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/api/groups", "application/json", bytes.NewBufferString(`{"name":"web"}`))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("建组失败：%v %v", err, resp.Status)
	}
	var g struct{ ID uuid.UUID }
	if err := json.NewDecoder(resp.Body).Decode(&g); err != nil {
		t.Fatal(err)
	}
	n := client.CommandPolicy.Query().Where(commandpolicy.GroupIDEQ(g.ID), commandpolicy.OriginEQ("ai"), commandpolicy.ModeEQ("deny")).CountX(ctx)
	if n != len(commandgate.DefaultAIDeny) {
		t.Errorf("新组应带 %d 条默认名单，实际 %d", len(commandgate.DefaultAIDeny), n)
	}
	if len(queries.ensured) != 1 || queries.ensured[0] != g.ID {
		t.Errorf("建组应开通查询身份：%v", queries.ensured)
	}

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/groups/"+g.ID.String(), nil)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("删组失败：%v %v", err, resp.Status)
	}
	if n := client.CommandPolicy.Query().Where(commandpolicy.GroupIDEQ(g.ID)).CountX(ctx); n != 0 {
		t.Errorf("删组应清掉名单，剩 %d 条", n)
	}
	if len(queries.dropped) != 1 || queries.dropped[0] != g.ID {
		t.Errorf("删组应回收查询身份：%v", queries.dropped)
	}
}

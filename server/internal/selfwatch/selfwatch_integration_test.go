//go:build integration

package selfwatch

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/alert"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/testdb"
)

// Patroni 动态配置：第一次记基线；改 pg_hba 判 5 级、只改 ttl 判 3 级；没变不报
func TestPatroniConfigChange(t *testing.T) {
	ctx, client := testdb.New(t)
	var mu sync.Mutex
	config := `{"ttl":60,"postgresql":{"pg_hba":["host all all 10.1.1.197/32 scram-sha-256"],"parameters":{"wal_level":"replica"}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = w.Write([]byte(config))
	}))
	t.Cleanup(srv.Close)
	set := func(c string) { mu.Lock(); config = c; mu.Unlock() }
	w := &Watch{DB: client, PatroniURL: srv.URL}
	alerts := func() []string {
		var out []string
		for _, a := range client.Alert.Query().Where(alert.RuleIDEQ(sigma.RuleControlPlaneChange)).Order(alert.ByTs()).AllX(ctx) {
			out = append(out, string(rune('0'+a.Severity))+" "+*a.Detail)
		}
		return out
	}

	for range 2 {
		if err := w.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got := alerts(); len(got) != 0 {
		t.Fatalf("基线与未变化都不报：%v", got)
	}
	set(`{"ttl":60,"postgresql":{"pg_hba":["host all all 10.1.1.0/24 trust"],"parameters":{"wal_level":"replica"}}}`)
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	set(`{"ttl":90,"postgresql":{"pg_hba":["host all all 10.1.1.0/24 trust"],"parameters":{"wal_level":"replica"}}}`)
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	got := alerts()
	if len(got) != 2 || !strings.HasPrefix(got[0], "5 ") || !strings.Contains(got[0], "postgresql.pg_hba") ||
		!strings.HasPrefix(got[1], "3 ") || !strings.Contains(got[1], "ttl") || strings.Contains(got[1], "pg_hba") {
		t.Fatalf("pg_hba 5 级、ttl 3 级，各报一次且基线跟着更新：%v", got)
	}
}

// 核心节点 agent 掉线：报 4 级，一小时内同一台不重复；普通主机掉线、核心节点在线都不报
func TestCoreAgentSilent(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()
	server := json.RawMessage(`[{"process":"openxdr-server","port":8081}]`)
	silent := client.Asset.Create().SetHostname("openxdr-node1").SetAgentID(uuid.New()).SetListening(server).SetLastSeen(now.Add(-20 * time.Minute)).SaveX(ctx)
	client.Asset.Create().SetHostname("openxdr-node2").SetAgentID(uuid.New()).SetListening(server).SetLastSeen(now).SaveX(ctx)
	client.Asset.Create().SetHostname("web").SetAgentID(uuid.New()).SetLastSeen(now.Add(-time.Hour)).SaveX(ctx)
	w := &Watch{DB: client}
	for range 2 {
		if err := w.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got := client.Alert.Query().Where(alert.RuleIDEQ(sigma.RuleCoreAgentSilent)).AllX(ctx)
	if len(got) != 1 || *got[0].AssetID != silent.ID || got[0].Severity != 4 || !strings.Contains(*got[0].Detail, "20 分钟") {
		t.Fatalf("只报掉线的核心节点一次：%+v", got)
	}
}

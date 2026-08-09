//go:build integration

package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/ent"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
)

func testProcessor(t *testing.T) (*Processor, *ent.Client, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("INTEGRATION_DATABASE_URL")
	if dsn == "" {
		t.Skip("INTEGRATION_DATABASE_URL 未配置")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	ctx := context.Background()
	if err := client.Schema.Create(ctx); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	_, _ = db.Exec(`TRUNCATE alert_dedup_state, alerts, events, assets CASCADE`)
	rules := sigma.LoadDir(t.TempDir())
	return &Processor{DB: db, Rules: rules, Suppress: suppress.New(client, 0), Intel: intel.New(client, 0), DedupWindow: time.Hour}, client, db
}

func TestProcessorEventIdempotency(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	e := Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: "asset-a", Timestamp: time.Now(), ClassUID: 1007, Source: "agent", Raw: json.RawMessage(`{"process":{"name":"safe"}}`)}
	if err := p.Process(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if n, _ := client.Event.Query().Count(context.Background()); n != 1 {
		t.Fatalf("重复投递只能落一条事件，实际 %d", n)
	}
}

func TestPersistentDedupAcrossProcessors(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	dir := t.TempDir()
	rule := `title: Test
id: 11111111-1111-4111-8111-111111111111
status: test
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: evil-marker
  condition: selection
level: high
`
	if err := os.WriteFile(filepath.Join(dir, "rule.yml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	p.Rules = sigma.LoadDir(dir)
	p2 := *p
	now := time.Now()
	base := Envelope{Version: EnvelopeVersion, PartitionKey: "asset-a", Timestamp: now, ClassUID: 1007, Source: "agent", AssetOS: "linux", Raw: json.RawMessage(`{"process":{"cmd_line":"evil-marker"}}`)}
	first := base
	first.ID = StableID(t.Name(), "1")
	second := base
	second.ID = StableID(t.Name(), "2")
	second.Timestamp = now.Add(time.Second)
	if err := p.Process(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := p2.Process(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	alerts, err := client.Alert.Query().All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Count != 2 {
		t.Fatalf("跨处理器应合并为一条 count=2 告警，实际 %#v", alerts)
	}
}

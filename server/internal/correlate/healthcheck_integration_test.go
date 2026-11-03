//go:build integration

package correlate

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

// 容器健康检查：agent 标了的告警照常入库、不进 incident，也不给已有 incident 添证据（不触发重研判）；
// 高危例外照常进；syslog 等非 agent 来源自带同样的字段不认；没标的同规则命中单独成告警、照常进
func TestHealthcheckAlertsStayOutOfIncidents(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := ingest.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`TRUNCATE alert_dedup_state`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for i, body := range trustedRules {
		if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(i)+".yml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	catalog := sigma.LoadDir(dir)
	p := &ingest.Processor{DB: db, Rules: catalog, Suppress: suppress.New(client, 0), Intel: intel.New(client, 0), DedupWindow: time.Hour}
	host := client.Asset.Create().SetHostname("docker1").SetOs("linux").SaveX(ctx)
	now := time.Now()

	seq := 0
	// emit 投递一条容器里的进程事件，返回它新建的告警（并进已有告警时返回 nil）
	emit := func(source, cmd string, healthcheck bool) *ent.Alert {
		t.Helper()
		seq++
		c := map[string]any{"runtime": "docker", "uid": "4f1c2a3b5d6e", "name": "guacd"}
		if healthcheck {
			c["healthcheck"] = true
		}
		body, _ := json.Marshal(map[string]any{"process": map[string]any{"cmd_line": cmd}, "container": c})
		id := ingest.StableID(t.Name(), strconv.Itoa(seq))
		e := ingest.Envelope{Version: ingest.EnvelopeVersion, ID: id, PartitionKey: host.ID.String(), AssetID: &host.ID,
			Timestamp: now.Add(time.Duration(seq) * time.Second), ClassUID: 1007, Source: source, AssetOS: "linux", Raw: body}
		if err := p.Process(ctx, e); err != nil {
			t.Fatal(err)
		}
		a, err := client.Alert.Query().Where(alert.EventIDEQ(id)).Only(ctx)
		if ent.IsNotFound(err) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	checked := emit("agent", "recon-marker", true)
	watched := emit("agent", "dump-marker", true)
	plain := emit("agent", "recon-marker", false)
	spoofed := emit("syslog", "dump-marker", true)
	if checked == nil || watched == nil || plain == nil || spoofed == nil {
		t.Fatal("每条都应新建告警：健康检查的告警单独去重，不能吞掉之后的真实命中")
	}
	if !checked.Healthcheck || checked.AutomationWatch {
		t.Fatalf("健康检查的告警应标注且不是高危例外: %+v", checked)
	}
	if !watched.Healthcheck || !watched.AutomationWatch {
		t.Fatalf("凭据窃取类规则是高危例外，应标注且仍进研判: %+v", watched)
	}
	if plain.Healthcheck || spoofed.Healthcheck {
		t.Fatalf("没标的、非 agent 来源的不应认成健康检查: %+v %+v", plain, spoofed)
	}

	eng := &Engine{DB: client, Rules: catalog, Window: 30 * time.Minute, MaxGraphNodes: 50}
	if err := eng.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if got := client.Alert.GetX(ctx, checked.ID); got.IncidentID != nil {
		t.Fatal("健康检查的告警不应进 incident")
	}
	for name, a := range map[string]*ent.Alert{"高危例外": watched, "没标的": plain, "syslog": spoofed} {
		if got := client.Alert.GetX(ctx, a.ID); got.IncidentID == nil {
			t.Fatalf("%s的告警应照常进 incident", name)
		}
	}

	// 之后每轮健康检查：并进同一条告警，不进 incident，也不给已有 incident 添新证据
	inc := client.Incident.GetX(ctx, *client.Alert.GetX(ctx, plain.ID).IncidentID)
	if emit("agent", "recon-marker", true) != nil {
		t.Fatal("同一容器的健康检查应并进已有的健康检查告警")
	}
	if err := eng.batch(ctx); err != nil {
		t.Fatal(err)
	}
	got := client.Alert.GetX(ctx, checked.ID)
	if got.Count != 2 || got.IncidentID != nil {
		t.Fatalf("健康检查告警应累计 2 次且仍不进 incident: %+v", got)
	}
	after := client.Incident.GetX(ctx, inc.ID)
	if !equalTime(after.EvidenceAt, inc.EvidenceAt) || !equalTime(after.UrgentAt, inc.UrgentAt) {
		t.Fatalf("健康检查不应给 incident 添证据（会触发重研判）: %v→%v %v→%v", inc.EvidenceAt, after.EvidenceAt, inc.UrgentAt, after.UrgentAt)
	}
}

func equalTime(a, b *time.Time) bool {
	return (a == nil) == (b == nil) && (a == nil || a.Equal(*b))
}

//go:build integration

package correlate

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/incident"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/review"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/temporal"
	"openxdr/server/internal/testdb"
)

// campaignFile validation/campaign/ 下的回放语料：资产与按事件时间排列的时间线，时间线上另有「研判」标记，
// 把某条事件告警所在的 incident 标成已研判（模拟研判引擎在那一刻给出的结论）
type campaignFile struct {
	Assets []struct {
		Name  string   `json:"name"`
		Group string   `json:"group"`
		IPs   []string `json:"ips"`
	} `json:"assets"`
	Timeline []struct {
		ID       string          `json:"id"`
		At       time.Time       `json:"at"`
		Asset    string          `json:"asset"`
		Class    int             `json:"class"`
		Username string          `json:"username"`
		Repeat   int             `json:"repeat"`
		Every    string          `json:"every"`
		Users    []string        `json:"users"`
		Raw      json.RawMessage `json:"raw"`
		Triage   *struct {
			IncidentOf string `json:"incidentOf"`
			Verdict    string `json:"verdict"`
			Notified   bool   `json:"notified"`
		} `json:"triage"`
	} `json:"timeline"`
}

// replayStep 展开后的一步：一条事件或一次研判标记
type replayStep struct {
	at     time.Time
	event  *ingest.Envelope
	triage func()
}

// 2026-11-02 Prowl 跳板事件的回放验收（validation/campaign/README.md）：真实入库处理器 + 仓库规则与时序规则 + 关联引擎，
// 事件按时间顺序到达，每过一分钟跑一次关联批次。关联与研判的改动都要过这条用例。
func TestCampaignReplayProwlPivot(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := ingest.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`TRUNCATE alert_dedup_state, temporal_matches, temporal_candidates, temporal_evaluation_gaps,
 temporal_detections, lateral_evidence, identity_observations, identity_local_snapshots CASCADE`); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join("..", "..", "..")
	store := &temporal.Store{}
	if err := store.Reload(filepath.Join(root, "rules"), filepath.Join(root, "temporal-rules")); err != nil {
		t.Fatal(err)
	}
	p := &ingest.Processor{DB: db, Temporal: store, Rules: store, Suppress: suppress.New(client, 0), Intel: intel.New(client, 0), DedupWindow: 5 * time.Minute}
	// 与生产默认值一致（main.go）
	eng := &Engine{DB: client, Rules: store, Window: 30 * time.Minute, MaxGraphNodes: 500, RecurSpan: 24 * time.Hour, RecurCoarse: true}

	data, err := os.ReadFile(filepath.Join(root, "validation", "campaign", "2026-11-02-prowl-pivot.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file campaignFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	assets := map[string]*ent.Asset{}
	groups := map[string]uuid.UUID{}
	for _, a := range file.Assets {
		if _, ok := groups[a.Group]; !ok {
			groups[a.Group] = client.Group.Create().SetName(a.Group).SaveX(ctx).ID
		}
		assets[a.Name] = client.Asset.Create().SetHostname(a.Name).SetOs("linux").SetGroupID(groups[a.Group]).SetIPAddrs(a.IPs).SaveX(ctx)
	}

	// 整条时间线平移到「喷洒开始于一小时前」，事件落在测试库现有的日分区里
	var sprayStart time.Time
	for _, item := range file.Timeline {
		if item.ID == "spray-node2" {
			sprayStart = item.At
		}
	}
	shift := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond).Sub(sprayStart)
	ids := map[string][]uuid.UUID{}
	var steps []replayStep
	for _, item := range file.Timeline {
		if item.Triage != nil {
			tr := *item.Triage
			steps = append(steps, replayStep{at: item.At.Add(shift), triage: func() {
				inc := incidentOfEvent(t, client, ids[tr.IncidentOf][0])
				upd := client.Incident.UpdateOneID(inc.ID).SetStatus("triaged").SetTriagedAt(time.Now()).
					SetAiVerdict(json.RawMessage(`{"verdict":"` + tr.Verdict + `"}`))
				if tr.Notified {
					upd.SetNotifiedAt(time.Now())
				}
				upd.ExecX(ctx)
			}})
			continue
		}
		every := time.Duration(0)
		if item.Every != "" {
			if every, err = time.ParseDuration(item.Every); err != nil {
				t.Fatal(err)
			}
		}
		a := assets[item.Asset]
		for i := range max(item.Repeat, 1) {
			raw, user := item.Raw, item.Username
			if len(item.Users) > 0 {
				user = item.Users[i%len(item.Users)]
				var doc map[string]any
				_ = json.Unmarshal(item.Raw, &doc)
				doc["user"] = map[string]any{"name": user}
				raw, _ = json.Marshal(doc)
			}
			id := ingest.StableID(t.Name(), fmt.Sprintf("%s/%d", item.ID, i))
			ids[item.ID] = append(ids[item.ID], id)
			e := ingest.Envelope{Version: ingest.EnvelopeVersion, ID: id, PartitionKey: a.ID.String(), AssetID: &a.ID, AssetOS: "linux",
				Timestamp: item.At.Add(shift + time.Duration(i)*every), ClassUID: item.Class, Source: "agent", Username: user, Raw: raw}
			steps = append(steps, replayStep{at: e.Timestamp, event: &e})
		}
	}
	slices.SortStableFunc(steps, func(a, b replayStep) int { return a.at.Compare(b.at) })

	var last time.Time
	for _, s := range steps {
		if s.at.Sub(last) >= time.Minute || s.triage != nil {
			if err := eng.batch(ctx); err != nil {
				t.Fatal(err)
			}
			last = s.at
		}
		if s.triage != nil {
			s.triage()
			continue
		}
		if err := p.Process(ctx, *s.event); err != nil {
			t.Fatal(err)
		}
	}
	if err := eng.batch(ctx); err != nil {
		t.Fatal(err)
	}

	uos, noise := assets["uos-server"], incidentOfEvent(t, client, ids["dnslog"][0])
	attack := incidentOfEvent(t, client, ids["range-b64-urlopen"][0])
	if attack.ID == noise.ID {
		t.Fatal("跳板容器的告警不应并进 uos-server 的噪声 incident")
	}
	// 跳板容器里每条产出告警的事件都在攻击 incident 里；噪声 incident 里没有容器的告警
	for _, al := range client.Alert.Query().Where(alert.AssetIDEQ(uos.ID), alert.EventIDNotNil()).AllX(ctx) {
		evt := client.Event.GetX(ctx, *al.EventID)
		inRange := containerOf(&ent.Alert{Edges: ent.AlertEdges{Event: evt}}) == "4f173e0d45b0"
		if al.IncidentID == nil {
			t.Fatalf("告警 %s 未归属", al.RuleID)
		}
		if inRange != (*al.IncidentID == attack.ID) {
			t.Errorf("告警 %s（跳板容器=%v）归属错误：%s", alertLabel(eng, al), inRange, al.IncidentID)
		}
	}
	// 受害主机上的告警经受害方证据并进攻击 incident，图上有 uos-server 到各受害主机的横向边
	var g Graph
	attack = client.Incident.GetX(ctx, attack.ID)
	if err := json.Unmarshal(attack.Graph, &g); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"openxdr-node2", "openxdr-node1", "lizhen-dev", "openxdr-test-linux"} {
		victim := assets[name]
		alerts := client.Alert.Query().Where(alert.AssetIDEQ(victim.ID)).AllX(ctx)
		if len(alerts) == 0 {
			t.Fatalf("%s 上没有告警，语料或规则变了", name)
		}
		for _, al := range alerts {
			if al.IncidentID == nil || *al.IncidentID != attack.ID {
				t.Errorf("%s 上的 %s 应并进攻击 incident", name, alertLabel(eng, al))
			}
		}
		if !slices.Contains(g.Edges, Edge{From: "asset:" + uos.ID.String(), To: "asset:" + victim.ID.String(), Rel: "lateral"}) {
			t.Errorf("图上缺 uos-server → %s 的横向边", name)
		}
	}
	// 恰好一条内部横向喷洒，落在 uos-server 上、在攻击 incident 里
	sprays := client.Alert.Query().Where(alert.RuleIDEQ(sigma.RuleLateralSpray)).AllX(ctx)
	if len(sprays) != 1 || sprays[0].AssetID == nil || *sprays[0].AssetID != uos.ID || sprays[0].IncidentID == nil || *sprays[0].IncidentID != attack.ID {
		t.Fatalf("应有恰好一条落在 uos-server、并进攻击 incident 的喷洒告警：%+v", sprays)
	}
	if sprays[0].Detail == nil {
		t.Error("喷洒告警缺 detail")
	} else {
		t.Logf("喷洒告警 detail：%s", *sprays[0].Detail)
	}
	// 升级：最高级别 5，已研判的结论作废、立即重研判，推送标记清掉，复核口径认它
	top := client.Alert.Query().Where(alert.IncidentIDEQ(attack.ID)).Order(ent.Desc(alert.FieldSeverity)).FirstX(ctx)
	if top.Severity != 5 || !review.IsUrgent(attack) || attack.NotifiedAt != nil {
		t.Errorf("攻击 incident 应升到 5 级、立即重研判、待推送：max=%d urgent=%v triaged=%v notified=%v",
			top.Severity, attack.UrgentAt, attack.TriagedAt, attack.NotifiedAt)
	}
	if !client.Incident.Query().Where(incident.IDEQ(attack.ID), review.Needed()).ExistX(ctx) {
		t.Error("攻击 incident 应进需人工复核口径")
	}
}

func incidentOfEvent(t *testing.T, client *ent.Client, event uuid.UUID) *ent.Incident {
	t.Helper()
	al, err := client.Alert.Query().Where(alert.EventIDEQ(event), alert.IncidentIDNotNil()).First(t.Context())
	if err != nil {
		t.Fatalf("事件 %s 没有已归属的告警: %v", event, err)
	}
	return client.Incident.GetX(t.Context(), *al.IncidentID)
}

func alertLabel(eng *Engine, al *ent.Alert) string {
	return eng.alertTitle(al) + "@" + al.Ts.Format(time.TimeOnly)
}

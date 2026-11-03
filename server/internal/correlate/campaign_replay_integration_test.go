//go:build integration

package correlate

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	item   string
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

	// 时间是生产真实时刻，不平移：过去日期的事件落进 events 的默认分区
	ids := map[string][]uuid.UUID{}
	var steps []replayStep
	for _, item := range file.Timeline {
		if item.Triage != nil {
			tr := *item.Triage
			steps = append(steps, replayStep{at: item.At, triage: func() {
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
				Timestamp: item.At.Add(time.Duration(i) * every), ClassUID: item.Class, Source: "agent", Username: user, Raw: raw}
			steps = append(steps, replayStep{at: e.Timestamp, event: &e, item: item.ID})
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
		// 喷洒告警在第三台受害主机（lizhen-dev，23:30:01）的证据到达时才出现；更早的 cache、termix 离得太远，不能凑数
		if s.item == "spray-lizhen" && s.event.ID == ids["spray-lizhen"][0] {
			if n := client.Alert.Query().Where(alert.RuleIDEQ(sigma.RuleLateralSpray)).CountX(ctx); n != 0 {
				t.Fatalf("lizhen-dev 之前不该有喷洒告警，实际 %d 条", n)
			}
		}
		if err := p.Process(ctx, *s.event); err != nil {
			t.Fatal(err)
		}
		if s.item == "spray-lizhen" && s.event.ID == ids["spray-lizhen"][0] {
			spray, err := client.Alert.Query().Where(alert.RuleIDEQ(sigma.RuleLateralSpray)).Only(ctx)
			if err != nil || !spray.Ts.Equal(s.event.Timestamp) || spray.Detail == nil || !strings.Contains(*spray.Detail, "共波及 3 台") {
				t.Fatalf("lizhen-dev 的第一条登录失败应触发喷洒告警（node2、node1、lizhen-dev）：%+v %v", spray, err)
			}
		}
	}
	if err := eng.batch(ctx); err != nil {
		t.Fatal(err)
	}

	uos := assets["uos-server"]
	noise := incidentOfEvent(t, client, ids["ops-whoami"][0])
	early := incidentOfEvent(t, client, ids["range-b64-exec-early"][0])
	attack := incidentOfEvent(t, client, ids["range-b64-urlopen"][0])
	if early.ID == noise.ID || attack.ID == noise.ID || attack.ID == early.ID {
		t.Fatal("跳板容器的两段活动（相隔近 4 小时）应各自成 incident，且都不并进宿主机噪声 incident")
	}
	// uos-server 上：宿主机自身的告警在噪声 incident，跳板容器 18 点那段在 early、22 点以后在 attack，别的容器都不进这三个
	for _, al := range client.Alert.Query().Where(alert.AssetIDEQ(uos.ID), alert.EventIDNotNil()).AllX(ctx) {
		evt := client.Event.GetX(ctx, *al.EventID)
		if al.IncidentID == nil {
			t.Fatalf("告警 %s 未归属", alertLabel(eng, al))
		}
		want := uuid.Nil
		switch c := containerOf(&ent.Alert{Edges: ent.AlertEdges{Event: evt}}); {
		case c == "":
			want = noise.ID
		case c == "4f173e0d45b0" && al.Ts.Before(time.Date(2026, 11, 2, 20, 0, 0, 0, time.UTC)):
			want = early.ID
		case c == "4f173e0d45b0":
			want = attack.ID
		}
		if got := *al.IncidentID; want != uuid.Nil && got != want || want == uuid.Nil && (got == noise.ID || got == early.ID || got == attack.ID) {
			t.Errorf("告警 %s 归属错误：%s", alertLabel(eng, al), got)
		}
	}
	// 受害主机上的告警经受害方证据并进当时跳板所在的 incident，图上有 uos-server 到各受害主机的横向边
	for inc, victims := range map[*ent.Incident][]string{
		early:  {"cache", "termix"},
		attack: {"openxdr-node2", "openxdr-node1", "lizhen-dev", "openxdr-test-linux", "dynamicdefend-v2"},
	} {
		var g Graph
		if err := json.Unmarshal(client.Incident.GetX(ctx, inc.ID).Graph, &g); err != nil {
			t.Fatal(err)
		}
		for _, name := range victims {
			victim := assets[name]
			alerts := client.Alert.Query().Where(alert.AssetIDEQ(victim.ID)).AllX(ctx)
			if len(alerts) == 0 {
				t.Fatalf("%s 上没有告警，语料或规则变了", name)
			}
			for _, al := range alerts {
				if al.IncidentID == nil || *al.IncidentID != inc.ID {
					t.Errorf("%s 上的 %s 应并进 %s", name, alertLabel(eng, al), inc.ID)
				}
			}
			if !slices.Contains(g.Edges, Edge{From: "asset:" + uos.ID.String(), To: "asset:" + victim.ID.String(), Rel: "lateral"}) {
				t.Errorf("图上缺 uos-server → %s 的横向边", name)
			}
		}
	}
	// 恰好一条内部横向喷洒：落在 uos-server、在攻击 incident 里；00:22 的两台受害主机距首条 53 分钟，仍在 60 分钟去重窗口内，
	// 并进同一条：计数是达到阈值后的证据事件数（lizhen-dev 3 + dynamicdefend-v2 11；openxdr-test-linux 那时回看只有两台，不计），
	// detail 列出首条前 60 分钟以来的全部受害主机。cache、termix 在 18:49，不在其中
	sprays := client.Alert.Query().Where(alert.RuleIDEQ(sigma.RuleLateralSpray)).AllX(ctx)
	if len(sprays) != 1 || sprays[0].AssetID == nil || *sprays[0].AssetID != uos.ID || sprays[0].IncidentID == nil || *sprays[0].IncidentID != attack.ID {
		t.Fatalf("应有恰好一条落在 uos-server、并进攻击 incident 的喷洒告警：%+v", sprays)
	}
	spray := sprays[0]
	dd := ids["spray-dynamicdefend"]
	lastDD := client.Event.GetX(ctx, dd[len(dd)-1]).Ts
	if spray.Count != 14 || spray.LastTs == nil || !spray.LastTs.Equal(lastDD) {
		t.Errorf("喷洒告警计数或最近时间不对：count=%d last=%v，期望 14、%v", spray.Count, spray.LastTs, lastDD)
	}
	if spray.Detail == nil {
		t.Fatal("喷洒告警缺 detail")
	}
	t.Logf("喷洒告警 detail：%s", *spray.Detail)
	for _, want := range []string{"共波及 5 台", "10.1.1.197 ×55", "10.1.1.198 ×80", "10.1.1.183 ×3", "10.1.1.137 ×180", "10.1.1.32 ×11"} {
		if !strings.Contains(*spray.Detail, want) {
			t.Errorf("detail 缺 %q", want)
		}
	}
	if strings.Contains(*spray.Detail, "10.1.1.30 ") || strings.Contains(*spray.Detail, "10.1.1.35 ") {
		t.Error("18:49 的 cache、termix 不在窗口内，不该列进 detail")
	}
	attack = client.Incident.GetX(ctx, attack.ID)
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

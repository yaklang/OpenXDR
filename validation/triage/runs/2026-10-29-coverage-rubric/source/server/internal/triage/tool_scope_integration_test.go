//go:build integration

package triage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/internal/testdb"
)

func scopedToolEngine(ctx context.Context, db *ent.Client, host uuid.UUID) *Engine {
	inc := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(host).SetRuleID("scope-fixture").SetSeverity(1).SetTs(time.Now().AddDate(-1, 0, 0)).SaveX(ctx)
	return &Engine{DB: db, investigationID: inc.ID}
}

func TestInvestigationToolsRespectIncidentGroups(t *testing.T) {
	ctx, db := testdb.New(t)
	ga := db.Group.Create().SetName("a").SaveX(ctx)
	gb := db.Group.Create().SetName("b").SaveX(ctx)
	a := db.Asset.Create().SetHostname("allowed-host").SetGroupID(ga.ID).SaveX(ctx)
	b := db.Asset.Create().SetHostname("secret-host").SetGroupID(gb.ID).SaveX(ctx)
	root, foreignParent := uuid.New(), uuid.New()
	add := func(host *ent.Asset, guid uuid.UUID, parent *uuid.UUID, message string) {
		q := db.Event.Create().SetAssetID(host.ID).SetTs(time.Now()).SetClassUID(1007).SetSource("agent").SetProcessGUID(guid).SetRaw(json.RawMessage(`{"message":"scope-marker ` + message + `"}`))
		if parent != nil {
			q.SetParentProcessGUID(*parent)
		}
		q.SaveX(ctx)
	}
	add(a, root, &foreignParent, "allowed-record")
	add(b, foreignParent, nil, "secret-parent")
	add(b, uuid.New(), &root, "secret-child")
	unassigned := db.Asset.Create().SetHostname("secret-unassigned").SaveX(ctx)
	add(unassigned, uuid.New(), nil, "secret-unassigned")
	db.Event.Create().SetTs(time.Now()).SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(`{"message":"scope-marker secret-orphan"}`)).SaveX(ctx)
	db.Alert.Create().SetAssetID(b.ID).SetRuleID("secret-rule").SetSeverity(3).SetTs(time.Now()).SaveX(ctx)
	db.ProcessBaseline.Create().SetAssetID(b.ID).SetExePath("/bin/secret").SetFirstSeen(time.Now()).SaveX(ctx)
	e := scopedToolEngine(ctx, db, a.ID)
	for _, mode := range []string{"indexed", "raw"} {
		result := e.execTool(ctx, "query_events", fmt.Sprintf(`{"keyword":"scope-marker","mode":%q,"group_id":%q,"incident_id":%q}`, mode, gb.ID, uuid.New()))
		if strings.Contains(result, "secret-") || !strings.Contains(result, "allowed-record") {
			t.Errorf("事件检索跨组: %s", result)
		}
	}
	result := e.execTool(ctx, "process_lineage", fmt.Sprintf(`{"process_guid":%q}`, root))
	if strings.Contains(result, "secret-") || !strings.Contains(result, "allowed-record") || !strings.Contains(result, `"missing_ancestor":true`) {
		t.Errorf("血缘查询跨组: %s", result)
	}
	for tool, args := range map[string]string{"host_alerts": fmt.Sprintf(`{"asset_id":%q}`, b.ID), "process_baseline": fmt.Sprintf(`{"asset_id":%q,"exe_path":"/bin/secret"}`, b.ID)} {
		result := e.execTool(ctx, tool, args)
		if !strings.Contains(result, `"status":"error"`) || strings.Contains(result, "secret-host") || strings.Contains(result, "secret-rule") {
			t.Errorf("%s 未拒绝组外资产: %s", tool, result)
		}
	}
	for _, unbound := range []*Engine{{DB: db}, {DB: db, investigationID: uuid.New()}} {
		for tool, args := range map[string]string{
			"query_events":     `{"keyword":"scope-marker"}`,
			"process_lineage":  fmt.Sprintf(`{"process_guid":%q}`, root),
			"host_alerts":      fmt.Sprintf(`{"asset_id":%q}`, a.ID),
			"process_baseline": fmt.Sprintf(`{"asset_id":%q,"exe_path":"/bin/tool"}`, a.ID),
		} {
			result := unbound.execTool(ctx, tool, args)
			if !strings.Contains(result, `"status":"error"`) {
				t.Errorf("%s 无范围仍执行: %s", tool, result)
			}
		}
	}
	peer := db.Asset.Create().SetHostname("allowed-peer").SetGroupID(ga.ID).SaveX(ctx)
	db.ProcessBaseline.Create().SetAssetID(peer.ID).SetExePath("/bin/tool").SetFirstSeen(time.Now()).SaveX(ctx)
	result = e.execTool(ctx, "process_baseline", fmt.Sprintf(`{"asset_id":%q,"exe_path":"/bin/tool"}`, peer.ID))
	if !strings.Contains(result, `"baseline_status":"recorded"`) {
		t.Errorf("同组基线被误拒绝: %s", result)
	}
	// 同一个 Engine 再次调用必须使用最新资产归组。
	db.Asset.UpdateOne(a).SetGroupID(gb.ID).ExecX(ctx)
	result = e.execTool(ctx, "host_alerts", fmt.Sprintf(`{"asset_id":%q}`, b.ID))
	if !strings.Contains(result, "secret-rule") || strings.Contains(result, `"status":"error"`) {
		t.Errorf("转组后未刷新范围: %s", result)
	}
}

func TestTriageToolScopeDoesNotCarryAcrossIncidents(t *testing.T) {
	ctx, db := testdb.New(t)
	var ids []uuid.UUID
	for _, name := range []string{"group-a", "group-b"} {
		group := db.Group.Create().SetName(name).SaveX(ctx)
		host := db.Asset.Create().SetHostname(name).SetGroupID(group.ID).SaveX(ctx)
		ids = append(ids, scopedToolEngine(ctx, db, host.ID).investigationID)
		raw, _ := json.Marshal(map[string]string{"message": "scope-marker " + name})
		db.Event.Create().SetAssetID(host.ID).SetTs(time.Now()).SetClassUID(1007).SetSource("agent").SetRaw(raw).SaveX(ctx)
	}
	calls := 0
	var results []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req struct {
			Messages []Message `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		msg := Message{Role: "assistant", Content: `{"verdict":"suspicious","confidence":60,"summary":"来源待核实","action_codes":["monitor"],"evidence_claims":[{"evidence_id":"query-1","field":"status","value":"ok"}]}`}
		if calls%2 == 1 {
			var call ToolCall
			call.ID, call.Type, call.Function.Name, call.Function.Arguments = "query", "function", "query_events", `{"keyword":"scope-marker"}`
			msg.Content, msg.ToolCalls = "", []ToolCall{call}
		} else {
			for _, m := range req.Messages {
				if m.Role == "tool" {
					results = append(results, m.Content)
				}
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": msg}}})
	}))
	defer srv.Close()
	e := Engine{DB: db, LLM: NewLLM(srv.URL, "test", "", time.Second)}
	for _, id := range ids {
		if err := e.triageOne(ctx, db.Incident.GetX(ctx, id)); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 4 || len(results) != 2 || e.investigationID != uuid.Nil {
		t.Fatalf("运行绑定污染共享 Engine: calls=%d results=%v", calls, results)
	}
	if !strings.Contains(results[0], "group-a") || strings.Contains(results[0], "group-b") || !strings.Contains(results[1], "group-b") || strings.Contains(results[1], "group-a") {
		t.Fatalf("生产研判调用链跨组: %v", results)
	}
}

func TestTriageRejectsChangedMembership(t *testing.T) {
	for _, withTool := range []bool{false, true} {
		t.Run(fmt.Sprintf("tool=%v", withTool), func(t *testing.T) {
			ctx, db := testdb.New(t)
			ga := db.Group.Create().SetName("before").SaveX(ctx)
			gb := db.Group.Create().SetName("after").SaveX(ctx)
			host := db.Asset.Create().SetHostname("moving").SetGroupID(ga.ID).SaveX(ctx)
			scoped := scopedToolEngine(ctx, db, host.ID)
			inc := db.Incident.GetX(ctx, scoped.investigationID)
			calls, callbacks := 0, 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if err := db.Asset.UpdateOne(host).SetGroupID(gb.ID).Exec(ctx); err != nil {
					t.Error(err)
				}
				msg := Message{Role: "assistant", Content: `{"verdict":"benign","confidence":80,"summary":"旧范围的结果","action_codes":["monitor"]}`}
				if withTool {
					var call ToolCall
					call.ID, call.Type, call.Function.Name, call.Function.Arguments = "query", "function", "query_events", `{"keyword":"moving"}`
					msg.Content, msg.ToolCalls = "", []ToolCall{call}
				}
				json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": msg}}})
			}))
			defer srv.Close()
			e := Engine{DB: db, LLM: NewLLM(srv.URL, "test", "", time.Second), OnVerdict: func(context.Context, uuid.UUID, json.RawMessage) { callbacks++ }}
			err := e.triageOne(ctx, inc)
			if !errors.Is(err, errInvestigationScopeChanged) {
				t.Fatalf("应中止已失效范围: %v", err)
			}
			fresh := db.Incident.GetX(ctx, inc.ID)
			if len(fresh.AiVerdict) != 0 || fresh.TriagedAt != nil || fresh.TriageCount != 0 || callbacks != 0 || calls != 1 {
				t.Fatalf("旧范围结果生效: verdict=%s count=%d callbacks=%d calls=%d", fresh.AiVerdict, fresh.TriageCount, callbacks, calls)
			}
		})
	}
}

func TestInvestigationScopeChangeCannotBeUndoneWithinRun(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("destination").SaveX(ctx)
	host := db.Asset.Create().SetHostname("moving").SaveX(ctx)
	e := scopedToolEngine(ctx, db, host.ID)
	var err error
	e.investigationMembers, err = e.investigationMembership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	db.Asset.UpdateOne(host).SetGroupID(group.ID).ExecX(ctx)
	if !errors.Is(e.checkInvestigationScope(ctx), errInvestigationScopeChanged) {
		t.Fatal("未发现转组")
	}
	db.Asset.UpdateOne(host).ClearGroupID().ExecX(ctx)
	if !errors.Is(e.checkInvestigationScope(ctx), errInvestigationScopeChanged) {
		t.Fatal("转回原组不应恢复旧轮次")
	}
}

// 在最终 Update 前停住研判，验证范围检查后资产转组必须等本轮事务结束。
func TestTriagePersistenceLocksIncidentAssets(t *testing.T) {
	ctx, db := testdb.New(t)
	ga := db.Group.Create().SetName("before").SaveX(ctx)
	gb := db.Group.Create().SetName("after").SaveX(ctx)
	host := db.Asset.Create().SetHostname("moving").SetGroupID(ga.ID).SaveX(ctx)
	inc := db.Incident.GetX(ctx, scopedToolEngine(ctx, db, host.ID).investigationID)
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	db.Incident.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			mutation, ok := m.(*ent.IncidentMutation)
			if ok {
				if _, present := mutation.AiVerdict(); present {
					close(reached)
					select {
					case <-release:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
			}
			return next.Mutate(ctx, m)
		})
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": Message{Role: "assistant", Content: `{"verdict":"suspicious","confidence":60,"summary":"来源待核实","action_codes":["monitor"]}`}}}})
	}))
	defer srv.Close()
	e := Engine{DB: db, LLM: NewLLM(srv.URL, "test", "", time.Second)}
	runCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.triageOne(runCtx, inc) }()
	select {
	case <-reached:
	case err := <-done:
		t.Fatalf("未到提交检查点: %v", err)
	case <-runCtx.Done():
		t.Fatal(runCtx.Err())
	}
	seed := db.Alert.Query().Where(alert.IncidentIDEQ(inc.ID)).OnlyX(ctx)
	for name, mutate := range map[string]func(context.Context) error{
		"资产转组":   func(ctx context.Context) error { return db.Asset.UpdateOneID(host.ID).SetGroupID(gb.ID).Exec(ctx) },
		"告警移出":   func(ctx context.Context) error { return db.Alert.UpdateOneID(seed.ID).ClearIncidentID().Exec(ctx) },
		"告警清除资产": func(ctx context.Context) error { return db.Alert.UpdateOneID(seed.ID).ClearAssetID().Exec(ctx) },
		"新增关联": func(ctx context.Context) error {
			return db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(host.ID).SetRuleID("late").SetSeverity(1).SetTs(time.Now()).Exec(ctx)
		},
	} {
		moveCtx, moveCancel := context.WithTimeout(ctx, 200*time.Millisecond)
		err := mutate(moveCtx)
		expired := errors.Is(moveCtx.Err(), context.DeadlineExceeded)
		moveCancel()
		if err == nil || !expired {
			t.Errorf("%s 未等待事务结束: %v", name, err)
		}
	}
	unblock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := db.Asset.UpdateOneID(host.ID).SetGroupID(gb.ID).Exec(ctx); err != nil {
		t.Fatalf("提交后应释放资产锁: %v", err)
	}
}

func TestInvestigationTracksReferencedPeers(t *testing.T) {
	for _, tool := range []string{"query_events", "process_lineage", "host_alerts", "process_baseline"} {
		t.Run(tool, func(t *testing.T) {
			ctx, db := testdb.New(t)
			group := db.Group.Create().SetName("allowed").SaveX(ctx)
			other := db.Group.Create().SetName("other").SaveX(ctx)
			host := db.Asset.Create().SetHostname("incident").SetGroupID(group.ID).SaveX(ctx)
			peer := db.Asset.Create().SetHostname("peer").SetGroupID(group.ID).SaveX(ctx)
			unrelated := db.Asset.Create().SetHostname("unused").SetGroupID(group.ID).SaveX(ctx)
			guid := uuid.New()
			db.Event.Create().SetAssetID(peer.ID).SetProcessGUID(guid).SetTs(time.Now()).SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(`{"message":"peer-marker"}`)).ExecX(ctx)
			db.ProcessBaseline.Create().SetAssetID(peer.ID).SetExePath("/bin/tool").SetFirstSeen(time.Now()).ExecX(ctx)
			e := scopedToolEngine(ctx, db, host.ID)
			var err error
			e.investigationMembers, err = e.investigationMembership(ctx)
			if err != nil {
				t.Fatal(err)
			}
			args := map[string]string{
				"query_events":     `{"keyword":"peer-marker"}`,
				"process_lineage":  fmt.Sprintf(`{"process_guid":%q}`, guid),
				"host_alerts":      fmt.Sprintf(`{"asset_id":%q}`, peer.ID),
				"process_baseline": fmt.Sprintf(`{"asset_id":%q,"exe_path":"/bin/tool"}`, peer.ID),
			}
			result := e.execTool(ctx, tool, args[tool])
			if strings.Contains(result, `"status":"error"`) || e.investigationReferences[peer.ID] != group.ID.String() {
				t.Fatalf("未记录实际引用: %s refs=%v", result, e.investigationReferences)
			}
			db.Asset.UpdateOne(unrelated).SetGroupID(other.ID).ExecX(ctx)
			if err := e.checkInvestigationScope(ctx); err != nil {
				t.Fatalf("未引用资产不应中止研判: %v", err)
			}
			db.Asset.UpdateOne(peer).SetGroupID(other.ID).ExecX(ctx)
			if !errors.Is(e.checkInvestigationScope(ctx), errInvestigationScopeChanged) {
				t.Fatal("引用资产转组后仍接受旧证据")
			}
		})
	}
}

func TestInvestigationReferenceLocksAndDeletion(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("allowed").SaveX(ctx)
	host := db.Asset.Create().SetHostname("incident").SetGroupID(group.ID).SaveX(ctx)
	peer := db.Asset.Create().SetHostname("peer").SetGroupID(group.ID).SaveX(ctx)
	e := scopedToolEngine(ctx, db, host.ID)
	var err error
	e.investigationMembers, err = e.investigationMembership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.investigationAsset(ctx, peer.ID); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	scoped := *e
	scoped.DB = tx.Client()
	if err := scoped.lockInvestigationScope(ctx); err != nil {
		t.Fatal(err)
	}
	moveCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	err = db.Asset.UpdateOne(peer).ClearGroupID().Exec(moveCtx)
	expired := errors.Is(moveCtx.Err(), context.DeadlineExceeded)
	cancel()
	if err == nil || !expired {
		t.Fatalf("引用资产未被锁定: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := db.Asset.DeleteOne(peer).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(e.checkInvestigationScope(ctx), errInvestigationScopeChanged) {
		t.Fatal("引用资产被删除后仍接受旧证据")
	}
}

func TestTriageRejectsMovedReferenceBeforePersistence(t *testing.T) {
	for _, history := range []bool{false, true} {
		t.Run(fmt.Sprintf("history=%v", history), func(t *testing.T) {
			ctx, db := testdb.New(t)
			group := db.Group.Create().SetName("allowed").SaveX(ctx)
			other := db.Group.Create().SetName("other").SaveX(ctx)
			host := db.Asset.Create().SetHostname("incident").SetGroupID(group.ID).SaveX(ctx)
			peer := db.Asset.Create().SetHostname("peer").SetGroupID(group.ID).SaveX(ctx)
			scoped := scopedToolEngine(ctx, db, host.ID)
			inc := db.Incident.GetX(ctx, scoped.investigationID)
			if history {
				old := db.Incident.Create().SetTitle("reference-marker").SetGraph(json.RawMessage(`{}`)).SetStatus("false_positive").SetResolvedBy("analyst").SetResolvedAt(time.Now()).SetResolution("案例范围内的人工判断").SaveX(ctx)
				db.Alert.Create().SetIncidentID(old.ID).SetAssetID(peer.ID).SetRuleID("scope-fixture").SetSeverity(1).SetTs(time.Now()).ExecX(ctx)
			}
			calls, callbacks := 0, 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var req struct {
					Messages []Message `json:"messages"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
					return
				}
				msg := Message{Role: "assistant", Content: `{"verdict":"suspicious","confidence":60,"summary":"引用仍需核实","action_codes":["monitor"]}`}
				if !history && calls == 1 {
					var call ToolCall
					call.ID, call.Type, call.Function.Name, call.Function.Arguments = "query", "function", "host_alerts", fmt.Sprintf(`{"asset_id":%q}`, peer.ID)
					msg.Content, msg.ToolCalls = "", []ToolCall{call}
				} else {
					data, _ := json.Marshal(req.Messages)
					if history && !strings.Contains(string(data), "reference-marker") {
						t.Error("模型未收到历史参考，测试无效")
					}
					if !history {
						found := false
						for _, m := range req.Messages {
							if m.Role == "tool" && strings.Contains(m.Content, `"status":"ok"`) {
								found = true
							}
						}
						if !found {
							t.Error("模型未收到工具证据，测试无效")
						}
						msg.Content = `{"verdict":"suspicious","confidence":60,"summary":"引用仍需核实","action_codes":["monitor"],"evidence_claims":[{"evidence_id":"query-1","field":"status","value":"ok"}]}`
					}
					if err := db.Asset.UpdateOne(peer).SetGroupID(other.ID).Exec(ctx); err != nil {
						t.Error(err)
					}
				}
				json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": msg}}})
			}))
			defer srv.Close()
			e := Engine{DB: db, LLM: NewLLM(srv.URL, "test", "", time.Second), OnVerdict: func(context.Context, uuid.UUID, json.RawMessage) { callbacks++ }}
			if err := e.triageOne(ctx, inc); !errors.Is(err, errInvestigationScopeChanged) {
				t.Fatalf("引用转组应中止: %v", err)
			}
			fresh := db.Incident.GetX(ctx, inc.ID)
			if len(fresh.AiVerdict) != 0 || fresh.TriageCount != 0 || callbacks != 0 {
				t.Fatalf("旧引用结果生效: %s callbacks=%d", fresh.AiVerdict, callbacks)
			}
			if len(e.investigationReferences) != 0 {
				t.Fatal("共享 Engine 留下跨轮引用")
			}
		})
	}
}

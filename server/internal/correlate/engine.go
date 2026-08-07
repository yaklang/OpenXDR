// Package correlate 关联引擎：周期性把未归属的告警聚合成 incident。
// MVP 策略：同一资产、时间窗口内的告警归入同一个 open/triaged incident。
package correlate

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/incident"
	"openxdr/server/internal/sigma"
)

type Engine struct {
	DB            *ent.Client
	Rules         *sigma.Engine
	Window        time.Duration
	Interval      time.Duration
	MaxGraphNodes int
}

func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(e.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.batch(ctx); err != nil {
				slog.Error("关联批次失败", "err", err)
			}
		}
	}
}

func (e *Engine) batch(ctx context.Context) error {
	pending, err := e.DB.Alert.Query().
		Where(alert.IncidentIDIsNil()).
		Order(ent.Asc(alert.FieldTs)).
		Limit(500).
		WithEvent().
		WithAsset().
		All(ctx)
	if err != nil || len(pending) == 0 {
		return err
	}

	// 批内同资产的告警直接命中内存里的 incident，不用回查数据库
	byAsset := map[uuid.UUID]*ent.Incident{}
	graphs := map[uuid.UUID]*Graph{}
	assign := map[uuid.UUID][]uuid.UUID{}
	reopen := map[uuid.UUID]bool{}

	for _, al := range pending {
		var inc *ent.Incident
		if al.AssetID != nil {
			if cached, ok := byAsset[*al.AssetID]; ok {
				inc = cached
			} else if found, err := e.findOpen(ctx, *al.AssetID, al.Ts.Add(-e.Window)); err == nil {
				inc = found
			}
		}
		if inc == nil {
			hostname := "unknown"
			if al.Edges.Asset != nil {
				hostname = al.Edges.Asset.Hostname
			}
			title := fmt.Sprintf("%s @ %s", e.ruleTitle(al.RuleID), hostname)
			inc, err = e.DB.Incident.Create().
				SetGraph(json.RawMessage("{}")).
				SetTitle(title).
				Save(ctx)
			if err != nil {
				return err
			}
		}
		if al.AssetID != nil {
			byAsset[*al.AssetID] = inc
		}
		// 已研判的 incident 收到新证据：重开，研判引擎会带新证据重新定性
		if inc.Status == "triaged" {
			reopen[inc.ID] = true
		}

		g, ok := graphs[inc.ID]
		if !ok {
			g = parseGraph(inc.Graph)
			graphs[inc.ID] = g
		}
		e.attach(g, al)
		assign[inc.ID] = append(assign[inc.ID], al.ID)
	}

	for incID, g := range graphs {
		upd := e.DB.Incident.UpdateOneID(incID).SetGraph(g.raw())
		if reopen[incID] {
			upd.SetStatus("open")
		}
		if err := upd.Exec(ctx); err != nil {
			return err
		}
		if err := e.DB.Alert.Update().
			Where(alert.IDIn(assign[incID]...)).
			SetIncidentID(incID).
			Exec(ctx); err != nil {
			return err
		}
	}
	slog.Info("关联完成", "alerts", len(pending), "incidents", len(graphs))
	return nil
}

func (e *Engine) findOpen(ctx context.Context, assetID uuid.UUID, since time.Time) (*ent.Incident, error) {
	al, err := e.DB.Alert.Query().
		Where(
			alert.AssetIDEQ(assetID),
			alert.TsGTE(since),
			alert.IncidentIDNotNil(),
			alert.HasIncidentWith(incident.StatusIn("open", "triaged")),
		).
		Order(ent.Desc(alert.FieldTs)).
		WithIncident().
		First(ctx)
	if err != nil {
		return nil, err
	}
	return al.Edges.Incident, nil
}

func (e *Engine) attach(g *Graph, al *ent.Alert) {
	// 风暴防线：图触顶后只累加溢出计数，不再无限膨胀
	if len(g.Nodes) >= e.MaxGraphNodes {
		g.Overflow++
		return
	}

	assetNode := ""
	if al.AssetID != nil {
		assetNode = "asset:" + al.AssetID.String()
		hostname := "unknown"
		if al.Edges.Asset != nil {
			hostname = al.Edges.Asset.Hostname
		}
		g.ensureNode(assetNode, "asset", hostname)
	}

	alertNode := "alert:" + al.ID.String()
	g.ensureNode(alertNode, "alert", e.ruleTitle(al.RuleID))

	if evt := al.Edges.Event; evt != nil {
		procNode := "event:" + evt.ID.String()
		if evt.ProcessGUID != nil {
			procNode = "process:" + evt.ProcessGUID.String()
		}
		g.ensureNode(procNode, "process", processLabel(evt))
		if assetNode != "" {
			g.ensureEdge(assetNode, procNode, "hosts")
		}
		g.ensureEdge(procNode, alertNode, "triggered")
	} else if assetNode != "" {
		g.ensureEdge(assetNode, alertNode, "triggered")
	}
}

func (e *Engine) ruleTitle(ruleID string) string {
	if title := e.Rules.TitleOf(ruleID); title != "" {
		return title
	}
	return ruleID
}

func processLabel(evt *ent.Event) string {
	var raw struct {
		Process struct {
			PID  *int64 `json:"pid"`
			Name string `json:"name"`
		} `json:"process"`
	}
	if json.Unmarshal(evt.Raw, &raw) != nil || raw.Process.Name == "" {
		return "process"
	}
	if raw.Process.PID != nil {
		return fmt.Sprintf("%s (%d)", raw.Process.Name, *raw.Process.PID)
	}
	return raw.Process.Name
}

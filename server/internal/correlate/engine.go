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
		// 匹配不到资产的告警（例如探针看到的外部 IP）统一归到 uuid.Nil 这个桶，
		// 否则每条都自成一个 incident，等于自己制造事件风暴
		bucket := uuid.Nil
		if al.AssetID != nil {
			bucket = *al.AssetID
		}

		var inc *ent.Incident
		if cached, ok := byAsset[bucket]; ok {
			inc = cached
		} else if found, err := e.findOpen(ctx, al.AssetID, al.Ts.Add(-e.Window)); err == nil {
			inc = found
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
		byAsset[bucket] = inc
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

// findOpen 找同一归属桶在时间窗内最近的 open/triaged incident。
// assetID 为 nil 时找的是同样没有资产归属的告警所在的 incident。
func (e *Engine) findOpen(ctx context.Context, assetID *uuid.UUID, since time.Time) (*ent.Incident, error) {
	scope := alert.AssetIDIsNil()
	if assetID != nil {
		scope = alert.AssetIDEQ(*assetID)
	}
	al, err := e.DB.Alert.Query().
		Where(
			scope,
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
		id, typ, label := eventNode(evt)
		g.ensureNode(id, typ, label)
		if assetNode != "" {
			g.ensureEdge(assetNode, id, "hosts")
		}
		g.ensureEdge(id, alertNode, "triggered")
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

// OCSF class：网络活动 / DNS 活动，其余按端点事件处理
const (
	classNetworkActivity = 4001
	classDNSActivity     = 4003
)

// eventNode 事件在图上的节点：端点事件画成进程，网络事件画成连接。
// 同一进程/连接的多条告警共用一个节点，靠 id 去重。
func eventNode(evt *ent.Event) (id, typ, label string) {
	if evt.ClassUID == classNetworkActivity || evt.ClassUID == classDNSActivity {
		id = "event:" + evt.ID.String()
		if evt.ConnTuple != nil {
			id = "conn:" + *evt.ConnTuple
		}
		return id, "connection", connLabel(evt)
	}

	id = "event:" + evt.ID.String()
	if evt.ProcessGUID != nil {
		id = "process:" + evt.ProcessGUID.String()
	}
	return id, "process", processLabel(evt)
}

func connLabel(evt *ent.Event) string {
	var raw struct {
		Query struct {
			Hostname string `json:"hostname"`
		} `json:"query"`
		TLS struct {
			SNI string `json:"sni"`
		} `json:"tls"`
		DstEndpoint struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		} `json:"dst_endpoint"`
	}
	if json.Unmarshal(evt.Raw, &raw) != nil {
		return "connection"
	}
	// 域名比 IP 有信息量，优先展示
	switch {
	case raw.Query.Hostname != "":
		return "DNS " + raw.Query.Hostname
	case raw.TLS.SNI != "":
		return raw.TLS.SNI
	case raw.DstEndpoint.IP != "":
		return fmt.Sprintf("%s:%d", raw.DstEndpoint.IP, raw.DstEndpoint.Port)
	default:
		return "connection"
	}
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

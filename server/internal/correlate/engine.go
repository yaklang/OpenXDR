// Package correlate 关联引擎：周期性把未归属的告警聚合成 incident。
// MVP 策略：同一资产、时间窗口内的告警归入同一个 open/triaged incident。
package correlate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/event"
	"openxdr/server/ent/incident"
	"openxdr/server/internal/sigma"
)

// 进程血缘上溯的层数上限，防止父子关系成环时打转
const maxLineageDepth = 16

var (
	errNoLineage = errors.New("无可用的进程血缘")
	errNoLateral = errors.New("无横向移动痕迹")
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

		// 进程血缘优先于时间窗：父进程所在的 incident 就是这条告警的归属，
		// 攻击链因此能跨越时间窗——这是 XDR 区别于孤立告警系统的地方。
		// 本机没有故事可归时再看横向移动：时间窗内有别的主机连过来，
		// 这台机器上的告警就是那台机器攻击故事的延续。
		var inc *ent.Incident
		var lateralFrom *ent.Asset
		if found, err := e.findByLineage(ctx, al); err == nil {
			inc = found
		} else if cached, ok := byAsset[bucket]; ok {
			inc = cached
		} else if found, err := e.findOpen(ctx, al.AssetID, al.Ts.Add(-e.Window)); err == nil {
			inc = found
		} else if found, src, err := e.findByLateral(ctx, al); err == nil {
			inc = found
			lateralFrom = src
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
		e.attach(ctx, g, al)
		// 横向移动在图上是一条主机到主机的边，攻击路径一眼可见
		if lateralFrom != nil && al.AssetID != nil && len(g.Nodes) < e.MaxGraphNodes {
			src := "asset:" + lateralFrom.ID.String()
			g.ensureNode(src, "asset", lateralFrom.Hostname)
			g.ensureEdge(src, "asset:"+al.AssetID.String(), "lateral")
		}
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

// findByLineage 沿进程血缘上溯，找祖先进程已归属的 incident。
// 逐级向上查，中间进程没触发过告警也能连上更早的攻击起点。
func (e *Engine) findByLineage(ctx context.Context, al *ent.Alert) (*ent.Incident, error) {
	evt := al.Edges.Event
	if evt == nil || evt.ParentProcessGUID == nil {
		return nil, errNoLineage
	}

	guid := *evt.ParentProcessGUID
	for depth := 0; depth < maxLineageDepth; depth++ {
		// 该祖先进程自己触发过的告警，其 incident 就是归属
		ancestor, err := e.DB.Alert.Query().
			Where(
				alert.IncidentIDNotNil(),
				alert.HasEventWith(event.ProcessGUIDEQ(guid)),
				alert.HasIncidentWith(incident.StatusIn("open", "triaged")),
			).
			WithIncident().
			First(ctx)
		if err == nil {
			return ancestor.Edges.Incident, nil
		}

		// 这一级没告警，继续往上找它的父进程
		up, err := e.DB.Event.Query().
			Where(event.ProcessGUIDEQ(guid), event.ParentProcessGUIDNotNil()).
			First(ctx)
		if err != nil {
			return nil, errNoLineage
		}
		guid = *up.ParentProcessGUID
	}
	return nil, errNoLineage
}

// findByLateral 横向移动：本机没有可归属的故事时，看时间窗内是否有别的
// 主机向本机发起过网络会话（sensor 流事件按源 IP 归属，conn_tuple 的
// 目的端是本机 IP），有则归并进对端的 incident。返回对端资产用于画图。
func (e *Engine) findByLateral(ctx context.Context, al *ent.Alert) (*ent.Incident, *ent.Asset, error) {
	if al.AssetID == nil || al.Edges.Asset == nil {
		return nil, nil, errNoLateral
	}
	since := al.Ts.Add(-e.Window)
	for _, ip := range al.Edges.Asset.IPAddrs {
		conns, err := e.DB.Event.Query().
			Where(
				event.TsGTE(since),
				event.ConnTupleContains(">"+ip+":"),
				event.AssetIDNotNil(),
				event.AssetIDNEQ(*al.AssetID),
			).
			WithAsset().
			Order(ent.Desc(event.FieldTs)).
			Limit(5).
			All(ctx)
		if err != nil {
			continue
		}
		for _, c := range conns {
			if inc, err := e.findOpen(ctx, c.AssetID, since); err == nil {
				return inc, c.Edges.Asset, nil
			}
		}
	}
	return nil, nil, errNoLateral
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

func (e *Engine) attach(ctx context.Context, g *Graph, al *ent.Alert) {
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

		// 父进程入图，攻击链在图上就是一串 spawned 边
		if evt.ParentProcessGUID != nil {
			parent := "process:" + evt.ParentProcessGUID.String()
			g.ensureNode(parent, "process", e.processName(ctx, *evt.ParentProcessGUID))
			g.ensureEdge(parent, id, "spawned")
			if assetNode != "" {
				g.ensureEdge(assetNode, parent, "hosts")
			}
		}
	} else if assetNode != "" {
		g.ensureEdge(assetNode, alertNode, "triggered")
	}
}

// processName 查进程 GUID 对应的名字，用于给图上的父进程节点打标签。
func (e *Engine) processName(ctx context.Context, guid uuid.UUID) string {
	evt, err := e.DB.Event.Query().Where(event.ProcessGUIDEQ(guid)).First(ctx)
	if err != nil {
		return "process"
	}
	return processLabel(evt)
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

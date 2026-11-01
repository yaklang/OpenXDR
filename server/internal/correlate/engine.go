// Package correlate 关联引擎：周期性把未归属的告警聚合成 incident。
// 策略：进程血缘、同一资产时间窗口内的告警、同资产同规则同实体的复发与横向移动
// 归入同一个 open/triaged incident。
package correlate

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/event"
	"openxdr/server/ent/incident"
	"openxdr/server/internal/automation"
	"openxdr/server/internal/incidentstate"
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
	Rules         sigma.Catalog
	Window        time.Duration
	Interval      time.Duration
	MaxGraphNodes int
	// RecurSpan 同资产同规则同实体的复发并回未结案 incident 的最长跨度（从 incident 创建起算），0 关闭
	RecurSpan time.Duration
	// RecurCoarse 进程类告警再按粗键（映像+用户+父进程映像，命令行不入键）归并复发；解释器类仍按完整命令行
	RecurCoarse bool
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
	tx, err := e.DB.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	worker := *e
	worker.DB = tx.Client()
	if err := worker.batchTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (e *Engine) batchTx(ctx context.Context, tx *ent.Tx) error {
	// 平台指令触发的告警挂在指令上，不组成事件：来源已知，发起与审批都有记录。
	// 登记的可信自动化来源同理，只有高危例外照常进关联
	pending, err := e.DB.Alert.Query().
		Where(alert.IncidentIDIsNil(), alert.CommandIDIsNil(), automation.Counted()).
		Order(ent.Asc(alert.FieldTs), ent.Asc(alert.FieldID)).
		Limit(500).
		WithEvent().
		WithAsset().
		All(ctx)
	if err != nil || len(pending) == 0 {
		return err
	}

	// 批内同资产且仍在时间窗内的告警命中缓存；批次边界不能改变关联语义。
	type cachedIncident struct {
		incident *ent.Incident
		lastTs   time.Time
	}
	byAsset := map[string]cachedIncident{}
	graphs := map[uuid.UUID]*Graph{}
	created := map[uuid.UUID]bool{}
	assign := map[uuid.UUID][]uuid.UUID{}
	// 并入了新证据的 incident（研判按 evidence_at 判断是否待重研判），其中 urgent 是升级类、要立即重研判的
	evidence := map[uuid.UUID]bool{}
	urgent := map[uuid.UUID]bool{}
	crit := e.criticalOf()
	ruleIn := map[string]bool{}
	// 标题跟随最高级别的告警：maxSev 是各 incident 当前最高级别，titles 是批内要改写的标题
	maxSev := map[uuid.UUID]int16{}
	titles := map[uuid.UUID]string{}
	// 复发：byEntity 是批内同资产同规则同实体（精确键与粗键各一份）最近归属的 incident，seen 记各 incident 批内已有的实体
	byEntity := map[string]*ent.Incident{}
	seen := map[string]bool{}
	// 级别升高的已有 incident：清掉推送标记，研判后按新级别重新决定是否推送
	escalate := map[uuid.UUID]bool{}

	for _, al := range pending {
		// 未归属的 Suricata 告警按组、探针与连接分桶，其余沿用全局 unknown 桶。
		bucket := correlationBucket(al)

		key, coarse := recurKeys(al)
		if !e.RecurCoarse {
			coarse = ""
		}
		entity, coarseEntity := "", ""
		if key != "" && al.AssetID != nil {
			entity = al.AssetID.String() + "|" + al.RuleID + "|" + key
			if coarse != "" {
				coarseEntity = al.AssetID.String() + "|" + al.RuleID + "|~" + coarse
			}
		}

		// 进程血缘优先于时间窗：父进程所在的 incident 就是这条告警的归属，
		// 攻击链因此能跨越时间窗——这是 XDR 区别于孤立告警系统的地方。
		// 超出时间窗后，同资产同规则同实体的复发并回仍未结案的 incident（跨度有上限）。
		// 本机没有故事可归时再看横向移动：时间窗内有别的主机连过来，
		// 这台机器上的告警就是那台机器攻击故事的延续。
		var inc *ent.Incident
		var lateralFrom *ent.Asset
		if found, err := e.findByLineage(ctx, al); err == nil {
			inc = found
		} else if cached, ok := byAsset[bucket]; ok &&
			!al.Ts.Before(cached.lastTs) && al.Ts.Sub(cached.lastTs) <= e.Window {
			inc = cached.incident
		} else if found, err := e.findForAlert(ctx, al, al.Ts.Add(-e.Window)); err == nil {
			inc = found
		} else if cached := cmp.Or(byEntity[entity], byEntity[coarseEntity]); cached != nil && al.Ts.Sub(cached.CreatedAt) <= e.RecurSpan {
			inc = cached
		} else if found, err := e.findRecurrence(ctx, al, key, coarse); err == nil {
			inc = found
		} else if found, src, err := e.findByLateral(ctx, al, func(id uuid.UUID) *ent.Incident {
			// 本批刚建、尚未落库挂接的 incident 也要能被横向关联到
			if cached, ok := byAsset[id.String()]; ok && al.Ts.Sub(cached.lastTs) <= e.Window {
				return cached.incident
			}
			return nil
		}); err == nil {
			inc = found
			lateralFrom = src
		}
		if inc == nil {
			inc, err = e.DB.Incident.Create().
				SetGraph(json.RawMessage("{}")).
				SetTitle(e.title(al)).
				Save(ctx)
			if err != nil {
				return err
			}
			created[inc.ID] = true
			maxSev[inc.ID] = al.Severity
		}
		if _, ok := maxSev[inc.ID]; !ok {
			if maxSev[inc.ID], err = e.maxSeverity(ctx, inc.ID); err != nil {
				return err
			}
		}
		escalated := al.Severity > maxSev[inc.ID]
		if escalated {
			maxSev[inc.ID] = al.Severity
			titles[inc.ID] = e.title(al)
			escalate[inc.ID] = true
		}
		byAsset[bucket] = cachedIncident{incident: inc, lastTs: al.Ts}
		// 已研判的 incident 收到新证据：记下时刻，研判引擎冷却到期后带新证据重新定性，旧结论在此之前继续有效。
		// 同一实体同一规则又来一次不算新证据——周期扫描每来一次就重新研判一遍，
		// 等于把拆开的 incident 换个形式又研判 N 次。按粗键并进来的不是同一实体（命令行不同、新冒出的程序），照常算。
		// 升级类证据不等冷却：级别升高，或这个 incident 里头一回出现的高危例外规则（情报命中、拿凭据、抹痕迹、
		// 关防护、搞破坏，与可信来源的高危例外同一口径）。同一条高危规则再来只按普通新证据冷却，免得它自己成风暴。
		// 还没研判过的照样记：首次研判可能正在进行，完成时据此知道有没看过的证据
		seenKey := inc.ID.String() + "|" + entity
		ruleKey := inc.ID.String() + "|" + al.RuleID
		if escalated || crit(al.RuleID) && !ruleIn[ruleKey] && !e.ruleIn(ctx, inc.ID, al.RuleID) {
			urgent[inc.ID] = true
			evidence[inc.ID] = true
		}
		ruleIn[ruleKey] = true
		if inc.Status != "triaged" || entity == "" || !seen[seenKey] && !e.seenIn(ctx, inc.ID, al, key) {
			evidence[inc.ID] = true
		}
		if entity != "" {
			seen[seenKey] = true
			if e.RecurSpan > 0 {
				byEntity[entity] = inc
				if coarseEntity != "" {
					byEntity[coarseEntity] = inc
				}
			}
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
		// 先归属告警再记证据时刻：研判按「证据时刻晚于取上下文的时刻」认没看过的证据，反过来会漏
		if err := e.DB.Alert.Update().
			Where(alert.IDIn(assign[incID]...)).
			SetIncidentID(incID).
			Exec(ctx); err != nil {
			return err
		}
		now := time.Now()
		upd := e.DB.Incident.UpdateOneID(incID).SetGraph(g.raw())
		if evidence[incID] {
			upd.SetEvidenceAt(now).ClearClosureProposal()
		}
		if urgent[incID] {
			upd.SetUrgentAt(now)
		}
		if title, ok := titles[incID]; ok {
			upd.SetTitle(title)
		}
		if escalate[incID] {
			upd.ClearNotifiedAt()
		}
		if err := upd.Exec(ctx); err != nil {
			return err
		}
		kind := incidentstate.EvidenceUpdated
		if created[incID] {
			kind = incidentstate.Created
		}
		if created[incID] || evidence[incID] {
			if err := incidentstate.Record(ctx, tx, incID, kind, incidentstate.Origin{Kind: "system"}, ""); err != nil {
				return err
			}
		}
	}
	slog.Info("关联完成", "alerts", len(pending), "incidents", len(graphs))
	return nil
}

// title incident 标题：告警规则标题 @ 主机名。
func (e *Engine) title(al *ent.Alert) string {
	hostname := "unknown"
	if al.Edges.Asset != nil {
		hostname = al.Edges.Asset.Hostname
	}
	return fmt.Sprintf("%s @ %s", e.alertTitle(al), hostname)
}

// criticalOf 本批次的高危例外判定（情报命中与高危战术/技术，见 automation.Watch），按规则缓存
func (e *Engine) criticalOf() func(ruleID string) bool {
	rules := e.Rules.Rules()
	cache := map[string]bool{}
	return func(ruleID string) bool {
		c, ok := cache[ruleID]
		if !ok {
			c = automation.Watch(ruleID, rules)
			cache[ruleID] = c
		}
		return c
	}
}

// ruleIn incident 里是否已有这条规则的告警；查不了按没有算，宁可多研判一次也不把高危压进冷却
func (e *Engine) ruleIn(ctx context.Context, incID uuid.UUID, ruleID string) bool {
	ok, err := e.DB.Alert.Query().Where(alert.IncidentIDEQ(incID), alert.RuleIDEQ(ruleID)).Exist(ctx)
	return ok && err == nil
}

// maxSeverity 已归属告警里的最高级别；没有已归属告警时返回最小值，任何告警都比它高。
func (e *Engine) maxSeverity(ctx context.Context, incID uuid.UUID) (int16, error) {
	top, err := e.DB.Alert.Query().
		Where(alert.IncidentIDEQ(incID)).
		Order(ent.Desc(alert.FieldSeverity)).
		First(ctx)
	if ent.IsNotFound(err) {
		return math.MinInt16, nil
	}
	if err != nil {
		return 0, err
	}
	return top.Severity, nil
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
func (e *Engine) findByLateral(ctx context.Context, al *ent.Alert, inBatch func(uuid.UUID) *ent.Incident) (*ent.Incident, *ent.Asset, error) {
	if al.AssetID == nil || al.Edges.Asset == nil {
		return nil, nil, errNoLateral
	}
	since := al.Ts.Add(-e.Window)
	group := asset.GroupIDIsNil()
	if al.Edges.Asset.GroupID != nil {
		group = asset.GroupIDEQ(*al.Edges.Asset.GroupID)
	}
	peers, err := e.DB.Asset.Query().Where(group, asset.IDNEQ(*al.AssetID)).IDs(ctx)
	if err != nil || len(peers) == 0 {
		return nil, nil, errNoLateral
	}
	for _, ip := range al.Edges.Asset.IPAddrs {
		conns, err := e.DB.Event.Query().
			Where(
				event.TsGTE(since),
				event.TsLTE(al.Ts),
				event.AssetIDIn(peers...),
				event.ConnTupleContains(">"+ip+":"),
			).
			WithAsset().
			Order(ent.Desc(event.FieldTs)).
			Limit(5).
			All(ctx)
		if err != nil {
			continue
		}
		for _, c := range conns {
			if inBatch != nil {
				if inc := inBatch(*c.AssetID); inc != nil {
					return inc, c.Edges.Asset, nil
				}
			}
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
	} else {
		scope = alert.And(scope, alert.Not(alert.HasEventWith(event.SourceEQ("suricata"))))
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
	g.ensureNode(alertNode, "alert", e.alertTitle(al))

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
	classFileActivity    = 1001
	classProcessActivity = 1007
	classNetworkActivity = 4001
	classDNSActivity     = 4003
)

// eventNode 事件在图上的节点：端点事件画成进程，网络事件画成连接，
// 没有进程上下文的文件事件画成文件。同一进程/连接/文件的多条告警共用一个节点，靠 id 去重。
func eventNode(evt *ent.Event) (id, typ, label string) {
	if evt.ClassUID == classNetworkActivity || evt.ClassUID == classDNSActivity || evt.Source == "suricata" {
		id = "event:" + evt.ID.String()
		if evt.ConnTuple != nil {
			id = "conn:" + *evt.ConnTuple
		}
		return id, "connection", connLabel(evt)
	}

	id = "event:" + evt.ID.String()
	if evt.ProcessGUID != nil {
		id = "process:" + evt.ProcessGUID.String()
	} else if path := bareFilePath(evt); path != "" {
		return "file:" + path, "file", path
	}
	return id, "process", processLabel(evt)
}

// bareFilePath 没有进程上下文的文件事件（inotify 路径只报路径与动作）返回文件路径，其余返回空。
// 这类事件画成进程会只剩一个兜底标签 "process"，看不出发生在哪个文件上。
func bareFilePath(evt *ent.Event) string {
	var raw struct {
		Process struct {
			Name string `json:"name"`
		} `json:"process"`
		File struct {
			Path string `json:"path"`
		} `json:"file"`
	}
	if evt.ClassUID != classFileActivity || json.Unmarshal(evt.Raw, &raw) != nil || raw.Process.Name != "" {
		return ""
	}
	return raw.File.Path
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
			IP       string `json:"ip"`
			Port     int    `json:"port"`
			Hostname string `json:"hostname"`
		} `json:"dst_endpoint"`
	}
	if json.Unmarshal(evt.Raw, &raw) != nil {
		return "connection"
	}
	// 域名比 IP 有信息量，优先展示；agent 按自己看到的 DNS 应答给出站连接回填了域名
	switch {
	case raw.Query.Hostname != "":
		return "DNS " + raw.Query.Hostname
	case raw.TLS.SNI != "":
		return raw.TLS.SNI
	case raw.DstEndpoint.Hostname != "":
		return fmt.Sprintf("%s:%d", raw.DstEndpoint.Hostname, raw.DstEndpoint.Port)
	case raw.DstEndpoint.IP != "":
		return fmt.Sprintf("%s:%d", raw.DstEndpoint.IP, raw.DstEndpoint.Port)
	default:
		return "connection"
	}
}

// processLabel 进程名与 pid；在容器里的前面加容器名，同名进程分得清在哪个容器
func processLabel(evt *ent.Event) string {
	var raw struct {
		Process struct {
			PID  *int64 `json:"pid"`
			Name string `json:"name"`
		} `json:"process"`
		Container struct {
			UID     string `json:"uid"`
			Name    string `json:"name"`
			Runtime string `json:"runtime"`
		} `json:"container"`
	}
	if json.Unmarshal(evt.Raw, &raw) != nil || raw.Process.Name == "" {
		return "process"
	}
	label := raw.Process.Name
	if raw.Process.PID != nil {
		label = fmt.Sprintf("%s (%d)", raw.Process.Name, *raw.Process.PID)
	}
	if c := raw.Container; c.UID != "" {
		label = cmp.Or(c.Name, c.Runtime+" "+c.UID) + "/" + label
	}
	return label
}

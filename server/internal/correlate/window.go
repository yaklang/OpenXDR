package correlate

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/event"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/predicate"
	"openxdr/server/internal/authfields"
	"openxdr/server/internal/sigma"
)

// 时间窗回查每次最多比对的告警数：一个归属桶半小时内超过这么多条告警时，更早的锚点看不到，按新建处理，不会错并
const windowCandidates = 200

// containerOf 告警事件所在的容器（agent 按 cgroup 认出的 container.uid），宿主机自身为空
func containerOf(al *ent.Alert) string {
	if al.Edges.Event == nil {
		return ""
	}
	var raw struct {
		Container struct {
			UID string `json:"uid"`
		} `json:"container"`
	}
	_ = json.Unmarshal(al.Edges.Event.Raw, &raw)
	return raw.Container.UID
}

// correlationBucket 时间窗归并的归属桶：有资产的按资产 + 容器，同一台宿主机上一个容器的噪声撑不住另一个容器的 incident；
// 无资产的 Suricata 告警按组、探针与连接，其余进全局 unknown 桶
func correlationBucket(al *ent.Alert) string {
	if al.AssetID != nil {
		return al.AssetID.String() + "|" + containerOf(al)
	}
	if scope := externalScope(al); scope != "" {
		return "suricata|" + scope
	}
	return uuid.Nil.String()
}

// bucketScope 归属桶在告警表上的范围，与 correlationBucket 同一口径
func bucketScope(al *ent.Alert) predicate.Alert {
	if al.AssetID != nil {
		return alert.And(alert.AssetIDEQ(*al.AssetID), inContainer(containerOf(al)))
	}
	if scope := externalScope(al); scope != "" {
		return alert.And(alert.AssetIDIsNil(), alert.TsLTE(al.Ts), alert.HasEventWith(event.SourceEQ("suricata"), func(s *sql.Selector) {
			s.Where(sqljson.ValueEQ(event.FieldRaw, scope, sqljson.Path("metadata", "suricata_scope")))
		}))
	}
	return alert.And(alert.AssetIDIsNil(), alert.Not(alert.HasEventWith(event.SourceEQ("suricata"))))
}

// inContainer 告警事件的容器是 uid（空串即宿主机自身）。events 按天分区，告警时间就是事件时间，
// 按 (id, ts) 回查只碰一个分区；没有事件或时间对不上的（个别合成告警）按宿主机算
func inContainer(uid string) predicate.Alert {
	return func(s *sql.Selector) {
		s.Where(sql.P(func(b *sql.Builder) {
			b.WriteString(fmt.Sprintf("COALESCE((SELECT e.raw->'container'->>'uid' FROM events e WHERE e.id = %s AND e.ts = %s), '')",
				s.C(alert.FieldEventID), s.C(alert.FieldTs))).
				WriteOp(sql.OpEQ).Arg(uid)
		}))
	}
}

// findWindow 同一归属桶时间窗内的 open/triaged incident。窗口锚点是有意义的告警（renews）或 incident 的第一条告警，
// 从最近的告警往前找第一个锚点；低危重复照常并入、不续期。高危告警跳过 AI 已判良性的 incident
func (e *Engine) findWindow(ctx context.Context, al *ent.Alert, high bool, renews func(*ent.Alert) bool) (*ent.Incident, error) {
	since := al.Ts.Add(-e.Window)
	rows, err := e.DB.Alert.Query().
		Where(
			bucketScope(al),
			alert.RuleIDNEQ(sigma.RuleLateralSpray),
			alert.TsGTE(since),
			alert.IncidentIDNotNil(),
			alert.HasIncidentWith(incident.StatusIn("open", "triaged")),
		).
		Order(ent.Desc(alert.FieldTs)).
		Limit(windowCandidates).
		WithIncident().
		All(ctx)
	if err != nil {
		return nil, err
	}
	started := map[uuid.UUID]bool{}
	for _, r := range rows {
		inc := r.Edges.Incident
		if high && benign(inc) {
			continue
		}
		if renews(r) {
			return inc, nil
		}
		s, ok := started[inc.ID]
		if !ok {
			s = e.startedSince(ctx, inc.ID, since)
			started[inc.ID] = s
		}
		if s {
			return inc, nil
		}
	}
	return nil, errNoWindow
}

// startedSince incident 的第一条告警不早于 since；查不了按否算，宁可新开也不错并
func (e *Engine) startedSince(ctx context.Context, incID uuid.UUID, since time.Time) bool {
	older, err := e.DB.Alert.Query().Where(alert.IncidentIDEQ(incID), alert.TsLT(since)).Exist(ctx)
	return err == nil && !older
}

// peerCandidate 批内已归属的一条告警，横向关联找源主机的 incident 时用
type peerCandidate struct {
	incident *ent.Incident
	severity int16
	ts       time.Time
}

// findPeer 源主机在时间窗内未结案、未被 AI 判良性的 incident：取窗内级别最高的告警所在的，同级取最近。
// 不按容器分桶：容器里的连接是采集盲区，受害方只看得到宿主机地址，源头可能是主机上任一容器；
// 按级别挑，宿主机上长期的巡检噪声不会盖过同时段的攻击。批内刚归属、尚未落库的告警一并比较
func (e *Engine) findPeer(ctx context.Context, src *ent.Asset, at time.Time, batch map[uuid.UUID][]peerCandidate) (*ent.Incident, error) {
	if src == nil {
		return nil, errNoLateral
	}
	since := at.Add(-e.Window)
	var best peerCandidate
	for _, c := range batch[src.ID] {
		if c.ts.Before(since) || c.ts.After(at) || benign(c.incident) {
			continue
		}
		if best.incident == nil || c.severity > best.severity || c.severity == best.severity && !c.ts.Before(best.ts) {
			best = c
		}
	}
	row, err := e.DB.Alert.Query().
		Where(
			alert.AssetIDEQ(src.ID),
			alert.TsGTE(since),
			alert.TsLTE(at),
			alert.IncidentIDNotNil(),
			alert.HasIncidentWith(incident.StatusIn("open", "triaged"), notBenign()),
		).
		Order(ent.Desc(alert.FieldSeverity), ent.Desc(alert.FieldTs)).
		WithIncident().
		First(ctx)
	if err == nil && (best.incident == nil || row.Severity > best.severity || row.Severity == best.severity && row.Ts.After(best.ts)) {
		return row.Edges.Incident, nil
	}
	if best.incident == nil {
		return nil, errNoLateral
	}
	return best.incident, nil
}

// lateralSource 受害方证据指向的源主机：事件的对端地址（登录来源、入站对端）唯一属于另一台纳管主机。
// 内部横向喷洒合成告警本身落在源主机上，源头就是它自己
func lateralSource(al *ent.Alert, owners map[string]*ent.Asset) *ent.Asset {
	if al.AssetID == nil || al.Edges.Asset == nil {
		return nil
	}
	if al.RuleID == sigma.RuleLateralSpray {
		return al.Edges.Asset
	}
	evt := al.Edges.Event
	if evt == nil {
		return nil
	}
	ip := authfields.PeerIP(evt.ClassUID, evt.Raw)
	if src := owners[ip]; ip != "" && src != nil && src.ID != *al.AssetID {
		return src
	}
	return nil
}

// addressOwners 纳管地址到资产。只收唯一属主的地址：docker 网桥 172.17.0.1 这类多台主机都有的地址认不出是谁，不认
func (e *Engine) addressOwners(ctx context.Context) (map[string]*ent.Asset, error) {
	assets, err := e.DB.Asset.Query().All(ctx)
	if err != nil {
		return nil, err
	}
	owners := map[string]*ent.Asset{}
	shared := map[string]bool{}
	for _, a := range assets {
		for _, raw := range a.IPAddrs {
			ip := authfields.CanonicalIP(raw)
			if o, ok := owners[ip]; ip == "" || shared[ip] || ok && o.ID == a.ID {
				continue
			} else if ok {
				delete(owners, ip)
				shared[ip] = true
				continue
			}
			owners[ip] = a
		}
	}
	return owners, nil
}

// benign AI 当前结论为良性；没有结论或解析不了都不算
func benign(inc *ent.Incident) bool {
	var v struct {
		Verdict string `json:"verdict"`
	}
	return inc != nil && json.Unmarshal(inc.AiVerdict, &v) == nil && v.Verdict == "benign"
}

// notBenign 与 benign 同一口径的查询条件
func notBenign() predicate.Incident {
	return func(s *sql.Selector) {
		s.Where(sql.ExprP(fmt.Sprintf("COALESCE(%s->>'verdict', '') <> 'benign'", s.C(incident.FieldAiVerdict))))
	}
}

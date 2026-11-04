package containment

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/predicate"
	"openxdr/server/internal/authfields"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/sigma"
)

// intelMinSeverity 情报命中要达到的级别才自动处置；低级别条目多是泛化的扫描源，误伤面大
const intelMinSeverity = 4

// signalAlerts 快路径的信号：只认确定性的合成检测与高级别情报命中，不认 Sigma 规则与 AI 结论
func signalAlerts() predicate.Alert {
	return alert.Or(
		alert.RuleIDIn(sigma.RuleLateralSpray, sigma.RuleBruteforceSuccess),
		alert.And(alert.RuleIDHasPrefix("intel:"), alert.SeverityGTE(intelMinSeverity)),
	)
}

func (e *Engine) planFor(ctx context.Context, al *ent.Alert) (plan, error) {
	switch {
	case al.RuleID == sigma.RuleLateralSpray:
		return e.planSpray(ctx, al)
	case al.RuleID == sigma.RuleBruteforceSuccess:
		return e.planBruteforce(ctx, al)
	default:
		return e.planIntel(ctx, al)
	}
}

// planSpray 内网横向喷洒：来源是告警所在主机，受害方取证据表里窗口内的主机与它们看到的来源地址。
// 来源是实验等级就隔离；受害方一律封锁来源地址，但来源与受害方都是核心时不封（平台节点互封等于切断控制面）
func (e *Engine) planSpray(ctx context.Context, al *ent.Alert) (plan, error) {
	src, err := e.DB.Asset.Get(ctx, *al.AssetID)
	if err != nil {
		return plan{}, err
	}
	srcTier, _, err := e.tier(ctx, src)
	if err != nil {
		return plan{}, err
	}
	outOfScope, err := e.scoped(ctx, src)
	if err != nil {
		return plan{}, err
	}
	last := al.Ts
	if al.LastTs != nil {
		last = *al.LastTs
	}
	rows, err := e.SQL.QueryContext(ctx, `SELECT DISTINCT victim_asset, src_ip FROM lateral_evidence
WHERE src_asset=$1 AND ts>$2 AND ts<=$3 AND src_ip IS NOT NULL AND victim_asset<>src_asset ORDER BY 1, 2`,
		src.ID, al.Ts.Add(-ingest.SprayWindow), last)
	if err != nil {
		return plan{}, err
	}
	type hit struct {
		victim uuid.UUID
		ip     string
	}
	var hits []hit
	for rows.Next() {
		var h hit
		if err := rows.Scan(&h.victim, &h.ip); err != nil {
			rows.Close()
			return plan{}, err
		}
		hits = append(hits, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return plan{}, err
	}

	p := plan{source: src}
	if srcTier == TierLab {
		p.actions = append(p.actions, e.isolateSource(src, outOfScope, "内网横向喷洒的来源，隔离本机"))
	}
	for _, h := range hits {
		victim, err := e.DB.Asset.Get(ctx, h.victim)
		if err != nil {
			return plan{}, err
		}
		a := action{asset: victim, kind: "block_network", target: h.ip, role: "victim", skip: outOfScope,
			why: "遭受来自 " + h.ip + " 的内网横向喷洒，封锁该地址"}
		if a.skip == "" && srcTier == TierCore {
			vt, _, err := e.tier(ctx, victim)
			if err != nil {
				return plan{}, err
			}
			if vt == TierCore {
				a.skip = "来源与受害方都是核心资产，互相封锁会切断控制面"
			}
		}
		p.actions = append(p.actions, a)
	}
	return p, nil
}

// planBruteforce 爆破得手：受害主机封锁登录来源、锁定被攻破的账号（内置账号由目标校验挡下，核心主机不锁，
// 锁错了没人能登上去处理）；来源是实验等级的纳管主机就隔离它
func (e *Engine) planBruteforce(ctx context.Context, al *ent.Alert) (plan, error) {
	victim, err := e.DB.Asset.Get(ctx, *al.AssetID)
	if err != nil {
		return plan{}, err
	}
	ev, err := e.eventOf(ctx, al)
	if err != nil || ev == nil {
		return plan{}, err
	}
	ip := authfields.PeerIP(ev.ClassUID, ev.Raw)
	src, err := e.ownerOf(ctx, ip, victim)
	if err != nil {
		return plan{}, err
	}
	outOfScope, err := e.scoped(ctx, victim, src)
	if err != nil {
		return plan{}, err
	}
	vt, _, err := e.tier(ctx, victim)
	if err != nil {
		return plan{}, err
	}
	p := plan{source: src}
	if src != nil {
		if st, _, err := e.tier(ctx, src); err != nil {
			return plan{}, err
		} else if st == TierLab {
			p.actions = append(p.actions, e.isolateSource(src, outOfScope, "爆破得手的来源，隔离本机"))
		}
	}
	if ip != "" {
		p.actions = append(p.actions, action{asset: victim, kind: "block_network", target: ip, role: "victim", skip: outOfScope,
			why: "来自 " + ip + " 的口令爆破已经登录成功，封锁该地址"})
	}
	if ev.Username != nil && *ev.Username != "" {
		a := action{asset: victim, kind: "disable_account", target: *ev.Username, role: "victim", skip: outOfScope,
			why: "账号 " + *ev.Username + " 的口令被爆破得手，锁定账号（需改密后人工解锁）"}
		if a.skip == "" && vt == TierCore {
			a.skip = "核心资产不自动锁定账号，锁错了没人能登上去处理"
		}
		p.actions = append(p.actions, a)
	}
	return p, nil
}

// planIntel 高级别情报命中：命中主机自身就是失陷方。
//   - IP：封锁；本机主动外连这个地址时结束发起连接的进程（入站命中的进程是本机的服务，结束它就是自己制造故障）
//   - 域名：只封锁；DNS 归属可能落在本机的解析服务上，不结束进程
//   - 文件哈希：进程本身的哈希命中就结束进程；文件隔离（核心资产不隔离文件，隔离错了可能停掉关键服务）
func (e *Engine) planIntel(ctx context.Context, al *ent.Alert) (plan, error) {
	kind, value, ok := strings.Cut(strings.TrimPrefix(al.RuleID, "intel:"), ":")
	if !ok || value == "" {
		return plan{}, nil
	}
	host, err := e.DB.Asset.Get(ctx, *al.AssetID)
	if err != nil {
		return plan{}, err
	}
	ev, err := e.eventOf(ctx, al)
	if err != nil {
		return plan{}, err
	}
	outOfScope, err := e.scoped(ctx, host)
	if err != nil {
		return plan{}, err
	}
	t, _, err := e.tier(ctx, host)
	if err != nil {
		return plan{}, err
	}
	var doc eventDoc
	if ev != nil {
		_ = json.Unmarshal(ev.Raw, &doc)
	}
	p := plan{}
	switch kind {
	case "ip", "domain":
		p.actions = append(p.actions, action{asset: host, kind: "block_network", target: value, role: "host", skip: outOfScope,
			why: "命中威胁情报 " + value + "，封锁该地址"})
		if kind == "ip" && doc.Connection.Direction == "outbound" && doc.Dst.IP == value {
			p.actions = append(p.actions, e.killProcess(host, ev, doc, outOfScope, "进程 "+doc.Process.Name+" 主动连接威胁情报地址 "+value+"，结束该进程"))
		}
	case "hash":
		if ev == nil {
			return p, nil
		}
		file := doc.Process.File
		if ev.ClassUID != 1007 {
			file = doc.File
		}
		if !file.has(value) {
			return p, nil
		}
		if ev.ClassUID == 1007 {
			p.actions = append(p.actions, e.killProcess(host, ev, doc, outOfScope, "进程 "+doc.Process.Name+" 的文件哈希命中威胁情报，结束该进程"))
		}
		a := action{asset: host, kind: "quarantine_file", target: file.Path, role: "host", skip: outOfScope,
			why: "文件 " + file.Path + " 的哈希命中威胁情报，移入隔离区（需人工恢复）"}
		if a.skip == "" && t == TierCore {
			a.skip = "核心资产不自动隔离文件，隔离错了可能停掉关键服务"
		}
		p.actions = append(p.actions, a)
	}
	return p, nil
}

// isolateSource 隔离来源主机的计划；没配置隔离放行地址时不隔离，隔离后收不到解除指令
func (e *Engine) isolateSource(src *ent.Asset, outOfScope, why string) action {
	a := action{asset: src, kind: "isolate_host", role: "source", skip: outOfScope, why: why}
	if len(e.AllowEndpoints) == 0 {
		a.skip = "未配置 ISOLATION_ALLOW，隔离后收不到解除指令"
	}
	return a
}

func (e *Engine) killProcess(host *ent.Asset, ev *ent.Event, doc eventDoc, outOfScope, why string) action {
	guid := ""
	if ev.ProcessGUID != nil {
		guid = ev.ProcessGUID.String()
	}
	return action{asset: host, kind: "kill_process", target: guid, pid: doc.Process.PID, role: "host", skip: outOfScope, why: why}
}

// eventOf 告警的触发事件；合成告警或事件已过保留期时为 nil
func (e *Engine) eventOf(ctx context.Context, al *ent.Alert) (*ent.Event, error) {
	if al.EventID == nil {
		return nil, nil
	}
	ev, err := e.DB.Event.Get(ctx, *al.EventID)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	return ev, err
}

// ownerOf 地址唯一属于哪台纳管主机（不是 except 本身）。docker 网桥这类多台都有的地址认不出，返回 nil
func (e *Engine) ownerOf(ctx context.Context, ip string, except *ent.Asset) (*ent.Asset, error) {
	if ip == "" {
		return nil, nil
	}
	rows, err := e.SQL.QueryContext(ctx, `SELECT id FROM assets WHERE ip_addrs ? $1 LIMIT 2`, ip)
	if err != nil {
		return nil, err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(ids) != 1 || ids[0] == except.ID {
		return nil, err
	}
	return e.DB.Asset.Get(ctx, ids[0])
}

// eventDoc 处置用到的事件字段（OCSF 风格，agent 上报的原文）
type eventDoc struct {
	Process struct {
		PID  uint32   `json:"pid"`
		Name string   `json:"name"`
		File fileInfo `json:"file"`
	} `json:"process"`
	File       fileInfo `json:"file"`
	Connection struct {
		Direction string `json:"direction"`
	} `json:"connection_info"`
	Dst struct {
		IP string `json:"ip"`
	} `json:"dst_endpoint"`
}

type fileInfo struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	SHA1   string `json:"sha1"`
	MD5    string `json:"md5"`
}

// has 情报命中的哈希就是这个文件的哈希，而不是事件里别的字段（父进程、关联文件）碰上的
func (f fileInfo) has(hash string) bool {
	return f.Path != "" && hash != "" && (strings.EqualFold(f.SHA256, hash) || strings.EqualFold(f.SHA1, hash) || strings.EqualFold(f.MD5, hash))
}

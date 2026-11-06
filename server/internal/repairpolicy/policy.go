// Package repairpolicy 保存管理员明确委托的有限修复范围，不把模型意图当成授权。
package repairpolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/command"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/predicate"
	"openxdr/server/ent/setting"
	"openxdr/server/ent/taskrun"
	"openxdr/server/ent/user"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/repaircmd"
)

const SettingKey = "repair-policy"
const RestartFailedService = "restart_failed_service"
const ReclaimDisk = "reclaim_disk"

type Grant struct {
	ID              uuid.UUID   `json:"id"`
	Action          string      `json:"action"`
	GroupID         uuid.UUID   `json:"group_id"`
	AssetIDs        []uuid.UUID `json:"asset_ids"`
	Units           []string    `json:"units"`
	Paths           []string    `json:"paths,omitempty"`
	ExpiresAt       time.Time   `json:"expires_at"`
	CooldownMinutes int         `json:"cooldown_minutes"`
}
type Policy struct {
	Grants []Grant `json:"grants"`
}
type Store struct{ DB *ent.Client }
type probeRef struct {
	SessionID uuid.UUID `json:"session_id"`
	CommandID uuid.UUID `json:"command_id"`
	AssetID   uuid.UUID `json:"asset_id"`
	Unit      string    `json:"unit"`
}
type use struct {
	ProblemHash   string     `json:"problem_hash"`
	GrantVersion  string     `json:"grant_version"`
	FindingID     uuid.UUID  `json:"finding_id"`
	Command       string     `json:"command,omitempty"`
	ActionID      uuid.UUID  `json:"action_id,omitempty"`
	VerifiedAt    *time.Time `json:"verified_at,omitempty"`
	AfterProbeID  uuid.UUID  `json:"after_probe_id,omitempty"`
	FinalizedAt   *time.Time `json:"finalized_at,omitempty"`
	SessionID     uuid.UUID  `json:"session_id"`
	GrantID       uuid.UUID  `json:"grant_id"`
	ReservationID uuid.UUID  `json:"reservation_id"`
	ReservedAt    time.Time  `json:"reserved_at"`
	NextAllowedAt time.Time  `json:"next_allowed_at"`
	ProbeID       uuid.UUID  `json:"probe_id"`
}

var unitName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}\.service$`)
var restart = regexp.MustCompile(`^systemctl restart -- ([a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}\.service)$`)

func validUnit(unit string) bool {
	if !unitName.MatchString(unit) || strings.Contains(unit, "..") {
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(unit, ".service"))
	for _, core := range []string{"openxdr", "patroni", "postgres", "nats", "ssh", "network", "system", "dbus", "audit", "rsyslog", "firewall", "iptables", "nftables", "ufw", "tailscale", "docker", "containerd", "kube", "pve", "corosync", "keepalived", "etcd", "consul", "mysql", "mariadb", "mongo", "clickhouse", "kafka", "zookeeper", "apparmor", "selinux", "polkit", "cron", "chrony", "ntp"} {
		if strings.Contains(name, core) {
			return false
		}
	}
	return true
}
func ProbeCommand(unit string) string {
	return "systemctl show --property=Id,ActiveState,UnitFileState -- " + unit
}
func strict(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("JSON包含额外内容")
	}
	return nil
}

func (s *Store) Load(ctx context.Context) (Policy, error) {
	row, err := s.DB.Setting.Get(ctx, SettingKey)
	if ent.IsNotFound(err) {
		return Policy{Grants: []Grant{}}, nil
	}
	if err != nil {
		return Policy{}, err
	}
	var p Policy
	err = strict(row.Value, &p)
	return p, err
}

func (s *Store) validate(ctx context.Context, p Policy, now time.Time) error {
	if len(p.Grants) > 50 {
		return errors.New("最多50条有限授权")
	}
	seen := map[uuid.UUID]bool{}
	for _, g := range p.Grants {
		if g.ID == uuid.Nil || seen[g.ID] || (g.Action != RestartFailedService && g.Action != ReclaimDisk) || g.GroupID == uuid.Nil || len(g.AssetIDs) == 0 || len(g.AssetIDs) > 50 || (g.Action == RestartFailedService && len(g.Units) == 0) || len(g.Units) > 20 || len(g.Paths) > 20 || g.CooldownMinutes < 60 || g.CooldownMinutes > 10080 || !g.ExpiresAt.After(now) || g.ExpiresAt.After(now.Add(30*24*time.Hour)) {
			return errors.New("授权须有唯一ID、明确组/资产/动作、60至10080分钟冷却及30天内有效期")
		}
		if g.Action == ReclaimDisk && len(g.Units) != 0 || g.Action == RestartFailedService && len(g.Paths) != 0 {
			return errors.New("服务与目录名单必须对应各自授权动作")
		}
		paths := map[string]bool{}
		for _, p := range g.Paths {
			if !repaircmd.Path(p) || paths[p] {
				return errors.New("回收目录须为非关键目录的规范绝对路径且不得重复")
			}
			paths[p] = true
		}
		seen[g.ID] = true
		assets := map[uuid.UUID]bool{}
		for _, id := range g.AssetIDs {
			if id == uuid.Nil || assets[id] {
				return errors.New("资产名单无效或重复")
			}
			assets[id] = true
			ok, err := s.DB.Asset.Query().Where(asset.IDEQ(id), asset.GroupIDEQ(g.GroupID), asset.OsEQ("linux")).Exist(ctx)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("授权资产不是指定组的 Linux 主机")
			}
		}
		units := map[string]bool{}
		for _, u := range g.Units {
			if !validUnit(u) || units[u] {
				return errors.New("只允许非关键、无路径/实例/转义的规范服务精确名")
			}
			units[u] = true
		}
	}
	return nil
}

// Save 只接受认证上下文中的真实全局管理员，内部任务/模型没有写策略入口。
func (s *Store) Save(ctx context.Context, p Policy, remote string) error {
	actor := auth.From(ctx)
	if actor == nil {
		return errors.New("仅真实管理员可配置维护范围")
	}
	current, err := s.DB.User.Get(ctx, actor.ID)
	if err != nil || current.Role != "admin" || current.Username == "system" || current.Username == "ai-reviewer" {
		return errors.New("仅真实管理员可配置维护范围")
	}
	if err := s.validate(ctx, p, time.Now()); err != nil {
		return err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tx, err := s.DB.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err = tx.User.Query().Where(user.IDEQ(actor.ID), user.RoleEQ("admin")).Where(func(q *sql.Selector) { q.ForUpdate() }).Only(ctx)
	if err != nil {
		return errors.New("管理员权限已失效")
	}
	n, err := tx.Setting.Update().Where(setting.IDEQ(SettingKey)).SetValue(raw).Save(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		if err := tx.Setting.Create().SetID(SettingKey).SetValue(raw).Exec(ctx); err != nil {
			return err
		}
	}
	if err := audit.Checked(ctx, tx.AuditLog.Create(), current.Username, remote, "repair_policy_update", SettingKey, "admin_user_id="+current.ID.String()+" policy="+string(raw)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := auth.From(r.Context())
		if u == nil {
			http.Error(w, "需要管理员登录", http.StatusForbidden)
			return
		}
		current, err := s.DB.User.Get(r.Context(), u.ID)
		if err != nil || current.Role != "admin" {
			http.Error(w, "仅管理员可访问维护范围", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			p, err := s.Load(r.Context())
			if err != nil {
				http.Error(w, "读取维护范围失败", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(p)
		case http.MethodPut:
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32768))
			if err != nil {
				http.Error(w, "请求过大", http.StatusBadRequest)
				return
			}
			var p Policy
			if err := strict(raw, &p); err != nil {
				http.Error(w, "维护范围JSON无效", http.StatusBadRequest)
				return
			}
			if err := s.Save(r.Context(), p, audit.RemoteAddr(r)); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Allow", "GET, PUT")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

func (s *Store) claimed(ctx context.Context, session *ent.AgentSession, id uuid.UUID) (*ent.AgentSession, *ent.Finding, error) {
	return claimedWithClient(ctx, s.DB, session, id)
}

func claimedWithClient(ctx context.Context, db *ent.Client, session *ent.AgentSession, id uuid.UUID) (*ent.AgentSession, *ent.Finding, error) {
	if session == nil {
		return nil, nil, errors.New("缺少真实任务会话")
	}
	now := time.Now()
	current, err := db.AgentSession.Get(ctx, session.ID)
	if err != nil || current.Kind != "task" || current.Initiator != "system" || current.Status != "running" || current.CancelRequestedAt != nil || current.GroupID != session.GroupID || current.RunOwner == nil || current.RunExpiresAt == nil || !current.RunExpiresAt.After(now) || current.RunDeadlineAt == nil || !current.RunDeadlineAt.After(now) {
		return nil, nil, errors.New("任务会话或租约失效")
	}
	bound, err := db.TaskRun.Query().Where(taskrun.TaskIDEQ(findings.FollowupTask), taskrun.SessionIDEQ(current.ID), taskrun.GroupIDEQ(current.GroupID), taskrun.StatusEQ("running")).Exist(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !bound {
		return nil, nil, errors.New("不是平台自治跟进任务")
	}
	filters := []predicate.Finding{finding.GroupIDEQ(current.GroupID), finding.StatusEQ("open"), finding.WorkOwnerEQ("ai"), finding.WorkSessionIDEQ(current.ID), finding.WorkLeaseUntilGT(now)}
	if id != uuid.Nil {
		filters = append(filters, finding.IDEQ(id))
	}
	rows, err := db.Finding.Query().Where(filters...).All(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range rows {
		if !slices.Contains(current.Subjects, "finding:"+f.ID.String()) {
			continue
		}
		ok, err := db.Asset.Query().Where(asset.IDEQ(f.AssetID), asset.GroupIDEQ(current.GroupID), asset.OsEQ("linux")).Exist(ctx)
		if err != nil {
			return nil, nil, err
		}
		if ok {
			return current, f, nil
		}
	}
	return nil, nil, errors.New("待办未被本轮有效领取")
}

// RecordProbe 在 exec 真实下发后由服务端调用；模型不能通过工具参数伪造会话与指令的关联。
func (s *Store) RecordProbe(ctx context.Context, session *ent.AgentSession, c *ent.Command) error {
	if session == nil {
		return errors.New("缺少真实任务会话")
	}
	if c == nil || c.Kind != "exec" || c.Cmd == nil {
		return nil
	}
	if _, ok := repaircmd.Parse(*c.Cmd); ok {
		return s.recordDiskAction(ctx, session, c)
	}
	if strings.HasPrefix(*c.Cmd, "df -P ") {
		return s.recordDiskProbe(ctx, session, c)
	}
	prefix := "systemctl show --property=Id,ActiveState,UnitFileState -- "
	if !strings.HasPrefix(*c.Cmd, prefix) {
		return nil
	}
	unit := strings.TrimPrefix(*c.Cmd, prefix)
	if !validUnit(unit) || *c.Cmd != ProbeCommand(unit) {
		return nil
	}
	// 其它既有会话不受此策略影响，也不能借它建立自治修复授权证据。
	bound, err := s.DB.TaskRun.Query().Where(taskrun.TaskIDEQ(findings.FollowupTask), taskrun.SessionIDEQ(session.ID), taskrun.StatusEQ("running")).Exist(ctx)
	if err != nil {
		return err
	}
	if !bound {
		return nil
	}
	current, _, err := s.claimed(ctx, session, uuid.Nil)
	if err != nil {
		return err
	}
	rows, err := s.DB.Finding.Query().Where(finding.GroupIDEQ(current.GroupID), finding.WorkSessionIDEQ(current.ID), finding.AssetIDEQ(c.AssetID), finding.StatusEQ("open"), finding.WorkLeaseUntilGT(time.Now())).All(ctx)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errors.New("诊断指令目标未被领取")
	}
	policy, err := s.Load(ctx)
	if err != nil {
		return err
	}
	inScope := false
	for _, grant := range policy.Grants {
		if grant.Action == RestartFailedService && grant.GroupID == current.GroupID && grant.ExpiresAt.After(time.Now()) && slices.Contains(grant.AssetIDs, c.AssetID) && slices.Contains(grant.Units, unit) {
			inScope = true
			break
		}
	}
	if !inScope {
		return nil
	} // 只保留已委托服务的诊断引用，避免任意 unit 名积累配置行。
	actual, err := s.DB.Command.Get(ctx, c.ID)
	if err != nil {
		return err
	}
	if actual.Kind != "exec" || actual.AssetID != c.AssetID || actual.Cmd == nil || *actual.Cmd != ProbeCommand(unit) || actual.CreatedAt.Before(current.CreatedAt) {
		return errors.New("实际诊断指令与会话范围不一致")
	}
	raw, _ := json.Marshal(probeRef{current.ID, c.ID, c.AssetID, unit})
	key := probeKey(c.AssetID, unit)
	n, err := s.DB.Setting.Update().Where(setting.IDEQ(key)).SetValue(raw).Save(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		return s.DB.Setting.Create().SetID(key).SetValue(raw).Exec(ctx)
	}
	return nil
}
func probeKey(asset uuid.UUID, unit string) string {
	return "repair-probe/" + asset.String() + "/" + unit
}
func useKey(asset uuid.UUID, unit string) string { return "repair-use/" + asset.String() + "/" + unit }

// Authorize 只预留一次精确动作；预留后 Gate 拒绝/超时也不重发，避免“没回执就再试”。
func (s *Store) Authorize(ctx context.Context, session *ent.AgentSession, f *ent.Finding, cmd string) error {
	return s.authorize(ctx, session, f, cmd, false)
}

// Revalidate 不新建预留，在审批后重新检查并一次性消费原预留；消费后投递失败也不重放。
func (s *Store) Revalidate(ctx context.Context, session *ent.AgentSession, f *ent.Finding, cmd string) error {
	return s.authorize(ctx, session, f, cmd, true)
}

func (s *Store) authorize(ctx context.Context, session *ent.AgentSession, f *ent.Finding, cmd string, finalize bool) (retErr error) {
	defer func() {
		if retErr == nil {
			return
		}
		logCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		target := "unbound"
		if session != nil {
			target = session.ID.String()
		}
		if err := audit.Checked(logCtx, s.DB.AuditLog.Create(), "system", "server", "repair_action_denied", target, retErr.Error()); err != nil {
			retErr = fmt.Errorf("%w；拒绝审计落库失败", retErr)
		}
	}()

	action, unit := RestartFailedService, ""
	match := restart.FindStringSubmatch(cmd)
	if len(match) == 2 && validUnit(match[1]) {
		unit = match[1]
	} else if _, ok := repaircmd.Parse(cmd); ok {
		action, unit = ReclaimDisk, ReclaimDisk
	} else {
		return errors.New("自主修复仅支持明确授权的 systemctl restart -- <非关键服务>、docker image prune -f、docker builder prune -f、apt-get clean 或 find -- <授权目录> -xdev -type f -mtime +<7..3650> -delete")
	}
	if f == nil {
		return errors.New("缺少待办")
	}
	current, actual, err := s.claimed(ctx, session, f.ID)
	if err != nil {
		return err
	}
	if action == ReclaimDisk && !diskFinding(actual) {
		return errors.New("磁盘回收仅适用于 key/title 明确的磁盘容量待办")
	}
	if actual.AssetID != f.AssetID {
		return errors.New("资产范围变化")
	}
	now := time.Now()
	tx, err := s.DB.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	row, err := tx.Setting.Query().Where(setting.IDEQ(SettingKey)).Where(func(q *sql.Selector) { q.ForUpdate() }).Only(ctx)
	if err != nil {
		return errors.New("未配置可信维护范围，仅只读跟进")
	}
	if _, err := tx.Finding.Query().Where(finding.IDEQ(f.ID)).Where(func(q *sql.Selector) { q.ForUpdate() }).Only(ctx); err != nil {
		return err
	}
	// 行锁可能等待；锁定后重取租约、归组与时间，不能使用等待前的旧授权快照。
	current, actual, err = claimedWithClient(ctx, tx.Client(), session, f.ID)
	if err != nil {
		return err
	}
	now = time.Now()
	if action == ReclaimDisk && !diskFinding(actual) {
		return errors.New("待办已不属于磁盘容量问题")
	}
	work, err := repairWork(actual, finalize)
	if err != nil {
		return err
	}
	problem := problemHash(actual, work)
	var prior use
	if finalize {
		used, err := tx.Setting.Get(ctx, useKey(actual.AssetID, unit))
		if err != nil {
			return errors.New("没有可复核的原维护预留")
		}
		if err := strict(used.Value, &prior); err != nil {
			return err
		}
		if prior.FindingID != actual.ID || prior.SessionID != current.ID || prior.FinalizedAt != nil || (action == ReclaimDisk && prior.Command != cmd) {
			return errors.New("维护预留不匹配或已消费，禁止再次下发")
		}
	}
	var p Policy
	if err := strict(row.Value, &p); err != nil {
		return err
	}
	var grant *Grant
	for i := range p.Grants {
		g := &p.Grants[i]
		if (!finalize || g.ID == prior.GrantID) && grantApplies(*g, current.GroupID, actual.AssetID, now) && actionScope(*g, action, unit, cmd) {
			grant = g
			break
		}
	}
	if grant == nil {
		return errors.New("动作、资产、服务或目录不在当前有效维护范围")
	}
	version := grantVersion(*grant)
	if finalize && (prior.ProblemHash != problem || prior.GrantVersion != version) {
		return errors.New("原问题或维护授权版本已变化，原预留不再适用")
	}

	proofRow, err := tx.Setting.Get(ctx, probeKey(actual.AssetID, unit))
	if err != nil {
		return errors.New("缺少本会话实际下发的固定只读诊断")
	}
	var ref probeRef
	if err := strict(proofRow.Value, &ref); err != nil {
		return err
	}
	if ref.SessionID != current.ID || ref.AssetID != actual.AssetID || (action == RestartFailedService && ref.Unit != unit) {
		return errors.New("诊断关联不匹配")
	}
	probe, err := tx.Command.Get(ctx, ref.CommandID)
	if err != nil {
		return err
	}
	if probe.AssetID != actual.AssetID || probe.Kind != "exec" || probe.Cmd == nil || *probe.Cmd != expectedProbe(action, unit, ref.Unit) || probe.Status != "succeeded" || probe.ExitCode == nil || *probe.ExitCode != 0 || probe.Truncated || probe.CompletedAt == nil || probe.CompletedAt.Before(now.Add(-10*time.Minute)) || probe.CompletedAt.After(now) || probe.CreatedAt.Before(current.CreatedAt) || probe.Stdout == nil {
		return errors.New("诊断未完整成功或已过期")
	}
	if action == ReclaimDisk {
		if _, err := diskSample(probe, ref.Unit); err != nil {
			return err
		}
	} else {
		fields := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(*probe.Stdout), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				return errors.New("systemctl诊断字段不完整或重复")
			}
			if _, duplicate := fields[k]; duplicate {
				return errors.New("systemctl诊断字段不完整或重复")
			}
			fields[k] = v
		}
		if len(fields) != 3 || fields["Id"] != unit || fields["ActiveState"] != "failed" || fields["UnitFileState"] != "enabled" {
			return errors.New("诊断未证明精确目标服务为 failed 且 enabled，禁止猜测或别名绕过")
		}
	}
	pending, err := tx.Command.Query().Where(command.AssetIDEQ(actual.AssetID), command.StatusIn("pending", "sent", "unknown")).All(ctx)
	if err != nil {
		return err
	}
	for _, c := range pending {
		if c.Kind != "exec" || c.Cmd == nil || !commandgate.ReadOnly(*c.Cmd) {
			return errors.New("存在未知写动作，禁止自动重放或新增修复")
		}
	}
	key := useKey(actual.AssetID, unit)
	if finalize {
		reservation := reservationID(*grant, current.ID, actual, unit, problem, version)
		if prior.ProbeID != probe.ID || prior.ReservationID != reservation || prior.ReservedAt.Before(*probe.CompletedAt) {
			return errors.New("原维护预留的诊断或动作身份不匹配")
		}
		finalNow := time.Now()
		if !grant.ExpiresAt.After(finalNow) || probe.CompletedAt.Before(finalNow.Add(-10*time.Minute)) || !current.RunExpiresAt.After(finalNow) || !current.RunDeadlineAt.After(finalNow) || actual.WorkLeaseUntil == nil || !actual.WorkLeaseUntil.After(finalNow) {
			return errors.New("维护范围、诊断或执行租约已过期")
		}
		prior.FinalizedAt = &finalNow
		raw, _ := json.Marshal(prior)
		if err := tx.Setting.UpdateOneID(key).SetValue(raw).Exec(ctx); err != nil {
			return err
		}
		if err := audit.Checked(ctx, tx.AuditLog.Create(), "system", "server", "repair_action_revalidated", actual.ID.String(), "reservation="+reservation.String()+" session="+current.ID.String()); err != nil {
			return err
		}
		return tx.Commit()
	}
	old, err := tx.Setting.Get(ctx, key)
	if err != nil && !ent.IsNotFound(err) {
		return err
	}
	if old != nil {
		var prior use
		if err := strict(old.Value, &prior); err != nil {
			return err
		}
		if prior.SessionID == current.ID || prior.NextAllowedAt.After(now) {
			return errors.New("相同会话已预留动作或仍处于资产动作冷却期")
		}
	}
	reserved := use{Command: cmd, ProblemHash: problem, GrantVersion: version, FindingID: actual.ID, SessionID: current.ID, GrantID: grant.ID, ReservationID: reservationID(*grant, current.ID, actual, unit, problem, version), ReservedAt: now, NextAllowedAt: now.Add(time.Duration(grant.CooldownMinutes) * time.Minute), ProbeID: probe.ID}
	raw, _ := json.Marshal(reserved)
	if old == nil {
		err = tx.Setting.Create().SetID(key).SetValue(raw).Exec(ctx)
	} else {
		err = tx.Setting.UpdateOneID(key).SetValue(raw).Exec(ctx)
	}
	if err != nil {
		return err
	}
	var rawWork map[string]json.RawMessage
	if len(actual.Work) != 0 {
		if err := json.Unmarshal(actual.Work, &rawWork); err != nil {
			return err
		}
	}
	if rawWork == nil {
		rawWork = make(map[string]json.RawMessage)
	}
	count, _ := json.Marshal(work.RepairAttempts + 1)
	rawWork["repair_attempts"] = count
	if work.Version < 2 {
		rawWork["version"] = json.RawMessage(`2`)
	}
	updatedWork, err := json.Marshal(rawWork)
	if err != nil {
		return err
	}
	if err := tx.Finding.UpdateOneID(actual.ID).Where(findings.Snapshot(actual)).SetWork(updatedWork).Exec(ctx); err != nil {
		return err
	}
	if err := audit.Checked(ctx, tx.AuditLog.Create(), "system", "server", "repair_action_reserved", actual.ID.String(), fmt.Sprintf("grant=%s session=%s asset=%s unit=%s probe=%s reservation=%s expires=%s", grant.ID, current.ID, actual.AssetID, unit, probe.ID, reserved.ReservationID, grant.ExpiresAt.UTC().Format(time.RFC3339))); err != nil {
		return err
	}
	return tx.Commit()
}

// HasGrant 仅查询服务端实际保存的精确授权，不把模型声明或相似服务名视为委托。
func (s *Store) HasGrant(ctx context.Context, groupID, assetID uuid.UUID, action, unit string) (bool, error) {
	if groupID == uuid.Nil || assetID == uuid.Nil || (action != RestartFailedService && action != ReclaimDisk) || (action == RestartFailedService && !validUnit(unit)) {
		return false, errors.New("维护范围查询必须指定真实组、资产、精确动作及服务或回收命令")
	}
	owned, err := s.DB.Asset.Query().Where(asset.IDEQ(assetID), asset.GroupIDEQ(groupID), asset.OsEQ("linux")).Exist(ctx)
	if err != nil || !owned {
		return false, err
	}
	policy, err := s.Load(ctx)
	if err != nil {
		return false, err
	}
	now := time.Now()
	for _, grant := range policy.Grants {
		if grantApplies(grant, groupID, assetID, now) && actionScope(grant, action, unit, unit) {
			return true, nil
		}
	}
	return false, nil
}

func repairWork(f *ent.Finding, finalize bool) (findings.Work, error) {
	var work findings.Work
	if len(f.Work) != 0 {
		if err := json.Unmarshal(f.Work, &work); err != nil {
			return work, errors.New("维护预算状态损坏，禁止修复")
		}
	}
	if work.RepairAttempts < 0 || work.RepairAttempts > findings.RepairBudget || (!finalize && work.RepairAttempts == findings.RepairBudget) {
		return work, errors.New("实际修复预算已耗尽或状态无效")
	}
	switch work.Blocker {
	case "legacy_decommission_confirm", "manual_business_decision", "external_dependency":
		return work, errors.New("待办存在退役确认、业务决策或外部依赖阻塞，不自动重启")
	}
	return work, nil
}

func digest(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func problemHash(f *ent.Finding, work findings.Work) string {
	title, problem := work.OriginalTitle, work.OriginalProblem
	if title == "" {
		title = f.Title
	}
	if problem == "" {
		problem = f.Detail
	}
	return digest([]string{f.ID.String(), f.GroupID.String(), f.AssetID.String(), f.Key, f.FirstSeen.UTC().Format(time.RFC3339Nano), title, problem})
}
func grantVersion(grant Grant) string {
	grant.AssetIDs = slices.Clone(grant.AssetIDs)
	slices.SortFunc(grant.AssetIDs, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	grant.Paths = slices.Clone(grant.Paths)
	slices.Sort(grant.Paths)
	grant.Units = slices.Clone(grant.Units)
	slices.Sort(grant.Units)
	grant.ExpiresAt = grant.ExpiresAt.UTC()
	return digest(grant)
}
func reservationID(grant Grant, session uuid.UUID, f *ent.Finding, unit, problem, version string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("openxdr:repair|"+grant.ID.String()+"|"+session.String()+"|"+f.ID.String()+"|"+f.AssetID.String()+"|"+unit+"|"+problem+"|"+version))
}

// HasAssetGrant 只用于判断真实资产是否具有任何有效支持的委托，不由模型声明权限缺失。
func (s *Store) HasAssetGrant(ctx context.Context, groupID, assetID uuid.UUID) (bool, error) {
	if groupID == uuid.Nil || assetID == uuid.Nil {
		return false, errors.New("维护范围查询须指定真实组和资产")
	}
	owned, err := s.DB.Asset.Query().Where(asset.IDEQ(assetID), asset.GroupIDEQ(groupID), asset.OsEQ("linux")).Exist(ctx)
	if err != nil || !owned {
		return false, err
	}
	policy, err := s.Load(ctx)
	if err != nil {
		return false, err
	}
	now := time.Now()
	for _, g := range policy.Grants {
		if !grantApplies(g, groupID, assetID, now) {
			continue
		}
		if g.Action == ReclaimDisk {
			return true, nil
		}
		for _, unit := range g.Units {
			if validUnit(unit) {
				return true, nil
			}
		}
	}
	return false, nil
}

func grantApplies(g Grant, groupID, assetID uuid.UUID, now time.Time) bool {
	return g.ID != uuid.Nil && (g.Action == RestartFailedService || g.Action == ReclaimDisk) && g.GroupID == groupID && g.ExpiresAt.After(now) && !g.ExpiresAt.After(now.Add(30*24*time.Hour)) && g.CooldownMinutes >= 60 && g.CooldownMinutes <= 10080 && slices.Contains(g.AssetIDs, assetID)
}

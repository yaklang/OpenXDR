package repairpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"math/bits"
	"slices"
	"strconv"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/setting"
	"openxdr/server/ent/taskrun"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/repaircmd"
)

func diskFinding(f *ent.Finding) bool {
	if f == nil {
		return false
	}
	text := strings.ToLower(f.Key + " " + f.Title)
	disk := false
	for _, word := range []string{"disk", "filesystem", "磁盘", "分区", "根盘"} {
		disk = disk || strings.Contains(text, word)
	}
	capacity := false
	for _, word := range []string{"full", "capacity", "space", "pressure", "usage", "满", "容量", "空间", "使用率"} {
		capacity = capacity || strings.Contains(text, word)
	}
	return disk && capacity
}

func actionScope(g Grant, action, unit, cmd string) bool {
	if g.Action != action {
		return false
	}
	if action == RestartFailedService {
		return slices.Contains(g.Units, unit)
	}
	dir, ok := repaircmd.Parse(cmd)
	return ok && (dir == "" || slices.Contains(g.Paths, dir))
}
func expectedProbe(action, unit, mount string) string {
	if action == ReclaimDisk {
		return "df -P " + mount
	}
	return ProbeCommand(unit)
}

// recordDiskProbe 复用诊断引用机制；路径只决定探针，不产生目录删除权限。
func (s *Store) recordDiskProbe(ctx context.Context, session *ent.AgentSession, c *ent.Command) error {
	mount := strings.TrimPrefix(*c.Cmd, "df -P ")
	if !repaircmd.Mount(mount) {
		return nil
	}
	bound, err := s.isFollowup(ctx, session)
	if err != nil || !bound {
		return err
	}
	current, _, err := s.claimed(ctx, session, uuid.Nil)
	if err != nil {
		return err
	}
	// claimed 可返回本轮其它主机，仍须精确核对探针主机的领取记录。
	rows, err := s.DB.Finding.Query().Where(finding.AssetIDEQ(c.AssetID), finding.GroupIDEQ(current.GroupID), finding.WorkSessionIDEQ(current.ID), finding.StatusEQ("open"), finding.WorkLeaseUntilGT(time.Now())).All(ctx)
	if err != nil {
		return err
	}
	owned := false
	for _, row := range rows {
		if slices.Contains(current.Subjects, "finding:"+row.ID.String()) && diskFinding(row) {
			owned = true
			break
		}
	}
	if !owned {
		return nil
	}
	policy, err := s.Load(ctx)
	if err != nil {
		return err
	}
	inScope := false
	for _, g := range policy.Grants {
		if g.Action == ReclaimDisk && grantApplies(g, current.GroupID, c.AssetID, time.Now()) {
			inScope = true
			break
		}
	}
	if !inScope {
		return nil
	}
	actual, err := s.DB.Command.Get(ctx, c.ID)
	if err != nil {
		return err
	}
	if actual.Kind != "exec" || actual.AssetID != c.AssetID || actual.Cmd == nil || *actual.Cmd != "df -P "+mount || actual.CreatedAt.Before(current.CreatedAt) {
		return errors.New("实际磁盘探针与会话不匹配")
	}
	raw, _ := json.Marshal(probeRef{current.ID, actual.ID, actual.AssetID, mount})
	key := probeKey(actual.AssetID, ReclaimDisk)
	n, err := s.DB.Setting.Update().Where(setting.IDEQ(key)).SetValue(raw).Save(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		return s.DB.Setting.Create().SetID(key).SetValue(raw).Exec(ctx)
	}
	return nil
}

func (s *Store) recordDiskAction(ctx context.Context, session *ent.AgentSession, c *ent.Command) error {
	bound, err := s.isFollowup(ctx, session)
	if err != nil || !bound {
		return err
	}
	tx, err := s.DB.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	row, err := tx.Setting.Query().Where(setting.IDEQ(useKey(c.AssetID, ReclaimDisk))).Where(func(q *sql.Selector) { q.ForUpdate() }).Only(ctx)
	if err != nil {
		return errors.New("回收已下发但缺少预留，禁止重放")
	}
	var u use
	if err := strict(row.Value, &u); err != nil {
		return err
	}
	actual, err := tx.Command.Get(ctx, c.ID)
	if err != nil {
		return err
	}
	if u.SessionID != session.ID || u.FinalizedAt == nil || u.ActionID != uuid.Nil || actual.Cmd == nil || *actual.Cmd != u.Command || actual.AssetID != c.AssetID || actual.Kind != "exec" || actual.CreatedAt.Before(*u.FinalizedAt) {
		return errors.New("回收指令与一次性预留不匹配，禁止重放")
	}
	u.ActionID = actual.ID
	raw, _ := json.Marshal(u)
	if err := tx.Setting.UpdateOneID(row.ID).SetValue(raw).Exec(ctx); err != nil {
		return err
	}
	if err := audit.Checked(ctx, tx.AuditLog.Create(), "system", "server", "repair_action_issued", u.FindingID.String(), "command="+actual.ID.String()+" reservation="+u.ReservationID.String()); err != nil {
		return err
	}
	return tx.Commit()
}

type diskReading struct {
	filesystem       string
	total, available uint64
}

func diskSample(c *ent.Command, mount string) (diskReading, error) {
	return readDiskSample(c, mount, true)
}

func readDiskSample(c *ent.Command, mount string, fresh bool) (diskReading, error) {
	bad := errors.New("磁盘探针须完整成功且容量、挂载与 df -P 格式一致")
	var sample diskReading
	now := time.Now()
	if !repaircmd.Mount(mount) || c == nil || c.Kind != "exec" || c.Cmd == nil || *c.Cmd != "df -P "+mount || c.Status != "succeeded" || c.ExitCode == nil || *c.ExitCode != 0 || c.Truncated || c.Stdout == nil || len(*c.Stdout) > 8192 || c.CompletedAt == nil || c.CompletedAt.Before(c.CreatedAt) || c.CompletedAt.After(now) || (fresh && c.CompletedAt.Before(now.Add(-10*time.Minute))) || c.Stderr != nil && strings.TrimSpace(*c.Stderr) != "" {
		return sample, bad
	}
	lines := strings.Split(strings.TrimSpace(*c.Stdout), "\n")
	if len(lines) != 2 || strings.Join(strings.Fields(lines[0]), " ") != "Filesystem 1024-blocks Used Available Capacity Mounted on" {
		return sample, bad
	}
	fields := strings.Fields(lines[1])
	if len(fields) != 6 || fields[5] != mount || !strings.HasSuffix(fields[4], "%") {
		return sample, bad
	}
	values := make([]uint64, 4)
	for i, field := range []string{fields[1], fields[2], fields[3], strings.TrimSuffix(fields[4], "%")} {
		if field == "" || strings.IndexFunc(field, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return sample, bad
		}
		n, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return sample, bad
		}
		values[i] = n
	}
	total, used, available, percent := values[0], values[1], values[2], values[3]
	if total == 0 || used > total || available > total-used || used+available == 0 || percent > 100 {
		return sample, bad
	}
	hi, lo := bits.Mul64(used, 100)
	calculated, remainder := bits.Div64(hi, lo, used+available)
	if remainder != 0 {
		calculated++
	}
	if calculated != percent {
		return sample, bad
	}
	return diskReading{fields[0], total, available}, nil
}

// VerifyDisk 独立验证回收效果，不把下发前消费预留或写命令成功当作恢复。
func (s *Store) VerifyDisk(ctx context.Context, session *ent.AgentSession, f *ent.Finding, ids []uuid.UUID) error {
	tx, err := s.DB.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	row, err := tx.Setting.Query().Where(setting.IDEQ(useKey(f.AssetID, ReclaimDisk))).Where(func(q *sql.Selector) { q.ForUpdate() }).Only(ctx)
	if ent.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var u use
	if err := strict(row.Value, &u); err != nil {
		return err
	}
	if u.FindingID != f.ID {
		return nil
	}
	_, actual, err := claimedWithClient(ctx, tx.Client(), session, f.ID)
	if err != nil {
		return err
	}
	if actual.AssetID != f.AssetID || actual.GroupID != f.GroupID {
		return errors.New("回收验证的资产范围已变化")
	}
	if u.FinalizedAt == nil || u.ActionID == uuid.Nil {
		return errors.New("回收未确认下发，不能宣称修复")
	}
	action, err := tx.Command.Get(ctx, u.ActionID)
	if err != nil {
		return err
	}
	if action.AssetID != f.AssetID || action.Kind != "exec" || action.Cmd == nil || *action.Cmd != u.Command || action.Status != "succeeded" || action.ExitCode == nil || *action.ExitCode != 0 || action.CompletedAt == nil || action.CompletedAt.After(time.Now()) || action.CompletedAt.Before(action.CreatedAt) || action.CreatedAt.Before(*u.FinalizedAt) {
		return errors.New("磁盘回收未成功完成，不能确认效果")
	}
	before, err := tx.Command.Get(ctx, u.ProbeID)
	if err != nil {
		return err
	}
	if before.Cmd == nil {
		return errors.New("缺少回收前磁盘探针")
	}
	mount := strings.TrimPrefix(*before.Cmd, "df -P ")
	// 前探针作为历史基线仍必须早于预留；后探针必须是本轮新鲜回执。
	pre, err := readDiskSample(before, mount, false)
	if err != nil || before.CompletedAt == nil || before.CompletedAt.After(u.ReservedAt) || before.AssetID != f.AssetID {
		return errors.New("回收前磁盘基线无效")
	}
	refRow, err := tx.Setting.Get(ctx, probeKey(f.AssetID, ReclaimDisk))
	if err != nil {
		return errors.New("缺少回收后的会话探针")
	}
	var ref probeRef
	if err := strict(refRow.Value, &ref); err != nil {
		return err
	}
	if ref.SessionID != session.ID || ref.AssetID != f.AssetID || ref.Unit != mount || !slices.Contains(ids, ref.CommandID) || ref.CommandID == before.ID {
		return errors.New("须引用服务端关联的同挂载回收后 df -P 探针")
	}
	after, err := tx.Command.Get(ctx, ref.CommandID)
	if err != nil {
		return err
	}
	post, err := diskSample(after, mount)
	if err != nil {
		return err
	}
	if after.AssetID != f.AssetID || after.CreatedAt.Before(session.CreatedAt) || !after.CreatedAt.After(*action.CompletedAt) || post.filesystem != pre.filesystem || post.total != pre.total || post.available <= pre.available {
		return errors.New("独立 df 探针尚未证明同一文件系统可用空间增加")
	}
	now := time.Now()
	u.VerifiedAt, u.AfterProbeID = &now, after.ID
	raw, _ := json.Marshal(u)
	if err := tx.Setting.UpdateOneID(row.ID).SetValue(raw).Exec(ctx); err != nil {
		return err
	}
	if err := audit.Checked(ctx, tx.AuditLog.Create(), "system", "server", "repair_action_verified", f.ID.String(), "before="+before.ID.String()+" after="+after.ID.String()+" command="+action.ID.String()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) isFollowup(ctx context.Context, session *ent.AgentSession) (bool, error) {
	if session == nil {
		return false, errors.New("缺少真实任务会话")
	}
	return s.DB.TaskRun.Query().Where(taskrun.TaskIDEQ(findings.FollowupTask), taskrun.SessionIDEQ(session.ID), taskrun.GroupIDEQ(session.GroupID), taskrun.StatusEQ("running")).Exist(ctx)
}

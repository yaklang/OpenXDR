package agentchat

import (
	"context"
	"encoding/json"
	"errors"
	"math/bits"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/command"
	"openxdr/server/internal/findings"
)

// findingRisk 仅读取固定探针的完整回执；目标由平台绑定，模型标题和级别不构成风险证据。
func (s *Service) findingRisk(ctx context.Context, session *ent.AgentSession, f *ent.Finding, ids []uuid.UUID) (string, time.Time, error) {
	if f.GroupID != session.GroupID {
		return "", time.Time{}, errors.New("风险待办不属于当前组")
	}
	var work findings.Work
	if len(f.Work) > 0 && json.Unmarshal(f.Work, &work) != nil {
		return "", time.Time{}, errors.New("风险目标计划损坏")
	}
	if work.RiskTarget == nil {
		return "", time.Time{}, nil
	}
	if work.RiskTarget.AssetID != f.AssetID {
		return "", time.Time{}, errors.New("风险目标不属于当前主机或组")
	}
	probe := ""
	switch work.RiskTarget.Kind {
	case "disk_root":
		if work.RiskTarget.Mount != "/" {
			return "", time.Time{}, errors.New("根磁盘风险目标必须精确为根挂载")
		}
		probe = "df -P /"
	case "memory":
		if work.RiskTarget.Mount != "" {
			return "", time.Time{}, errors.New("内存风险目标不能包含挂载路径")
		}
		probe = "free -b"
	default:
		return "", time.Time{}, nil
	}
	current, err := s.DB.Asset.Query().Where(asset.IDEQ(f.AssetID), asset.GroupIDEQ(session.GroupID)).Exist(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	if !current {
		return "", time.Time{}, errors.New("风险主机已移出本组")
	}
	if len(ids) > 5 {
		return "", time.Time{}, errors.New("风险探针最多引用五条本轮指令")
	}
	now := time.Now()
	seen := make(map[uuid.UUID]bool, len(ids))
	kind := ""
	var observed time.Time
	for _, id := range ids {
		if id == uuid.Nil || seen[id] {
			return "", time.Time{}, errors.New("风险探针指令编号无效或重复")
		}
		seen[id] = true
		c, err := s.DB.Command.Query().Where(command.IDEQ(id), command.AssetIDEQ(f.AssetID)).Only(ctx)
		if err != nil {
			return "", time.Time{}, errors.New("风险探针不存在或不属该主机")
		}
		if c.CreatedAt.Before(session.CreatedAt) || c.CreatedAt.After(now) || session.CreatedAt.After(now) {
			return "", time.Time{}, errors.New("风险探针不属于本轮有效时间范围")
		}
		if c.Kind != "exec" || c.Cmd == nil || *c.Cmd != probe {
			continue
		}
		if c.Status != "succeeded" || c.ExitCode == nil || *c.ExitCode != 0 || c.CompletedAt == nil || c.CompletedAt.Before(c.CreatedAt) || c.CompletedAt.After(now) || c.CompletedAt.Before(now.Add(-10*time.Minute)) || c.Truncated || c.Stdout == nil || strings.TrimSpace(*c.Stdout) == "" || len(*c.Stdout) > 8192 || c.Stderr != nil && strings.TrimSpace(*c.Stderr) != "" {
			return "", time.Time{}, errors.New("风险探针须为新鲜、完整、无错误的成功回执")
		}
		var measured string
		if probe == "df -P /" {
			measured, err = parseFindingDiskRisk(*c.Stdout)
		} else {
			measured, err = parseFindingMemoryRisk(*c.Stdout)
		}
		if err != nil {
			return "", time.Time{}, err
		}
		if c.CompletedAt.Equal(observed) && measured != kind {
			return "", time.Time{}, errors.New("同刻风险探针相互矛盾，不能据此判断恢复")
		}
		if observed.IsZero() || c.CompletedAt.After(observed) {
			kind, observed = measured, *c.CompletedAt
		}
	}
	// 查询期间转组的旧回执不能用于新的风险判断。
	current, err = s.DB.Asset.Query().Where(asset.IDEQ(f.AssetID), asset.GroupIDEQ(session.GroupID)).Exist(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	if !current {
		return "", time.Time{}, errors.New("风险主机已移出本组")
	}
	if kind == "" {
		return "", time.Time{}, nil
	}
	return kind, observed, nil
}

func findingProbeLines(out string) []string {
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func findingProbeUint(s string) (uint64, error) {
	if s == "" {
		return 0, errors.New("风险探针数值缺失")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("风险探针数值无效")
		}
	}
	return strconv.ParseUint(s, 10, 64)
}

func parseFindingDiskRisk(out string) (string, error) {
	bad := errors.New("根磁盘探针格式、容量或挂载不一致")
	lines := findingProbeLines(out)
	if len(lines) != 2 || strings.Join(strings.Fields(lines[0]), " ") != "Filesystem 1024-blocks Used Available Capacity Mounted on" {
		return "", bad
	}
	row := strings.Fields(lines[1])
	if len(row) != 6 || row[5] != "/" || !strings.HasSuffix(row[4], "%") {
		return "", bad
	}
	total, e1 := findingProbeUint(row[1])
	used, e2 := findingProbeUint(row[2])
	available, e3 := findingProbeUint(row[3])
	percent, e4 := findingProbeUint(strings.TrimSuffix(row[4], "%"))
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || total == 0 || used > total || available > total-used || used+available == 0 || percent > 100 {
		return "", bad
	}
	// POSIX df 容量按 used/(used+available) 向上取整；保留块不包含在 available 中。
	hi, lo := bits.Mul64(used, 100)
	calculated, remainder := bits.Div64(hi, lo, used+available)
	if remainder != 0 {
		calculated++
	}
	if calculated != percent {
		return "", bad
	}
	if percent >= 95 {
		return "disk_pressure", nil
	}
	return "disk_ok", nil
}

func parseFindingMemoryRisk(out string) (string, error) {
	bad := errors.New("内存探针必须包含唯一且完整的字节容量行")
	lines := findingProbeLines(out)
	if len(lines) != 3 || strings.Join(strings.Fields(lines[0]), " ") != "total used free shared buff/cache available" {
		return "", bad
	}
	mem, swap := strings.Fields(lines[1]), strings.Fields(lines[2])
	if len(mem) != 7 || mem[0] != "Mem:" || len(swap) != 4 || swap[0] != "Swap:" {
		return "", bad
	}
	m := make([]uint64, 6)
	v := make([]uint64, 3)
	for i := range m {
		value, err := findingProbeUint(mem[i+1])
		if err != nil {
			return "", bad
		}
		m[i] = value
	}
	for i := range v {
		value, err := findingProbeUint(swap[i+1])
		if err != nil {
			return "", bad
		}
		v[i] = value
	}
	if m[0] == 0 || v[1] > v[0] || v[2] != v[0]-v[1] {
		return "", bad
	}
	for _, value := range m[1:] {
		if value > m[0] {
			return "", bad
		}
	}
	lowMemory := m[5] <= m[0]/10 && m[5] <= 2<<30
	// 分段计算 95% 的向上取整阈值，避免 uint64 乘法溢出。
	threshold := v[0]/100*95 + (v[0]%100*95+99)/100
	if lowMemory && v[0] > 0 && v[1] >= threshold {
		return "memory_pressure", nil
	}
	if !lowMemory || v[0] > 0 {
		return "memory_ok", nil
	}
	// 没有 swap 且可用内存仍低，不把“无法满足该探针条件”冒充恢复。
	return "", nil
}

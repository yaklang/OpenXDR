// Package schedule 预设任务调度：仓库 tasks/*.yml 定义任务，到点按组拉起 Pi 会话。
package schedule

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/robfig/cron/v3"
	// CRON_TZ= 要按名字加载时区；运行镜像是 alpine，未必带 tzdata，内嵌一份保证可解析
	"gopkg.in/yaml.v3"
	_ "time/tzdata"

	"openxdr/server/ent"
	enttask "openxdr/server/ent/task"
)

// Spec 任务 YAML 的结构。
type Spec struct {
	ID            string `yaml:"id"`
	Name          string `yaml:"name"`
	NameEN        string `yaml:"name_en"`
	Description   string `yaml:"description"`
	DescriptionEN string `yaml:"description_en"`
	// ops 运维 / security 安全 / report 报告
	Category string `yaml:"category"`
	// 首次同步进库时的开关，默认开；之后启停归界面，YAML 改它不覆盖
	Enabled  *bool  `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
	Model    string `yaml:"model"`
	Targets  struct {
		Group string `yaml:"group"`
	} `yaml:"targets"`
	ApprovalTimeout   string `yaml:"approval_timeout"`
	Prompt            string `yaml:"prompt"`
	RuntimeCapability string `yaml:"runtime_capability"`

	approvalTimeout time.Duration
}

// ParseSchedule 五段 cron，支持 @daily 等描述符与 CRON_TZ= 前缀。
func ParseSchedule(s string) (cron.Schedule, error) { return cron.ParseStandard(s) }

func parseSpec(data []byte) (Spec, error) {
	var s Spec
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // 拼错的字段直接拒绝，不能静默变成默认值
	if err := dec.Decode(&s); err != nil {
		return s, err
	}
	// 新任务在旧节点 KnownFields 校验时整项拒绝，避免滚动升级期间落到无自治闸门的执行器。
	if s.RuntimeCapability != "" && s.RuntimeCapability != "finding_work_v1" {
		return s, errors.New("不支持的任务运行时能力")
	}
	if s.ID == "ops-followup" && s.RuntimeCapability != "finding_work_v1" {
		return s, errors.New("自治跟进任务必须声明 finding_work_v1 运行时能力")
	}
	if s.RuntimeCapability == "finding_work_v1" && s.ID != "ops-followup" {
		return s, errors.New("运行时能力与任务身份不匹配")
	}
	switch {
	case s.ID == "":
		return s, errors.New("id 必填")
	case s.Prompt == "":
		return s, errors.New("prompt 必填")
	}
	if _, err := ParseSchedule(s.Schedule); err != nil {
		return s, fmt.Errorf("schedule 无效: %w", err)
	}
	if s.Name == "" {
		s.Name = s.ID
	}
	switch s.Category {
	case "", "ops", "security", "report":
	default:
		return s, fmt.Errorf("category 只能是 ops / security / report: %q", s.Category)
	}
	if s.Targets.Group == "" {
		s.Targets.Group = "*"
	}
	s.approvalTimeout = 10 * time.Minute
	if s.ApprovalTimeout != "" {
		d, err := time.ParseDuration(s.ApprovalTimeout)
		if err != nil || d <= 0 {
			return s, fmt.Errorf("approval_timeout 无效: %q", s.ApprovalTimeout)
		}
		s.approvalTimeout = d
	}
	return s, nil
}

// LoadDir 读目录下全部 *.yml / *.yaml。坏文件跳过并记日志：坏任务不跑，不拖累好任务。
func LoadDir(dir string) []Spec {
	files, _ := filepath.Glob(filepath.Join(dir, "*.yml"))
	more, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
	var specs []Spec
	seen := map[string]string{}
	for _, f := range append(files, more...) {
		data, err := os.ReadFile(f)
		if err == nil {
			var s Spec
			if s, err = parseSpec(data); err == nil {
				if prev, dup := seen[s.ID]; dup {
					err = fmt.Errorf("id %q 与 %s 重复", s.ID, prev)
				} else {
					seen[s.ID] = f
					specs = append(specs, s)
					continue
				}
			}
		}
		slog.Error("任务文件无效，已跳过", "file", f, "err", err)
	}
	return specs
}

// Sync 把 YAML 定义同步进库。启停与自定义周期归界面，不覆盖；
// YAML 里消失的任务标记 removed，停止调度但保留运行历史。
func Sync(ctx context.Context, db *ent.Client, specs []Spec) error {
	ids := make([]string, len(specs))
	for i, s := range specs {
		ids[i] = s.ID
		timeout := int64(s.approvalTimeout / time.Second)
		err := db.Task.UpdateOneID(s.ID).
			SetName(s.Name).SetNameEn(s.NameEN).SetDescription(s.Description).SetDescriptionEn(s.DescriptionEN).SetCategory(s.Category).
			SetSchedule(s.Schedule).SetModel(s.Model).
			SetTargetGroup(s.Targets.Group).SetPrompt(s.Prompt).
			SetApprovalTimeoutSeconds(timeout).SetRemoved(false).
			Exec(ctx)
		if ent.IsNotFound(err) {
			err = db.Task.Create().
				SetID(s.ID).SetName(s.Name).SetNameEn(s.NameEN).SetDescription(s.Description).SetDescriptionEn(s.DescriptionEN).SetCategory(s.Category).
				SetEnabled(s.Enabled == nil || *s.Enabled).
				SetSchedule(s.Schedule).SetModel(s.Model).
				SetTargetGroup(s.Targets.Group).SetPrompt(s.Prompt).
				SetApprovalTimeoutSeconds(timeout).
				Exec(ctx)
		}
		if err != nil {
			return err
		}
	}
	return db.Task.Update().Where(enttask.IDNotIn(ids...), enttask.Removed(false)).SetRemoved(true).Exec(ctx)
}

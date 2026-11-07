package commandreview

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/command"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/redact"
)

var reviewPrivateKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
var reviewSecretLine = regexp.MustCompile(`(?im)^.*(?:password|passwd|secret|token|api[_-]?key|authorization)["']?\s*[:=].*$`)

func reviewText(s string) string {
	return reviewSecretLine.ReplaceAllString(reviewPrivateKey.ReplaceAllString(redact.String(s), "[凭据已隐去]"), "[凭据字段已隐去]")
}

// 审计材料只来自目标资产的实际回执，不信模型在说明里转述的指令ID或健康结论。
func (r *Reviewer) currentEvidence(ctx context.Context, session *ent.AgentSession, host uuid.UUID) (string, error) {
	owned, err := r.DB.Asset.Query().Where(asset.IDEQ(host), asset.GroupIDEQ(session.GroupID)).Exist(ctx)
	if err != nil {
		return "", err
	}
	if !owned {
		return "", errors.New("待审资产不属于当前会话组")
	}
	now := time.Now()
	since := now.Add(-30 * time.Minute)
	if session.CreatedAt.After(since) {
		since = session.CreatedAt
	}
	rows, err := r.DB.Command.Query().Where(command.AssetIDEQ(host), command.KindEQ("exec"), command.CreatedAtGTE(since), command.CreatedAtLTE(now)).Order(ent.Desc(command.FieldCreatedAt), ent.Desc(command.FieldID)).Limit(24).All(ctx)
	if err != nil {
		return "", err
	}
	type receipt struct {
		ID          uuid.UUID  `json:"id"`
		CreatedAt   time.Time  `json:"created_at"`
		CompletedAt *time.Time `json:"completed_at"`
		Command     string     `json:"command"`
		Status      string     `json:"status"`
		ExitCode    *int32     `json:"exit_code"`
		ReadOnly    bool       `json:"read_only"`
		Complete    bool       `json:"complete_fresh_probe"`
		Clipped     bool       `json:"material_clipped"`
		Stdout      string     `json:"stdout"`
		Stderr      string     `json:"stderr"`
	}
	out := []receipt{}
	for _, c := range rows {
		if len(out) == 10 {
			break
		}
		if c.Cmd == nil {
			continue
		}
		stdout, stderr := "", ""
		if c.Stdout != nil {
			stdout = reviewText(*c.Stdout)
		}
		if c.Stderr != nil {
			stderr = reviewText(*c.Stderr)
		}
		clipped := utf8.RuneCountInString(stdout) > 3500 || utf8.RuneCountInString(stderr) > 1000
		ro := commandgate.ReadOnly(*c.Cmd)
		complete := ro && c.Status == "succeeded" && c.ExitCode != nil && *c.ExitCode == 0 && !c.Truncated && !clipped && c.CompletedAt != nil && !c.CreatedAt.After(*c.CompletedAt) && !c.CompletedAt.Before(since) && !c.CompletedAt.After(now) && stdout != ""
		out = append(out, receipt{ID: c.ID, CreatedAt: c.CreatedAt, CompletedAt: c.CompletedAt, Command: Clip(reviewText(*c.Cmd), 2000), Status: c.Status, ExitCode: c.ExitCode, ReadOnly: ro, Complete: complete, Clipped: clipped, Stdout: Clip(stdout, 3500), Stderr: Clip(stderr, 1000)})
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return "平台实时读取的目标资产最近30分钟真实指令回执（新到旧；complete_fresh_probe=false不得作为完整健康证明；没有回执不等于健康）：\n" + string(b), nil
}

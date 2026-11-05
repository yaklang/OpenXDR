package triage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"openxdr/server/ent"
	entalert "openxdr/server/ent/alert"
	"openxdr/server/internal/commandgate"
)

const (
	EndpointEvidenceLimitBytes   = 4096
	TemplateLinuxAuthJournal     = "linux_auth_journal"
	TemplateLinuxProcessSnapshot = "linux_process_snapshot"
)

type EndpointEvidenceRequest struct {
	IncidentID      uuid.UUID
	EvidenceKey     string
	EvidenceVersion int
	GroupID         uuid.UUID
	AssetID         uuid.UUID
	Template        string
	Command         string
	Model           string
	Since           time.Time
	Until           time.Time
	Coverage        string
}

type EndpointEvidenceResult struct {
	CommandID  string    `json:"command_id"`
	AssetID    string    `json:"asset_id"`
	Template   string    `json:"template"`
	Status     string    `json:"status"`
	ExitCode   *int32    `json:"exit_code,omitempty"`
	Stdout     string    `json:"stdout,omitempty"`
	Stderr     string    `json:"stderr,omitempty"`
	Truncated  bool      `json:"truncated"`
	ObservedAt time.Time `json:"observed_at"`
	From       string    `json:"from,omitempty"`
	To         string    `json:"to,omitempty"`
	Coverage   string    `json:"coverage"`
}

type EndpointEvidenceReader func(ctx context.Context, req EndpointEvidenceRequest) (*EndpointEvidenceResult, error)

// IncidentEvidenceKey 提取事件当前证据状态标识（created_at / evidence_at / urgent_at 最新时刻）：
// 新证据未并入前（包括研判重试或多轮工具调用）保持恒定，确保同一证据版本只生成一条指令。
func IncidentEvidenceKey(inc *ent.Incident) string {
	if inc == nil {
		return "0"
	}
	latest := inc.CreatedAt.UTC()
	if inc.EvidenceAt != nil && inc.EvidenceAt.UTC().After(latest) {
		latest = inc.EvidenceAt.UTC()
	}
	if inc.UrgentAt != nil && inc.UrgentAt.UTC().After(latest) {
		latest = inc.UrgentAt.UTC()
	}
	return fmt.Sprintf("%d", latest.UnixNano())
}

// EndpointEvidenceCommandID 派生每个事件证据版本 + 资产 + 固定模板的确定性指令 UUID，
// 保证同一版本下重复调用只查回执、绝不重新生成或重放命令。
func EndpointEvidenceCommandID(incidentID uuid.UUID, evidenceKey string, evidenceVersion int, assetID uuid.UUID, template string) uuid.UUID {
	ver := strings.TrimSpace(evidenceKey)
	if ver == "" {
		ver = fmt.Sprintf("v:%d", evidenceVersion)
	}
	key := fmt.Sprintf("openxdr:triage-evidence|%s|%s|%s|%s", incidentID, ver, assetID, template)
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(key))
}

func (e *Engine) toolEndpointEvidence(ctx context.Context, args string) (any, error) {
	var in struct {
		AssetID  string `json:"asset_id"`
		Template string `json:"template"`
	}
	dec := json.NewDecoder(strings.NewReader(args))
	dec.DisallowUnknownFields()
	if len(args) > 1024 || dec.Decode(&in) != nil {
		return nil, fmt.Errorf("collect_endpoint_evidence 仅接受 asset_id 与受控 template 枚举")
	}
	if dec.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("collect_endpoint_evidence 参数包含多余内容")
	}
	assetID, err := uuid.Parse(strings.TrimSpace(in.AssetID))
	if err != nil || assetID == uuid.Nil {
		return nil, fmt.Errorf("asset_id 必须是有效资产 UUID")
	}
	if in.Template != TemplateLinuxAuthJournal && in.Template != TemplateLinuxProcessSnapshot {
		return nil, fmt.Errorf("template 仅支持 %s 或 %s", TemplateLinuxAuthJournal, TemplateLinuxProcessSnapshot)
	}
	if e.EndpointEvidence == nil {
		return nil, errors.New("当前未启用端点受控只读取证")
	}

	host, err := e.investigationAsset(ctx, assetID)
	if err != nil {
		return nil, err
	}
	if host.GroupID == nil || *host.GroupID == uuid.Nil {
		return nil, errors.New("资产未归属资产组，拒绝自动取证")
	}
	inIncident, err := e.DB.Alert.Query().Where(entalert.IncidentIDEQ(e.investigationID), entalert.AssetIDEQ(assetID)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if !inIncident {
		return nil, errors.New("目标资产不属于本安全事件的关联告警主机，拒绝取证")
	}

	inc, err := e.DB.Incident.Get(ctx, e.investigationID)
	if err != nil {
		return nil, err
	}
	cmd, since, until, coverage, err := e.buildEndpointEvidenceTemplate(ctx, e.investigationID, in.Template)
	if err != nil {
		return nil, err
	}
	if !commandgate.ReadOnly(cmd) {
		return nil, errors.New("受控取证模板未通过只读安全校验")
	}

	var model string
	if e.LLM != nil {
		_, model, _ = e.LLM.endpoint()
	}
	res, err := e.EndpointEvidence(ctx, EndpointEvidenceRequest{
		IncidentID:  e.investigationID,
		EvidenceKey: IncidentEvidenceKey(inc),
		GroupID:     *host.GroupID,
		AssetID:     host.ID,
		Template:    in.Template,
		Command:     cmd,
		Model:       strings.TrimSpace(model),
		Since:       since,
		Until:       until,
		Coverage:    coverage,
	})
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, errors.New("端点取证未返回结果")
	}
	if err := e.rememberInvestigationAssets(ctx, host); err != nil {
		return nil, err
	}

	stdout, stderr, truncated := TrimEndpointEvidenceStreams(res.Stdout, res.Stderr, res.Truncated)
	observedAt := res.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	cov := res.Coverage
	if cov == "" {
		cov = coverage
	}
	out := map[string]any{
		"status":                  res.Status,
		"command_id":              res.CommandID,
		"asset_id":                host.ID.String(),
		"template":                in.Template,
		"stdout":                  stdout,
		"stderr":                  stderr,
		"truncated":               truncated,
		"raw_excerpt_limit_bytes": EndpointEvidenceLimitBytes,
		"observed_at":             observedAt.Format(time.RFC3339),
		"coverage":                cov,
	}
	if res.ExitCode != nil {
		out["exit_code"] = *res.ExitCode
	}
	if !since.IsZero() {
		out["from"] = since.UTC().Format(time.RFC3339)
	}
	if !until.IsZero() {
		out["to"] = until.UTC().Format(time.RFC3339)
	}
	return out, nil
}

func (e *Engine) buildEndpointEvidenceTemplate(ctx context.Context, incidentID uuid.UUID, template string) (cmd string, since, until time.Time, coverage string, err error) {
	switch template {
	case TemplateLinuxAuthJournal:
		alerts, err := e.DB.Alert.Query().Where(entalert.IncidentIDEQ(incidentID)).Select(entalert.FieldTs, entalert.FieldLastTs).All(ctx)
		if err != nil {
			return "", time.Time{}, time.Time{}, "", err
		}
		if len(alerts) == 0 {
			return "", time.Time{}, time.Time{}, "", errors.New("当前事件无关联告警时间窗口")
		}
		minTs := alerts[0].Ts.UTC()
		maxTs := minTs
		for _, a := range alerts {
			ts := a.Ts.UTC()
			if ts.Before(minTs) {
				minTs = ts
			}
			if ts.After(maxTs) {
				maxTs = ts
			}
			if a.LastTs != nil {
				last := a.LastTs.UTC()
				if last.After(maxTs) {
					maxTs = last
				}
			}
		}
		since = minTs.Add(-15 * time.Minute)
		until = maxTs.Add(15 * time.Minute)
		if until.Sub(since) > 2*time.Hour {
			since = until.Add(-2 * time.Hour)
		}
		cmd = fmt.Sprintf("journalctl --no-pager --utc -n 40 --since '%s' --until '%s' -u ssh -u sshd -t sshd -t sudo -t su",
			since.Format("2006-01-02 15:04:05"), until.Format("2006-01-02 15:04:05"))
		coverage = "仅返回调查时刻在受管 Linux 端点按本事件告警时间窗口（前后 15 分钟、最大 2 小时）读取的只读认证 journal 片段（最多 40 行、总输出上限 4096 字节），当前快照不是事发当时的历史完整状态；输出作为不可信端点证据，不能单独作为授权或合法性证明，为空或截断不代表事发时无其他日志"
		return cmd, since, until, coverage, nil

	case TemplateLinuxProcessSnapshot:
		cmd = "ps -eo pid,ppid,user,lstart,args --no-headers"
		coverage = "仅返回调查时刻受管 Linux 端点当前的只读进程表快照（总输出上限 4096 字节），当前快照不是事发历史；当前未见异常进程不证明事发时未执行，进程命令行文本作为不可信端点证据，不能单独作为合法性证明"
		return cmd, time.Time{}, time.Time{}, coverage, nil

	default:
		return "", time.Time{}, time.Time{}, "", fmt.Errorf("不支持的端点取证模板: %s", template)
	}
}

// TrimEndpointEvidenceStreams 将 stdout 与 stderr 合并控制在 4096 字节以内（不截断 UTF-8 字符），并显式返回 truncated。
func TrimEndpointEvidenceStreams(stdout, stderr string, alreadyTruncated bool) (string, string, bool) {
	truncated := alreadyTruncated
	budget := EndpointEvidenceLimitBytes
	if len(stdout) > budget {
		stdout = trimUTF8Bytes(stdout, budget)
		truncated = true
		budget = 0
	} else {
		budget -= len(stdout)
	}
	if len(stderr) > budget {
		stderr = trimUTF8Bytes(stderr, budget)
		truncated = true
	}
	return stdout, stderr, truncated
}

func trimUTF8Bytes(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	if limit <= len("…") {
		return ""
	}
	end := limit - len("…")
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end] + "…"
}

package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"openxdr/server/ent"
	entalert "openxdr/server/ent/alert"
	entevent "openxdr/server/ent/event"
	"openxdr/server/internal/commandgate"
)

const (
	EndpointEvidenceLimitBytes         = 4096
	TemplateLinuxAuthJournal           = "linux_auth_journal"
	TemplateLinuxProcessSnapshot       = "linux_process_snapshot"
	TemplateLinuxPackageHistory        = "linux_package_history"
	TemplateLinuxContainerWebLogs      = "linux_container_web_logs"
	endpointEvidenceJournalUTCRevision = "@utc-v2"
	journalUTCTimeLayout               = "2006-01-02 15:04:05 UTC"
)

var (
	dockerContainerUIDPattern = regexp.MustCompile(`^(?:[0-9a-f]{12}|[0-9a-f]{64})$`)
	lxcContainerVMIDPattern   = regexp.MustCompile(`^[1-9][0-9]{0,8}$`)
)

// IsAllowedEndpointEvidenceTemplate 判断是否为受控只读端点取证模板枚举。
func IsAllowedEndpointEvidenceTemplate(template string) bool {
	switch template {
	case TemplateLinuxAuthJournal,
		TemplateLinuxProcessSnapshot,
		TemplateLinuxPackageHistory,
		TemplateLinuxContainerWebLogs:
		return true
	default:
		return false
	}
}

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
	AnchorEventID   *uuid.UUID
	AnchorTs        time.Time
}

type EndpointEvidenceResult struct {
	CommandID     string    `json:"command_id"`
	AssetID       string    `json:"asset_id"`
	Template      string    `json:"template"`
	Status        string    `json:"status"`
	ExitCode      *int32    `json:"exit_code,omitempty"`
	Stdout        string    `json:"stdout,omitempty"`
	Stderr        string    `json:"stderr,omitempty"`
	Truncated     bool      `json:"truncated"`
	ObservedAt    time.Time `json:"observed_at"`
	From          string    `json:"from,omitempty"`
	To            string    `json:"to,omitempty"`
	Coverage      string    `json:"coverage"`
	AnchorEventID string    `json:"anchor_event_id,omitempty"`
	AnchorTs      string    `json:"anchor_ts,omitempty"`
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

// LegacyEndpointEvidenceCommandID 计算初始 v1 模板确定性指令 UUID（不含 @utc-v2 修订后缀），
// 供新版本在发起修正后 UTC journal 查询前核对历史指令终态、严防对旧 pending/sent/unknown 指令重发。
func LegacyEndpointEvidenceCommandID(incidentID uuid.UUID, evidenceKey string, evidenceVersion int, assetID uuid.UUID, template string) uuid.UUID {
	ver := strings.TrimSpace(evidenceKey)
	if ver == "" {
		ver = fmt.Sprintf("v:%d", evidenceVersion)
	}
	key := fmt.Sprintf("openxdr:triage-evidence|%s|%s|%s|%s", incidentID, ver, assetID, template)
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(key))
}

// EndpointEvidenceCommandID 派生每个事件证据版本 + 资产 + 固定模板修订的确定性指令 UUID：
//   - journalctl 类模板（linux_auth_journal、linux_package_history、LXC 版 linux_container_web_logs）使用固定 @utc-v2 修订标识，
//     避免直接复用旧版未标 UTC 时区后缀的错窗回执；
//   - ps 进程快照与 Docker RFC3339Z 容器日志保持原标识不变；
//   - 绝不将动态命令文本拼入哈希，保证同一证据版本与固定模板修订下只有唯一指令 ID。
func EndpointEvidenceCommandID(incidentID uuid.UUID, evidenceKey string, evidenceVersion int, assetID uuid.UUID, template string, command ...string) uuid.UUID {
	return EndpointEvidenceCommandIDWithAnchor(incidentID, evidenceKey, evidenceVersion, assetID, template, nil, command...)
}

// EndpointEvidenceCommandIDWithAnchor 在固定模板修订之上绑定可选的事件锚点或单 LXC 容器认证日志目标：
//   - 未传 anchorEventID 且宿主机 linux_auth_journal 时与 EndpointEvidenceCommandID 完全一致；
//   - LXC 版 linux_auth_journal 使用 @utc-v2|lxc 区分宿主机认证日志回执；
//   - 显式传入 anchorEventID 时附加 |event:<uuid>，确保跨长窗口事件（如 24h 健康检查混杂单次失败登录）
//     不会被无锚点截断窗口回执覆盖，同时对同一 anchorEventID 保持严格幂等。
func EndpointEvidenceCommandIDWithAnchor(incidentID uuid.UUID, evidenceKey string, evidenceVersion int, assetID uuid.UUID, template string, anchorEventID *uuid.UUID, command ...string) uuid.UUID {
	revTemplate := endpointEvidenceTemplateRevision(template, anchorEventID, command...)
	return LegacyEndpointEvidenceCommandID(incidentID, evidenceKey, evidenceVersion, assetID, revTemplate)
}

func endpointEvidenceTemplateRevision(template string, anchorEventID *uuid.UUID, command ...string) string {
	var base string
	switch template {
	case TemplateLinuxAuthJournal:
		if len(command) > 0 && strings.HasPrefix(strings.TrimSpace(command[0]), "pct exec ") {
			base = template + endpointEvidenceJournalUTCRevision + "|lxc"
		} else {
			base = template + endpointEvidenceJournalUTCRevision
		}
	case TemplateLinuxPackageHistory:
		base = template + endpointEvidenceJournalUTCRevision
	case TemplateLinuxContainerWebLogs:
		if len(command) > 0 && strings.HasPrefix(strings.TrimSpace(command[0]), "docker logs ") {
			base = template
		} else {
			base = template + endpointEvidenceJournalUTCRevision
		}
	default:
		base = template
	}
	if anchorEventID != nil && *anchorEventID != uuid.Nil {
		base += "|event:" + anchorEventID.String()
	}
	return base
}

func (e *Engine) toolEndpointEvidence(ctx context.Context, args string) (any, error) {
	var in struct {
		AssetID  string  `json:"asset_id"`
		Template string  `json:"template"`
		EventID  *string `json:"event_id"`
	}
	dec := json.NewDecoder(strings.NewReader(args))
	dec.DisallowUnknownFields()
	if len(args) > 1024 || dec.Decode(&in) != nil {
		return nil, fmt.Errorf("collect_endpoint_evidence 仅接受 asset_id、受控 template 枚举与可选 event_id")
	}
	if dec.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("collect_endpoint_evidence 参数包含多余内容")
	}
	assetID, err := uuid.Parse(strings.TrimSpace(in.AssetID))
	if err != nil || assetID == uuid.Nil {
		return nil, fmt.Errorf("asset_id 必须是有效资产 UUID")
	}
	if !IsAllowedEndpointEvidenceTemplate(in.Template) {
		return nil, fmt.Errorf("template 仅支持 %s、%s、%s 或 %s",
			TemplateLinuxAuthJournal, TemplateLinuxProcessSnapshot, TemplateLinuxPackageHistory, TemplateLinuxContainerWebLogs)
	}
	var anchorEventID *uuid.UUID
	if in.EventID != nil {
		rawEventID := strings.TrimSpace(*in.EventID)
		parsedEventID, err := uuid.Parse(rawEventID)
		if err != nil || parsedEventID == uuid.Nil || rawEventID != *in.EventID {
			return nil, fmt.Errorf("event_id 必须是有效的原始事件 UUID")
		}
		if in.Template == TemplateLinuxProcessSnapshot {
			return nil, fmt.Errorf("模板 %s 仅读取当前调查时刻进程快照，不支持按历史 event_id 锚定时间窗口", in.Template)
		}
		anchorEventID = &parsedEventID
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
	cmd, since, until, anchorTs, coverage, err := e.buildEndpointEvidenceTemplate(ctx, e.investigationID, host.ID, in.Template, anchorEventID)
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
		IncidentID:    e.investigationID,
		EvidenceKey:   IncidentEvidenceKey(inc),
		GroupID:       *host.GroupID,
		AssetID:       host.ID,
		Template:      in.Template,
		Command:       cmd,
		Model:         strings.TrimSpace(model),
		Since:         since,
		Until:         until,
		Coverage:      coverage,
		AnchorEventID: anchorEventID,
		AnchorTs:      anchorTs,
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
	if anchorEventID != nil {
		out["anchor_event_id"] = anchorEventID.String()
		if !anchorTs.IsZero() {
			out["anchor_ts"] = anchorTs.UTC().Format(time.RFC3339)
		}
	} else if res.AnchorEventID != "" {
		out["anchor_event_id"] = res.AnchorEventID
		if res.AnchorTs != "" {
			out["anchor_ts"] = res.AnchorTs
		}
	}
	return out, nil
}

func (e *Engine) buildEndpointEvidenceTemplate(ctx context.Context, incidentID, assetID uuid.UUID, template string, anchorEventID *uuid.UUID) (cmd string, since, until, anchorTs time.Time, coverage string, err error) {
	if template == TemplateLinuxProcessSnapshot {
		cmd = "ps -eo pid,ppid,user,lstart,args --no-headers"
		coverage = "仅返回调查时刻受管 Linux 端点当前的只读进程表快照（总输出上限 4096 字节），当前快照不是事发历史；当前未见异常进程不证明事发时未执行，进程命令行文本作为不可信端点证据，不能单独作为合法性证明"
		return cmd, time.Time{}, time.Time{}, time.Time{}, coverage, nil
	}

	var anchorEv *ent.Event
	if anchorEventID != nil {
		anchorEv, err = e.resolveIncidentAssetAnchorEvent(ctx, incidentID, assetID, *anchorEventID)
		if err != nil {
			return "", time.Time{}, time.Time{}, time.Time{}, "", err
		}
		anchorTs = anchorEv.Ts.UTC()
		since = anchorTs.Add(-15 * time.Minute)
		until = anchorTs.Add(15 * time.Minute)
	} else {
		since, until, err = e.incidentAlertWindow(ctx, incidentID)
		if err != nil {
			return "", time.Time{}, time.Time{}, time.Time{}, "", err
		}
	}

	switch template {
	case TemplateLinuxAuthJournal:
		var lxcUID string
		if anchorEv != nil {
			hasContainer, rt, uid, err := parseOptionalStrictAgentContainer(anchorEv.Raw)
			if err != nil {
				return "", time.Time{}, time.Time{}, time.Time{}, "", err
			}
			if hasContainer {
				if rt != "lxc" {
					return "", time.Time{}, time.Time{}, time.Time{}, "", fmt.Errorf("容器运行时 %s 不支持受控 systemd journal 认证日志模板（仅支持宿主机或 LXC 容器）", rt)
				}
				lxcUID = uid
			}
		} else {
			lxcUID, err = e.resolveIncidentAssetAuthTarget(ctx, incidentID, assetID)
			if err != nil {
				return "", time.Time{}, time.Time{}, time.Time{}, "", err
			}
		}
		if lxcUID != "" {
			cmd = fmt.Sprintf("pct exec %s -- journalctl --no-pager --utc -n 40 --since '%s' --until '%s' -u ssh -u sshd",
				lxcUID, since.UTC().Format(journalUTCTimeLayout), until.UTC().Format(journalUTCTimeLayout))
			coverage = fmt.Sprintf("仅返回调查时刻在受管 Linux 宿主机经固定只读模板读取的目标 LXC 容器（vmid=%s）内按 UTC 时间窗口过滤的固定 systemd ssh/sshd 服务单元只读认证 journal 片段（仅覆盖容器内 ssh/sshd 单元，不覆盖容器内 sudo/su 等其他单元或宿主机认证日志；最多 40 行、总输出上限 4096 字节），当前快照不是事发当时的历史完整状态；VMID 仅取自本事件关联 agent 原始事件结构化字段（属端点证据而非授权），输出作为不可信端点证据，不能单独作为授权或合法性证明，为空或截断不代表事发时无其他日志", lxcUID)
			return cmd, since, until, anchorTs, coverage, nil
		}
		cmd = fmt.Sprintf("journalctl --no-pager --utc -n 40 --since '%s' --until '%s' -u ssh -u sshd -t sshd -t sudo -t su",
			since.UTC().Format(journalUTCTimeLayout), until.UTC().Format(journalUTCTimeLayout))
		coverage = "仅返回调查时刻在受管 Linux 端点按本事件告警或锚点事件 UTC 时间窗口（前后 15 分钟、无锚点时最大 2 小时）读取的宿主机 systemd ssh/sshd 服务单元内且 syslog 标识为 sshd/sudo/su 的只读认证 journal 片段（journalctl 中 -u 与 -t 为 AND 组合过滤，不覆盖脱离 ssh/sshd 单元的独立 sudo/su 会话、容器内部认证日志或未接入 journald 的文件日志；最多 40 行、总输出上限 4096 字节），当前快照不是事发当时的历史完整状态；输出作为不可信端点证据，不能单独作为授权或合法性证明，为空或截断不代表事发时无其他日志"
		return cmd, since, until, anchorTs, coverage, nil

	case TemplateLinuxPackageHistory:
		cmd = fmt.Sprintf("journalctl --no-pager --utc -n 25 --since '%s' --until '%s' -u apt-daily.service -u apt-daily-upgrade.service -u unattended-upgrades.service -u packagekit.service && tail -n 30 /var/log/dpkg.log /var/log/apt/history.log",
			since.UTC().Format(journalUTCTimeLayout), until.UTC().Format(journalUTCTimeLayout))
		coverage = "仅返回调查时刻在受管 Linux 端点按本事件告警 UTC 时间窗口（前后 15 分钟、最大 2 小时）读取的固定包管理 systemd unit（apt-daily/apt-daily-upgrade/unattended-upgrades/packagekit）journal 片段（最多 25 行）及调查时刻当前 /var/log/dpkg.log、/var/log/apt/history.log 固定末尾（各最多 30 行，总输出上限 4096 字节）；窄过滤不代表完整系统日志，固定日志文件末尾仅反映调查时刻当前尾部、不等同完整事发时间窗口，不能因 0 输出或末尾无匹配断言事发时不存在相关记录；输出作为不可信端点证据，存在软件包操作记录也不自动证明本事件操作或外联已获业务授权"
		return cmd, since, until, anchorTs, coverage, nil

	case TemplateLinuxContainerWebLogs:
		var runtimeName, uid string
		if anchorEv != nil {
			runtimeName, uid, err = parseStrictAgentContainer(anchorEv.Raw)
		} else {
			runtimeName, uid, err = e.resolveIncidentAssetContainer(ctx, incidentID, assetID)
		}
		if err != nil {
			return "", time.Time{}, time.Time{}, time.Time{}, "", err
		}
		switch runtimeName {
		case "docker":
			cmd = fmt.Sprintf("docker logs --timestamps --since '%s' --until '%s' --tail 40 %s",
				since.UTC().Format(time.RFC3339), until.UTC().Format(time.RFC3339), uid)
			coverage = fmt.Sprintf("仅返回调查时刻在受管 Linux 宿主机按本事件告警 UTC 时间窗口（前后 15 分钟、最大 2 小时）读取的目标 Docker 容器（uid=%s）标准输出与标准错误片段（最多 40 行、总输出上限 4096 字节），不进入容器执行命令；容器 ID 仅取自本事件关联 agent 原始事件结构化字段（属端点证据而非授权），历史容器可能已重建或复用、容器内 Web 访问日志可能写入自定义文件而非标准流，不能因 0 输出断言无访问记录，且任何读取成功均不证明业务授权或非纳管客户端归属", uid)
			return cmd, since, until, anchorTs, coverage, nil
		case "lxc":
			cmd = fmt.Sprintf("pct exec %s -- journalctl --no-pager --utc -n 40 --since '%s' --until '%s' -u caddy -u nginx -u apache2 -u httpd",
				uid, since.UTC().Format(journalUTCTimeLayout), until.UTC().Format(journalUTCTimeLayout))
			coverage = fmt.Sprintf("仅返回调查时刻在受管 Linux 宿主机经固定只读模板读取的目标 LXC 容器（vmid=%s）内按本事件告警 UTC 时间窗口（前后 15 分钟、最大 2 小时）的固定 Web 服务 unit（caddy/nginx/apache2/httpd）journal 片段（最多 40 行、总输出上限 4096 字节）；窄 unit 过滤不代表容器完整日志，VMID 仅取自本事件关联 agent 原始事件结构化字段（属端点证据而非授权），旧 VMID 可能已被复用，容器内 Web 访问日志可能未写入上述 unit 的 journald（如直接写入自定义文件路径），不能因 0 输出断言无访问记录，且任何读取成功均不证明业务授权或非纳管客户端归属", uid)
			return cmd, since, until, anchorTs, coverage, nil
		default:
			return "", time.Time{}, time.Time{}, time.Time{}, "", fmt.Errorf("不支持的容器运行时: %s", runtimeName)
		}

	default:
		return "", time.Time{}, time.Time{}, time.Time{}, "", fmt.Errorf("不支持的端点取证模板: %s", template)
	}
}

func (e *Engine) resolveIncidentAssetAnchorEvent(ctx context.Context, incidentID, assetID, eventID uuid.UUID) (*ent.Event, error) {
	alerts, err := e.DB.Alert.Query().
		Where(entalert.IncidentIDEQ(incidentID), entalert.AssetIDEQ(assetID), entalert.EventIDEQ(eventID)).
		Select(entalert.FieldID, entalert.FieldEventID, entalert.FieldAssetID, entalert.FieldTs).
		All(ctx)
	if err != nil {
		return nil, err
	}
	if len(alerts) == 0 {
		return nil, errors.New("指定的 event_id 不属于当前安全事件在目标主机上的关联告警")
	}
	events, err := e.DB.Event.Query().Where(entevent.IDEQ(eventID)).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, errors.New("指定的 event_id 原始事件记录缺失或已不在热表，拒绝锚定取证")
	}
	if len(events) > 1 {
		return nil, errors.New("指定的 event_id 存在多条不同时间戳原始记录，拒绝锚定取证")
	}
	ev := events[0]
	if ev.AssetID == nil || *ev.AssetID != assetID {
		return nil, errors.New("指定的 event_id 原始事件资产归属与目标主机不一致，拒绝锚定取证")
	}
	if ev.Source != "agent" {
		return nil, errors.New("指定的 event_id 原始事件非受管 agent 采集来源，拒绝锚定取证")
	}
	for _, al := range alerts {
		if !ev.Ts.UTC().Equal(al.Ts.UTC()) {
			return nil, errors.New("指定的 event_id 原始事件时间与关联告警首次时间戳不一致，拒绝锚定取证")
		}
	}
	return ev, nil
}

func (e *Engine) resolveIncidentAssetAuthTarget(ctx context.Context, incidentID, assetID uuid.UUID) (string, error) {
	alerts, err := e.DB.Alert.Query().
		Where(entalert.IncidentIDEQ(incidentID), entalert.AssetIDEQ(assetID)).
		Select(entalert.FieldID, entalert.FieldEventID, entalert.FieldAssetID, entalert.FieldTs).
		All(ctx)
	if err != nil {
		return "", err
	}
	if len(alerts) == 0 {
		return "", errors.New("当前事件在目标主机上无关联告警，拒绝认证日志取证")
	}

	var eventIDs []uuid.UUID
	seenEventIDs := make(map[uuid.UUID]struct{}, len(alerts))
	sawWithoutEvent := false
	for _, al := range alerts {
		if al.EventID == nil || *al.EventID == uuid.Nil {
			sawWithoutEvent = true
			continue
		}
		if _, ok := seenEventIDs[*al.EventID]; !ok {
			seenEventIDs[*al.EventID] = struct{}{}
			eventIDs = append(eventIDs, *al.EventID)
		}
	}
	if len(eventIDs) == 0 {
		return "", nil
	}

	events, err := e.DB.Event.Query().Where(entevent.IDIn(eventIDs...)).All(ctx)
	if err != nil {
		return "", err
	}
	eventsByID := make(map[uuid.UUID]*ent.Event, len(events))
	for _, ev := range events {
		if _, dup := eventsByID[ev.ID]; dup {
			return "", errors.New("关联原始事件 ID 存在多条不同时间戳记录，拒绝认证日志取证")
		}
		eventsByID[ev.ID] = ev
	}
	if len(eventsByID) != len(eventIDs) {
		return "", errors.New("当前事件关联的原始事件记录缺失或已不在热表，拒绝在无锚点下猜测宿主机或容器认证日志目标")
	}

	sawHost := sawWithoutEvent
	var containerRuntime, containerUID string
	for _, al := range alerts {
		if al.EventID == nil || *al.EventID == uuid.Nil {
			continue
		}
		ev := eventsByID[*al.EventID]
		if ev.AssetID == nil || *ev.AssetID != assetID {
			return "", errors.New("关联原始事件的资产归属与目标主机不一致，拒绝认证日志取证")
		}
		if ev.Source != "agent" {
			return "", errors.New("关联原始事件非受管 agent 采集来源，拒绝作为认证日志取证依据")
		}
		if !ev.Ts.UTC().Equal(al.Ts.UTC()) {
			return "", errors.New("关联原始事件时间与告警首次时间戳不一致，拒绝作为认证日志取证依据")
		}
		hasContainer, rt, id, err := parseOptionalStrictAgentContainer(ev.Raw)
		if err != nil {
			return "", err
		}
		if !hasContainer {
			sawHost = true
			continue
		}
		if containerRuntime == "" && containerUID == "" {
			containerRuntime, containerUID = rt, id
			continue
		}
		if containerRuntime != rt || containerUID != id {
			return "", errors.New("当前事件在目标主机上涉及多个不同容器，请传入 event_id 锚定具体告警事件后再读取认证日志")
		}
	}

	if containerRuntime == "" {
		return "", nil
	}
	if sawHost {
		return "", errors.New("当前事件在目标主机上同时包含宿主机与容器告警，请传入 event_id 锚定具体告警事件后再读取认证日志")
	}
	if containerRuntime != "lxc" {
		return "", fmt.Errorf("容器运行时 %s 不支持受控 systemd journal 认证日志模板（仅支持宿主机或 LXC 容器）", containerRuntime)
	}
	return containerUID, nil
}

func (e *Engine) incidentAlertWindow(ctx context.Context, incidentID uuid.UUID) (since, until time.Time, err error) {
	alerts, err := e.DB.Alert.Query().Where(entalert.IncidentIDEQ(incidentID)).Select(entalert.FieldTs, entalert.FieldLastTs).All(ctx)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if len(alerts) == 0 {
		return time.Time{}, time.Time{}, errors.New("当前事件无关联告警时间窗口")
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
	return since, until, nil
}

// resolveIncidentAssetContainer 仅从本事件在目标资产上的关联告警原始事件提取唯一可信容器身份：
//   - 必须所有关联告警均绑定真实 EventID，且原始事件仍在热表；
//   - 原始事件必须满足 asset_id == 目标资产、source == "agent"、时间戳落在告警时间窗内；
//   - 仅读取结构化 raw.container.{runtime,uid}，绝不按容器名称、模型输入、同组其他主机或最新设备清单推导；
//   - 若任一告警无容器、或同一事件在该主机上涉及多个不同容器，一律按歧义 fail-closed 拒绝。
func (e *Engine) resolveIncidentAssetContainer(ctx context.Context, incidentID, assetID uuid.UUID) (runtimeName, uid string, err error) {
	alerts, err := e.DB.Alert.Query().
		Where(entalert.IncidentIDEQ(incidentID), entalert.AssetIDEQ(assetID)).
		Select(entalert.FieldID, entalert.FieldEventID, entalert.FieldAssetID, entalert.FieldTs, entalert.FieldLastTs).
		All(ctx)
	if err != nil {
		return "", "", err
	}
	if len(alerts) == 0 {
		return "", "", errors.New("当前事件在目标主机上无关联告警，拒绝容器日志取证")
	}

	eventIDs := make([]uuid.UUID, 0, len(alerts))
	seenEventIDs := make(map[uuid.UUID]struct{}, len(alerts))
	for _, al := range alerts {
		if al.EventID == nil || *al.EventID == uuid.Nil {
			return "", "", errors.New("当前事件在目标主机上包含无原始事件的合成告警，拒绝猜测容器身份")
		}
		if _, ok := seenEventIDs[*al.EventID]; !ok {
			seenEventIDs[*al.EventID] = struct{}{}
			eventIDs = append(eventIDs, *al.EventID)
		}
	}

	events, err := e.DB.Event.Query().Where(entevent.IDIn(eventIDs...)).All(ctx)
	if err != nil {
		return "", "", err
	}
	eventsByID := make(map[uuid.UUID]*ent.Event, len(events))
	for _, ev := range events {
		if _, dup := eventsByID[ev.ID]; dup {
			return "", "", errors.New("关联原始事件 ID 存在多条不同时间戳记录，拒绝猜测容器身份")
		}
		eventsByID[ev.ID] = ev
	}
	if len(eventsByID) != len(eventIDs) {
		return "", "", errors.New("当前事件关联的原始事件记录缺失或已不在热表，拒绝猜测容器身份")
	}

	for _, al := range alerts {
		ev := eventsByID[*al.EventID]
		if ev == nil {
			return "", "", errors.New("当前事件关联的原始事件记录缺失，拒绝猜测容器身份")
		}
		if ev.AssetID == nil || *ev.AssetID != assetID {
			return "", "", errors.New("关联原始事件的资产归属与目标主机不一致，拒绝容器日志取证")
		}
		if ev.Source != "agent" {
			return "", "", errors.New("关联原始事件非受管 agent 采集来源，拒绝作为容器取证依据")
		}
		if !ev.Ts.UTC().Equal(al.Ts.UTC()) {
			return "", "", errors.New("关联原始事件时间与告警首次时间戳不一致，拒绝作为容器取证依据")
		}

		rt, id, err := parseStrictAgentContainer(ev.Raw)
		if err != nil {
			return "", "", err
		}
		if runtimeName == "" && uid == "" {
			runtimeName, uid = rt, id
			continue
		}
		if runtimeName != rt || uid != id {
			return "", "", errors.New("当前事件在目标主机上涉及多个不同容器，容器身份存在歧义，拒绝猜测容器")
		}
	}
	return runtimeName, uid, nil
}

func parseOptionalStrictAgentContainer(raw json.RawMessage) (hasContainer bool, runtimeName, uid string, err error) {
	if len(raw) == 0 {
		return false, "", "", errors.New("关联原始事件 JSON 为空")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return false, "", "", errors.New("关联原始事件 JSON 格式非法")
	}
	cRaw, exists := top["container"]
	trimmed := bytes.TrimSpace(cRaw)
	if !exists || len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return false, "", "", nil
	}
	rt, id, err := parseStrictAgentContainer(raw)
	if err != nil {
		return true, "", "", err
	}
	return true, rt, id, nil
}

func parseStrictAgentContainer(raw json.RawMessage) (runtimeName, uid string, err error) {
	var envelope struct {
		Container json.RawMessage `json:"container"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || len(envelope.Container) == 0 || string(envelope.Container) == "null" {
		return "", "", errors.New("当前事件关联原始事件缺少结构化 container 字段，拒绝猜测容器身份")
	}
	var c struct {
		Runtime *string `json:"runtime"`
		UID     *string `json:"uid"`
	}
	if err := json.Unmarshal(envelope.Container, &c); err != nil || c.Runtime == nil || c.UID == nil {
		return "", "", errors.New("当前事件关联原始事件的 container 结构化字段不完整，拒绝猜测容器身份")
	}
	rt := strings.TrimSpace(*c.Runtime)
	id := strings.TrimSpace(*c.UID)
	if rt != *c.Runtime || id != *c.UID || rt == "" || id == "" {
		return "", "", errors.New("当前事件关联原始事件的 container 字段格式非法")
	}
	switch rt {
	case "docker":
		if !dockerContainerUIDPattern.MatchString(id) {
			return "", "", errors.New("Docker 容器 uid 必须是严格的小写十六进制 ID，拒绝按名称或非法标识取证")
		}
		return rt, id, nil
	case "lxc":
		if !lxcContainerVMIDPattern.MatchString(id) {
			return "", "", errors.New("LXC 容器 uid 必须是严格的数字 VMID，拒绝按名称或非法标识取证")
		}
		return rt, id, nil
	default:
		return "", "", fmt.Errorf("容器运行时 %s 暂不支持受控 Web 日志取证模板", rt)
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

package response

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrVerificationScope = errors.New("无指令复核权限或指令不存在")
var ErrVerificationInput = errors.New("复核参数无效")

type VerificationInput struct {
	Outcome  string      `json:"outcome"`
	Expected string      `json:"expected"`
	Observed string      `json:"observed"`
	EventIDs []uuid.UUID `json:"eventIds"`
}

type VerificationEvidence struct {
	ID          uuid.UUID       `json:"id"`
	Ts          time.Time       `json:"ts"`
	Source      string          `json:"source"`
	ClassUID    int             `json:"classUid"`
	ProcessGUID *uuid.UUID      `json:"processGuid,omitempty"`
	Raw         json.RawMessage `json:"raw,omitempty"`
}

type Verification struct {
	ID            uuid.UUID              `json:"id"`
	CommandID     uuid.UUID              `json:"commandId"`
	GroupID       *uuid.UUID             `json:"groupId"`
	CreatedAt     time.Time              `json:"createdAt"`
	Source        string                 `json:"source"`
	Method        string                 `json:"method"`
	SessionID     *uuid.UUID             `json:"sessionId,omitempty"`
	Reviewer      string                 `json:"reviewer"`
	CommandStatus string                 `json:"commandStatus"`
	Outcome       string                 `json:"outcome"`
	Expected      string                 `json:"expected"`
	Observed      string                 `json:"observed"`
	Evidence      []VerificationEvidence `json:"evidence"`
	Context       []VerificationEvidence `json:"context,omitempty"`
}

// MachineVerificationInput 机器/AI 效果验证参数。
// 身份与来源由服务端从后台组件或 AgentSession 派生，严禁借人工接口或冒充用户身份。
type MachineVerificationInput struct {
	CommandID       uuid.UUID   `json:"commandId"`
	GroupID         uuid.UUID   `json:"groupId"`
	Source          string      `json:"source"`
	Method          string      `json:"method"`
	Component       string      `json:"component,omitempty"`
	SessionID       *uuid.UUID  `json:"sessionId,omitempty"`
	Outcome         string      `json:"outcome"`
	Expected        string      `json:"expected"`
	Observed        string      `json:"observed"`
	EventIDs        []uuid.UUID `json:"eventIds"`
	ContextEventIDs []uuid.UUID `json:"contextEventIds,omitempty"`
}

func EnsureVerificationSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS command_verifications (
 id uuid PRIMARY KEY, command_id uuid NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
 group_id uuid, created_at timestamptz NOT NULL, reviewer text NOT NULL,
 command_status text NOT NULL, outcome text NOT NULL CHECK (outcome IN ('effective','ineffective','inconclusive')),
 expected text NOT NULL, observed text NOT NULL, evidence jsonb NOT NULL,
 source text NOT NULL DEFAULT 'human' CHECK (source IN ('human','system','ai')),
 method text NOT NULL DEFAULT 'manual_review',
 session_id uuid,
 context jsonb NOT NULL DEFAULT '[]'::jsonb);
 ALTER TABLE command_verifications ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'human';
 ALTER TABLE command_verifications ADD COLUMN IF NOT EXISTS method text NOT NULL DEFAULT 'manual_review';
 ALTER TABLE command_verifications ADD COLUMN IF NOT EXISTS session_id uuid;
 ALTER TABLE command_verifications ADD COLUMN IF NOT EXISTS context jsonb NOT NULL DEFAULT '[]'::jsonb;
 CREATE INDEX IF NOT EXISTS command_verifications_command ON command_verifications(command_id,created_at);`)
	return err
}

func (in VerificationInput) validate() error {
	if in.Outcome != "effective" && in.Outcome != "ineffective" && in.Outcome != "inconclusive" {
		return fmt.Errorf("%w：outcome 必须为 effective / ineffective / inconclusive", ErrVerificationInput)
	}
	for _, text := range []string{in.Expected, in.Observed} {
		if strings.TrimSpace(text) == "" || len(text) > 4000 || strings.ContainsRune(text, 0) {
			return fmt.Errorf("%w：预期和观察说明必填且各不超过 4000 字节", ErrVerificationInput)
		}
	}
	if len(in.EventIDs) > 20 || (in.Outcome != "inconclusive" && len(in.EventIDs) == 0) {
		return fmt.Errorf("%w：明确结论需要 1–20 条后续事件证据", ErrVerificationInput)
	}
	seen := map[uuid.UUID]bool{}
	for _, id := range in.EventIDs {
		if id == uuid.Nil || seen[id] {
			return fmt.Errorf("%w：事件 ID 无效或重复", ErrVerificationInput)
		}
		seen[id] = true
	}
	return nil
}

var allowedMachineMethods = map[string]bool{
	"telemetry_post_action": true,
	"exec_probe":            true,
	"receipt_correlation":   true,
	"context_only":          true,
	"ai_investigation":      true,
}

func (in MachineVerificationInput) validate() error {
	if in.CommandID == uuid.Nil || in.GroupID == uuid.Nil {
		return fmt.Errorf("%w：commandId 与 groupId 必填", ErrVerificationInput)
	}
	if in.Source != "ai" && in.Source != "system" {
		return fmt.Errorf("%w：机器验证 source 必须为 ai 或 system，严禁冒充人工复核", ErrVerificationInput)
	}
	if !allowedMachineMethods[in.Method] {
		return fmt.Errorf("%w：验证方法 method 无效", ErrVerificationInput)
	}
	if in.Source == "ai" {
		if in.SessionID == nil || *in.SessionID == uuid.Nil {
			return fmt.Errorf("%w：AI 验证必须绑定有效会话 ID", ErrVerificationInput)
		}
	} else {
		if in.SessionID != nil {
			return fmt.Errorf("%w：system 验证不能伪造会话 ID", ErrVerificationInput)
		}
		comp := strings.TrimSpace(in.Component)
		if comp == "" || len(comp) > 64 || strings.ContainsRune(comp, 0) || strings.ContainsAny(comp, " \t\r\n:") {
			return fmt.Errorf("%w：system 验证必须提供合法组件标识", ErrVerificationInput)
		}
	}
	if in.Outcome != "effective" && in.Outcome != "ineffective" && in.Outcome != "inconclusive" {
		return fmt.Errorf("%w：outcome 必须为 effective / ineffective / inconclusive", ErrVerificationInput)
	}
	for _, text := range []string{in.Expected, in.Observed} {
		if strings.TrimSpace(text) == "" || len(text) > 4000 || strings.ContainsRune(text, 0) {
			return fmt.Errorf("%w：预期和观察说明必填且各不超过 4000 字节", ErrVerificationInput)
		}
	}
	if len(in.EventIDs) > 20 || len(in.ContextEventIDs) > 20 {
		return fmt.Errorf("%w：事件证据与上下文事件各不超过 20 条", ErrVerificationInput)
	}
	if in.Outcome != "inconclusive" {
		if len(in.EventIDs) == 0 {
			return fmt.Errorf("%w：缺少下发后正向事件证据，结论只能记为 inconclusive", ErrVerificationInput)
		}
		if in.Method == "context_only" {
			return fmt.Errorf("%w：仅凭下发前上下文（context_only）不能判定 effective 或 ineffective", ErrVerificationInput)
		}
	}
	seen := map[uuid.UUID]bool{}
	for _, id := range in.EventIDs {
		if id == uuid.Nil || seen[id] {
			return fmt.Errorf("%w：事件 ID 无效或重复", ErrVerificationInput)
		}
		seen[id] = true
	}
	for _, id := range in.ContextEventIDs {
		if id == uuid.Nil || seen[id] {
			return fmt.Errorf("%w：上下文事件 ID 无效或与后续证据重复", ErrVerificationInput)
		}
		seen[id] = true
	}
	return nil
}

// RecordVerification 记录人工复核意见，不改变执行回执，也不把事件存在解释成机器验证成功。
// 归属/成员资格在事务内锁定，审计失败则整体回滚。证据快照随复核留存。
func RecordVerification(ctx context.Context, db *sql.DB, userID, commandID uuid.UUID, remoteAddr string, in VerificationInput) (*Verification, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var reviewer, role string
	if err := tx.QueryRowContext(ctx, `SELECT username,role FROM users WHERE id=$1 FOR SHARE`, userID).Scan(&reviewer, &role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVerificationScope
		}
		return nil, err
	}
	var assetID uuid.UUID
	var group uuid.NullUUID
	var status string
	var issued time.Time
	if err := tx.QueryRowContext(ctx, `SELECT c.asset_id,a.group_id,c.status,c.created_at FROM commands c JOIN assets a ON a.id=c.asset_id WHERE c.id=$1 FOR SHARE OF c,a`, commandID).Scan(&assetID, &group, &status, &issued); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVerificationScope
		}
		return nil, err
	}
	if role != "admin" {
		var membership string
		if !group.Valid {
			return nil, ErrVerificationScope
		}
		if err := tx.QueryRowContext(ctx, `SELECT role FROM group_members WHERE user_id=$1 AND group_id=$2 AND role IN ('analyst','admin') FOR SHARE`, userID, group.UUID).Scan(&membership); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrVerificationScope
			}
			return nil, err
		}
	}
	out := &Verification{
		ID: uuid.New(), CommandID: commandID, CreatedAt: time.Now().UTC(),
		Source: "human", Method: "manual_review", Reviewer: reviewer,
		CommandStatus: status, Outcome: in.Outcome, Expected: in.Expected, Observed: in.Observed,
		Evidence: make([]VerificationEvidence, 0, len(in.EventIDs)),
	}
	if group.Valid {
		out.GroupID = &group.UUID
	}
	for _, id := range in.EventIDs {
		var e VerificationEvidence
		var procGUID uuid.NullUUID
		if err := tx.QueryRowContext(ctx, `SELECT id,ts,source,class_uid,process_guid,raw FROM events WHERE id=$1 AND asset_id=$2 AND ts >= $3 AND ts <= $4 FOR SHARE`, id, assetID, issued, out.CreatedAt).Scan(&e.ID, &e.Ts, &e.Source, &e.ClassUID, &procGUID, &e.Raw); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("%w：证据必须是同资产下发后的已发生事件", ErrVerificationInput)
			}
			return nil, err
		}
		if procGUID.Valid {
			idCopy := procGUID.UUID
			e.ProcessGUID = &idCopy
		}
		out.Evidence = append(out.Evidence, e)
	}
	evidence, err := json.Marshal(out.Evidence)
	if err != nil {
		return nil, err
	}
	if len(evidence) > 1024*1024 {
		return nil, fmt.Errorf("%w：证据快照超过 1 MiB", ErrVerificationInput)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO command_verifications(id,command_id,group_id,created_at,reviewer,command_status,outcome,expected,observed,evidence,source,method,session_id,context) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'human','manual_review',NULL,'[]'::jsonb)`, out.ID, commandID, out.GroupID, out.CreatedAt, reviewer, status, in.Outcome, in.Expected, in.Observed, evidence)
	if err != nil {
		return nil, err
	}
	detail, _ := json.Marshal(map[string]any{"verificationId": out.ID, "source": "human", "method": "manual_review", "outcome": out.Outcome, "eventIds": in.EventIDs, "commandStatus": status})
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(id,ts,username,action,target,detail,remote_addr) VALUES($1,$2,$3,'command_verification_recorded',$4,$5,$6)`, uuid.New(), out.CreatedAt, reviewer, commandID.String(), string(detail), remoteAddr)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

// RecordMachineVerification 记录服务端派生的 AI 会话或确定性机器效果验证。
// 严格区分人工意见（human）与机器验证（ai/system）：
//   - AI 验证强制校验会话存在、归属同组、处于 running 且未取消/未过期；
//   - 无下发后正向且与处置目标匹配的事件证据时一律禁止记为 effective/ineffective；
//   - 下发前事件（如目标进程在下发前已退出）只能作为 ContextEventIDs 归档，结论必须为 inconclusive。
func RecordMachineVerification(ctx context.Context, db *sql.DB, in MachineVerificationInput) (*Verification, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	var reviewer string
	if in.Source == "ai" {
		var sessionGroup uuid.UUID
		var sessionStatus string
		var cancelAt, expiresAt, deadlineAt sql.NullTime
		if err := tx.QueryRowContext(ctx, `SELECT group_id,status,cancel_requested_at,run_expires_at,run_deadline_at FROM agent_sessions WHERE id=$1 FOR SHARE`, *in.SessionID).
			Scan(&sessionGroup, &sessionStatus, &cancelAt, &expiresAt, &deadlineAt); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrVerificationScope
			}
			return nil, err
		}
		if sessionGroup != in.GroupID || sessionStatus != "running" || cancelAt.Valid ||
			(expiresAt.Valid && !expiresAt.Time.After(now)) ||
			(deadlineAt.Valid && !deadlineAt.Time.After(now)) {
			return nil, ErrVerificationScope
		}
		reviewer = "ai:session:" + in.SessionID.String()
	} else {
		reviewer = "system:" + strings.TrimSpace(in.Component)
	}

	var assetID uuid.UUID
	var group uuid.NullUUID
	var cmdKind, status, cmdTarget, cmdDetail string
	var issued time.Time
	var completedAt sql.NullTime
	var cmdPID int64
	var cmdGUID uuid.NullUUID
	if err := tx.QueryRowContext(ctx, `SELECT c.asset_id,a.group_id,c.kind,c.status,c.created_at,c.completed_at,c.pid,c.process_guid,COALESCE(c.target,''),COALESCE(c.detail,'') FROM commands c JOIN assets a ON a.id=c.asset_id WHERE c.id=$1 FOR SHARE OF c,a`, in.CommandID).
		Scan(&assetID, &group, &cmdKind, &status, &issued, &completedAt, &cmdPID, &cmdGUID, &cmdTarget, &cmdDetail); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVerificationScope
		}
		return nil, err
	}
	if !group.Valid || group.UUID != in.GroupID {
		return nil, ErrVerificationScope
	}
	if in.Outcome != "inconclusive" && status != "succeeded" {
		return nil, fmt.Errorf("%w：未确认执行成功的指令（status=%s）不能判定为 %s", ErrVerificationInput, status, in.Outcome)
	}

	verificationID := uuid.New()
	if in.Source == "system" {
		verificationID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("openxdr:sys-verify|"+in.CommandID.String()+"|"+status+"|"+in.Outcome))
		var existingID uuid.UUID
		if err := tx.QueryRowContext(ctx, `SELECT id FROM command_verifications WHERE id=$1`, verificationID).Scan(&existingID); err == nil {
			return &Verification{
				ID: existingID, CommandID: in.CommandID, GroupID: &group.UUID, CreatedAt: now,
				Source: in.Source, Method: in.Method, Reviewer: reviewer,
				CommandStatus: status, Outcome: in.Outcome, Expected: in.Expected, Observed: in.Observed,
			}, nil
		}
	}

	out := &Verification{
		ID: verificationID, CommandID: in.CommandID, GroupID: &group.UUID, CreatedAt: now,
		Source: in.Source, Method: in.Method, SessionID: in.SessionID, Reviewer: reviewer,
		CommandStatus: status, Outcome: in.Outcome, Expected: in.Expected, Observed: in.Observed,
		Evidence: make([]VerificationEvidence, 0, len(in.EventIDs)),
		Context:  make([]VerificationEvidence, 0, len(in.ContextEventIDs)),
	}
	for _, id := range in.EventIDs {
		var e VerificationEvidence
		var procGUID uuid.NullUUID
		if err := tx.QueryRowContext(ctx, `SELECT id,ts,source,class_uid,process_guid,raw FROM events WHERE id=$1 AND asset_id=$2 AND ts >= $3 AND ts <= $4 FOR SHARE`, id, assetID, issued, out.CreatedAt).
			Scan(&e.ID, &e.Ts, &e.Source, &e.ClassUID, &procGUID, &e.Raw); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("%w：证据必须是同资产下发后的已发生事件", ErrVerificationInput)
			}
			return nil, err
		}
		if procGUID.Valid {
			idCopy := procGUID.UUID
			e.ProcessGUID = &idCopy
		}
		out.Evidence = append(out.Evidence, e)
	}
	for _, id := range in.ContextEventIDs {
		var e VerificationEvidence
		var procGUID uuid.NullUUID
		if err := tx.QueryRowContext(ctx, `SELECT id,ts,source,class_uid,process_guid,raw FROM events WHERE id=$1 AND asset_id=$2 AND ts < $3 FOR SHARE`, id, assetID, issued).
			Scan(&e.ID, &e.Ts, &e.Source, &e.ClassUID, &procGUID, &e.Raw); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("%w：上下文事件必须是同资产下发前的已发生事件", ErrVerificationInput)
			}
			return nil, err
		}
		if procGUID.Valid {
			idCopy := procGUID.UUID
			e.ProcessGUID = &idCopy
		}
		out.Context = append(out.Context, e)
	}
	if in.Outcome != "inconclusive" && !evidenceCorroboratesCommand(cmdKind, uint32(cmdPID), cmdGUID, completedAt, in.Outcome, out.Evidence) {
		return nil, fmt.Errorf("%w：缺少结构化确定性后续证据（当前仅支持 agent 采集的同 process_guid 进程退出/存活事件），结论应记为 inconclusive", ErrVerificationInput)
	}

	evidenceJSON, err := json.Marshal(out.Evidence)
	if err != nil {
		return nil, err
	}
	contextJSON, err := json.Marshal(out.Context)
	if err != nil {
		return nil, err
	}
	if len(evidenceJSON)+len(contextJSON) > 1024*1024 {
		return nil, fmt.Errorf("%w：证据快照超过 1 MiB", ErrVerificationInput)
	}
	var insertedID uuid.UUID
	err = tx.QueryRowContext(ctx, `INSERT INTO command_verifications(id,command_id,group_id,created_at,reviewer,command_status,outcome,expected,observed,evidence,source,method,session_id,context) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT (id) DO NOTHING RETURNING id`,
		out.ID, in.CommandID, out.GroupID, out.CreatedAt, reviewer, status, in.Outcome, in.Expected, in.Observed, evidenceJSON, in.Source, in.Method, in.SessionID, contextJSON).Scan(&insertedID)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	detail, _ := json.Marshal(map[string]any{
		"verificationId":  out.ID,
		"source":          out.Source,
		"method":          out.Method,
		"sessionId":       out.SessionID,
		"outcome":         out.Outcome,
		"eventIds":        in.EventIDs,
		"contextEventIds": in.ContextEventIDs,
		"commandStatus":   status,
	})
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(id,ts,username,action,target,detail,remote_addr) VALUES($1,$2,$3,'command_verification_recorded',$4,$5,'')`,
		uuid.New(), out.CreatedAt, reviewer, in.CommandID.String(), string(detail))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

// evidenceCorroboratesCommand 严格 fail-closed 校验：
//   - 目前仅允许 kill_process 在具备结构化 events.process_guid 精确匹配、source="agent"、class_uid=1007、
//     且 raw.process.pid 精确整数相等（不匹配 parent_process 或任意子串）时判定 effective（activity_id=2 退出）或 ineffective（完成时间后仍存续）；
//   - 其他动作类型或非结构化/子串提及证据一律不得记为 effective/ineffective，必须记为 inconclusive。
func evidenceCorroboratesCommand(kind string, pid uint32, guid uuid.NullUUID, completedAt sql.NullTime, outcome string, evidence []VerificationEvidence) bool {
	if kind != "kill_process" || !guid.Valid || guid.UUID == uuid.Nil {
		return false
	}
	for _, e := range evidence {
		if e.Source != "agent" || e.ClassUID != 1007 || e.ProcessGUID == nil || *e.ProcessGUID != guid.UUID {
			continue
		}
		actID, evPID, ok := parseProcessActivityAndPID(e.Raw)
		if !ok {
			continue
		}
		if pid > 0 && evPID != pid {
			continue
		}
		if outcome == "effective" && actID == 2 {
			return true
		}
		if outcome == "ineffective" && actID == 1 && (!completedAt.Valid || !e.Ts.Before(completedAt.Time)) {
			return true
		}
	}
	return false
}

func parseProcessActivityAndPID(raw json.RawMessage) (activityID int, pid uint32, ok bool) {
	var payload struct {
		ActivityID any `json:"activity_id"`
		Process    struct {
			PID *uint64 `json:"pid"`
		} `json:"process"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return 0, 0, false
	}
	switch v := payload.ActivityID.(type) {
	case float64:
		if v != float64(int(v)) {
			return 0, 0, false
		}
		activityID = int(v)
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, 0, false
		}
		activityID = n
	default:
		return 0, 0, false
	}
	if payload.Process.PID == nil || *payload.Process.PID == 0 || *payload.Process.PID > uint64(^uint32(0)) {
		return 0, 0, false
	}
	return activityID, uint32(*payload.Process.PID), true
}

// RunAutoVerification 单活周期巡检近期非 exec 处置指令的效果验证。
func RunAutoVerification(ctx context.Context, db *sql.DB, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := AutoVerifyCommands(ctx, db, time.Now().UTC()); err != nil && ctx.Err() == nil {
			slog.Error("指令自动效果核验失败", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// AutoVerifyCommands 服务端单活有界自动核验近期处置指令（由 containment.Engine.Tick 与后台单活循环调用）：
//   - 对 kill_process：若存在同资产下发后结构化匹配的进程退出事件（source=agent, class_uid=1007, process_guid 相等, activity_id=2）且指令已 succeeded，记录 effective；
//   - 若无确定性后验退出事件（或为其他动作类型/指令未成功），仅幂等记录一条 inconclusive（含下发前已退出的 context_only 归类），不重复追加；
//   - 若此前记为 inconclusive 的成功 kill_process 随后收到延迟到达的确定性退出事件，自动补记一条 effective 后收敛。
func AutoVerifyCommands(ctx context.Context, db *sql.DB, now time.Time) error {
	if db == nil {
		return nil
	}
	if err := EnsureVerificationSchema(ctx, db); err != nil {
		return err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows, err := db.QueryContext(ctx, `SELECT c.id, c.asset_id, a.group_id, c.kind, c.status, c.created_at, c.pid, c.process_guid, COALESCE(c.target,''), COALESCE(c.detail,'')
 FROM commands c
 JOIN assets a ON a.id = c.asset_id
 WHERE c.kind <> 'exec'
   AND a.group_id IS NOT NULL
   AND c.status IN ('succeeded','failed','unsupported','unknown')
   AND c.created_at >= $1 AND c.created_at <= $2
   AND (
     NOT EXISTS (
       SELECT 1 FROM command_verifications v
       WHERE v.command_id = c.id AND v.source = 'system' AND v.command_status = c.status
     )
     OR (
       c.kind = 'kill_process' AND c.status = 'succeeded' AND c.process_guid IS NOT NULL
       AND NOT EXISTS (
         SELECT 1 FROM command_verifications v
         WHERE v.command_id = c.id AND v.source = 'system' AND v.command_status = c.status AND v.outcome = 'effective'
       )
       AND EXISTS (
         SELECT 1 FROM events e
         WHERE e.asset_id = c.asset_id AND e.source = 'agent' AND e.class_uid = 1007
           AND e.process_guid = c.process_guid AND e.ts >= c.created_at AND e.ts <= $2
       )
     )
   )
 ORDER BY c.created_at ASC, c.id ASC
 LIMIT 500`, now.Add(-24*time.Hour), now)
	if err != nil {
		return err
	}
	type candidate struct {
		id      uuid.UUID
		assetID uuid.UUID
		groupID uuid.UUID
		kind    string
		status  string
		issued  time.Time
		pid     int64
		guid    uuid.NullUUID
		target  string
		detail  string
	}
	var list []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.assetID, &c.groupID, &c.kind, &c.status, &c.issued, &c.pid, &c.guid, &c.target, &c.detail); err != nil {
			rows.Close()
			return err
		}
		list = append(list, c)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, c := range list {
		var prevOutcome, prevStatus string
		err := db.QueryRowContext(ctx, `SELECT outcome, command_status FROM command_verifications WHERE command_id=$1 AND source='system' ORDER BY created_at DESC, id DESC LIMIT 1`, c.id).
			Scan(&prevOutcome, &prevStatus)
		hasPrev := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if hasPrev && prevOutcome == "effective" && prevStatus == c.status {
			continue
		}

		if c.kind == "kill_process" && c.guid.Valid && c.guid.UUID != uuid.Nil {
			if c.status == "succeeded" {
				if exitID, ok, err := findStructuredProcessExit(ctx, db, c.assetID, c.guid.UUID, uint32(c.pid), c.issued, now, true); err != nil {
					return err
				} else if ok {
					if _, err := RecordMachineVerification(ctx, db, MachineVerificationInput{
						CommandID: c.id,
						GroupID:   c.groupID,
						Source:    "system",
						Component: "containment",
						Method:    "telemetry_post_action",
						Outcome:   "effective",
						Expected:  "目标进程在下发 kill_process 后退出",
						Observed:  "已观测到同资产下发后结构化 process_guid 与 PID 精确匹配的进程退出事件（activity_id=2）",
						EventIDs:  []uuid.UUID{exitID},
					}); err != nil {
						return err
					}
					continue
				}
			}
			if hasPrev && prevStatus == c.status {
				continue
			}
			if preExitID, ok, err := findStructuredProcessExit(ctx, db, c.assetID, c.guid.UUID, uint32(c.pid), c.issued, now, false); err != nil {
				return err
			} else if ok {
				if _, err := RecordMachineVerification(ctx, db, MachineVerificationInput{
					CommandID:       c.id,
					GroupID:         c.groupID,
					Source:          "system",
					Component:       "containment",
					Method:          "context_only",
					Outcome:         "inconclusive",
					Expected:        "核验目标进程终止效果",
					Observed:        "目标进程在指令下发前已退出（见上下文退出事件），不计为下发后机器验证成功，也不归为执行器故障",
					ContextEventIDs: []uuid.UUID{preExitID},
				}); err != nil {
					return err
				}
				continue
			}
		}

		if hasPrev && prevStatus == c.status {
			continue
		}
		observed := describeInconclusiveReceipt(c.kind, c.status, c.detail)
		method := "receipt_correlation"
		if c.status == "succeeded" {
			method = "telemetry_post_action"
		}
		if _, err := RecordMachineVerification(ctx, db, MachineVerificationInput{
			CommandID: c.id,
			GroupID:   c.groupID,
			Source:    "system",
			Component: "containment",
			Method:    method,
			Outcome:   "inconclusive",
			Expected:  "核验处置指令实际生效证据",
			Observed:  observed,
		}); err != nil {
			return err
		}
	}
	return nil
}

func findStructuredProcessExit(ctx context.Context, db *sql.DB, assetID, guid uuid.UUID, pid uint32, issued, now time.Time, afterIssuance bool) (uuid.UUID, bool, error) {
	query := `SELECT id, raw FROM events WHERE asset_id=$1 AND source='agent' AND class_uid=1007 AND process_guid=$2 AND ts >= $3 AND ts <= $4 ORDER BY ts ASC LIMIT 20`
	var rows *sql.Rows
	var err error
	if afterIssuance {
		rows, err = db.QueryContext(ctx, query, assetID, guid, issued, now)
	} else {
		query = `SELECT id, raw FROM events WHERE asset_id=$1 AND source='agent' AND class_uid=1007 AND process_guid=$2 AND ts < $3 ORDER BY ts DESC LIMIT 20`
		rows, err = db.QueryContext(ctx, query, assetID, guid, issued)
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var raw json.RawMessage
		if err := rows.Scan(&id, &raw); err != nil {
			return uuid.Nil, false, err
		}
		actID, evPID, ok := parseProcessActivityAndPID(raw)
		if ok && actID == 2 && (pid == 0 || evPID == pid) {
			return id, true, nil
		}
	}
	return uuid.Nil, false, rows.Err()
}

func describeInconclusiveReceipt(kind, status, detail string) string {
	d := strings.TrimSpace(detail)
	if status == "succeeded" {
		return "指令回执为 succeeded，但尚无下发后确定性目标状态探针或退出事件正证据；仅无新告警不证明处置持续有效，记为 inconclusive"
	}
	if kind == "kill_process" && status == "failed" {
		lower := strings.ToLower(d)
		if strings.Contains(lower, "no such process") || strings.Contains(lower, "esrch") || strings.Contains(lower, "os error 3") ||
			(strings.Contains(d, "进程不存在") && !strings.Contains(lower, "pidfd")) {
			return "指令回执报告目标进程已不存在（ESRCH/No such process），缺少下发后退出事件正证据，记为 inconclusive：" + d
		}
		if strings.Contains(d, "身份不匹配") || strings.Contains(d, "已过期") || strings.Contains(d, "身份不符") {
			return "安全闸门拒绝执行（进程身份不匹配或已过期），未执行终止，记为 inconclusive：" + d
		}
	}
	if d != "" {
		return fmt.Sprintf("指令状态为 %s（%s），缺少确定性效果正证据，记为 inconclusive", status, d)
	}
	return fmt.Sprintf("指令状态为 %s，缺少确定性效果正证据，记为 inconclusive", status)
}

const verificationScope = ` FROM command_verifications v JOIN commands c ON c.id=v.command_id JOIN assets a ON a.id=c.asset_id JOIN users u ON u.id=$1
 WHERE v.command_id=$2 AND (u.role='admin' OR (
 EXISTS(SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=v.group_id AND m.role IN ('viewer','analyst','admin')) AND
 EXISTS(SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=a.group_id AND m.role IN ('viewer','analyst','admin'))))`

// ListVerifications 同时约束复核时归组与当前资产归组，多取一条供 API 判断截断。
func ListVerifications(ctx context.Context, db *sql.DB, userID, commandID uuid.UUID) ([]Verification, error) {
	rows, err := db.QueryContext(ctx, `SELECT v.id,v.command_id,v.group_id,v.created_at,v.source,v.method,v.session_id,v.reviewer,v.command_status,v.outcome,v.expected,v.observed,
 COALESCE((SELECT jsonb_agg(e - 'raw') FROM jsonb_array_elements(v.evidence) e),'[]'::jsonb),
 COALESCE((SELECT jsonb_agg(e - 'raw') FROM jsonb_array_elements(v.context) e),'[]'::jsonb)
`+verificationScope+`
 ORDER BY v.created_at DESC,v.id DESC LIMIT 101`, userID, commandID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Verification, 0)
	for rows.Next() {
		var v Verification
		var evidence, contextRaw []byte
		if err := rows.Scan(&v.ID, &v.CommandID, &v.GroupID, &v.CreatedAt, &v.Source, &v.Method, &v.SessionID, &v.Reviewer, &v.CommandStatus, &v.Outcome, &v.Expected, &v.Observed, &evidence, &contextRaw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(evidence, &v.Evidence); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(contextRaw, &v.Context); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetVerification 只读取一条授权复核及其留存原文，不能跨指令引用其他复核 ID。
func GetVerification(ctx context.Context, db *sql.DB, userID, commandID, verificationID uuid.UUID) (*Verification, error) {
	var v Verification
	var evidence, contextRaw []byte
	err := db.QueryRowContext(ctx, `SELECT v.id,v.command_id,v.group_id,v.created_at,v.source,v.method,v.session_id,v.reviewer,v.command_status,v.outcome,v.expected,v.observed,v.evidence,v.context`+verificationScope+` AND v.id=$3`, userID, commandID, verificationID).
		Scan(&v.ID, &v.CommandID, &v.GroupID, &v.CreatedAt, &v.Source, &v.Method, &v.SessionID, &v.Reviewer, &v.CommandStatus, &v.Outcome, &v.Expected, &v.Observed, &evidence, &contextRaw)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(evidence, &v.Evidence); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(contextRaw, &v.Context); err != nil {
		return nil, err
	}
	return &v, nil
}

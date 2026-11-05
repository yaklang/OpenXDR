// Package commandgate 统一人工与 AI 的 exec 判权、名单和审批。
package commandgate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/approval"
	"openxdr/server/ent/commandpolicy"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/response"
)

type Gate struct {
	DB              *ent.Client
	Hub             *response.Hub
	ApprovalTimeout time.Duration
	// Notify 新审批创建时推给组管理员，nil 表示不外发；签名同 schedule.Notifier
	Notify func(ctx context.Context, title, text, path string) error
	// Reviewer 非空时 AI 发起的待批准命令由 AI 审计员当场评审，不再等人；人发起的照旧等组管理员
	Reviewer Reviewer
}
type Request struct {
	UserID uuid.UUID
	// 定时任务的系统身份：不对应任何用户，UserID 忽略
	System    bool
	GroupID   uuid.UUID
	SessionID *uuid.UUID
	Origin    string
	Command   response.Request
	// 非零时覆盖 Gate.ApprovalTimeout，定时任务按任务配置
	ApprovalTimeout time.Duration
	// PreferReviewer 为 true 时，若命令命中高风险管控名单，优先交 AI 审计员评审，未配置审计员则直接拒绝，不走系统自动放行或人工长等待
	PreferReviewer bool
}

// SystemActor 系统身份的发起人名，也是定时任务会话的 initiator。用户名不允许取这个值。
const SystemActor = "system"

// Search 在整条命令里非锚定搜索：名单都是高风险名单，命令里任何一段命中都算，
// 拼在 `x && rm -rf /` 后面也躲不过。
func Search(pattern, cmd string) (bool, error) {
	if len(pattern) == 0 || len(pattern) > 4096 {
		return false, errors.New("pattern 长度须为 1–4096")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, err
	}
	return re.MatchString(cmd), nil
}

// authorize 返回发起人名。系统身份没有用户与组内角色可查，
// 只能在 kind=task、initiator=system 的任务会话里对本组资产执行。
func (g *Gate) authorize(ctx context.Context, req Request) (string, error) {
	actor := SystemActor
	if req.System {
		if req.SessionID == nil {
			return "", errors.New("系统身份必须绑定任务会话")
		}
	} else {
		u, err := g.DB.User.Get(ctx, req.UserID)
		if err != nil {
			return "", errors.New("发起人不存在")
		}
		if !auth.Allowed(auth.GroupRole(ctx, g.DB, u, req.GroupID), "analyst") {
			return "", errors.New("无组内执行权限")
		}
		actor = u.Username
	}
	a, err := g.DB.Asset.Get(ctx, req.Command.AssetID)
	if err != nil || a.GroupID == nil || *a.GroupID != req.GroupID {
		return "", errors.New("资产不属于当前组")
	}
	if req.SessionID != nil {
		s, err := g.DB.AgentSession.Get(ctx, *req.SessionID)
		if err != nil || s.GroupID != req.GroupID || s.Initiator != actor || req.System != (s.Kind == "task") {
			return "", errors.New("会话身份不匹配")
		}
		now := time.Now()
		if s.Status != "running" || s.CancelRequestedAt != nil ||
			(s.RunExpiresAt != nil && !s.RunExpiresAt.After(now)) ||
			(s.RunDeadlineAt != nil && !s.RunDeadlineAt.After(now)) {
			return "", errors.New("会话已结束、取消或执行租约已失效")
		}
	}
	return actor, nil
}

// needsApproval 人工与 AI 同一套语义：命中本组该来源任一高风险名单就等审批，否则直接执行。
func (g *Gate) needsApproval(ctx context.Context, req Request) (bool, error) {
	policies, err := g.DB.CommandPolicy.Query().Where(commandpolicy.GroupIDEQ(req.GroupID), commandpolicy.OriginEQ(commandpolicy.Origin(req.Origin))).All(ctx)
	if err != nil {
		return false, err
	}
	for _, policy := range policies {
		if policy.Mode != commandpolicy.ModeDeny {
			return false, errors.New("名单模式无效：只支持 deny")
		}
		ok, err := Search(policy.Pattern, *req.Command.Cmd)
		if err != nil {
			return false, fmt.Errorf("名单无效: %w", err)
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// Issue 的 origin 由平台入口固定，不能从客户端或模型参数读取。
func (g *Gate) Issue(ctx context.Context, req Request) (out *ent.Command, retErr error) {
	if req.Origin != "ai" && req.Origin != "human" {
		return nil, errors.New("无效的命令来源")
	}
	if req.Command.Kind != "exec" || req.Command.Cmd == nil || strings.TrimSpace(*req.Command.Cmd) == "" || len(*req.Command.Cmd) > 32768 {
		return nil, errors.New("exec 命令长度须为 1–32768")
	}
	if req.Command.TimeoutMS > 300000 {
		return nil, errors.New("命令超时不可超过 300 秒")
	}
	// 请求先持久化审计，包括随后因授权、名单或超时被拒绝的请求。
	detail := fmt.Sprintf("origin=%s group=%s cmd=%s", req.Origin, req.GroupID, *req.Command.Cmd)
	// 审计里写用户名，与其它审计记录一致；查不到用户时留 ID，授权随后会拒绝
	who := req.UserID.String()
	if req.System {
		who = SystemActor
	} else if u, err := g.DB.User.Get(ctx, req.UserID); err == nil {
		who = u.Username
	}
	if err := g.log(ctx, who, "exec_requested", req.Command.AssetID.String(), detail); err != nil {
		return nil, err
	}
	defer func() {
		logCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		status := "exec_issued"
		result := ""
		if retErr != nil {
			status = "exec_denied"
			result = retErr.Error()
		}
		if out != nil {
			result = out.ID.String() + " " + out.Status
		}
		if errors.Is(retErr, response.ErrDeliveryUnknown) || (out != nil && out.Status == "unknown") {
			status = "exec_unknown"
		}
		if err := g.log(logCtx, who, status, req.Command.AssetID.String(), result); err != nil && retErr == nil {
			retErr = fmt.Errorf("命令可能已下发，审计回写失败，禁止自动重试: %w", err)
		}
	}()
	actor, err := g.authorize(ctx, req)
	if err != nil {
		return nil, err
	}
	if why := hardDenied(*req.Command.Cmd); why != "" && req.Origin == "ai" {
		return nil, fmt.Errorf("这条命令属于平台硬拒绝的操作（%s），不执行也不送审计；不要换写法重试，确有必要在回复里说明，由人处理", why)
	}
	if g.Hub == nil || !g.Hub.Enabled {
		return nil, errors.New("响应能力未启用")
	}
	required, err := g.needsApproval(ctx, req)
	if err != nil {
		return nil, err
	}
	if required {
		wait := g.await
		switch {
		case req.PreferReviewer:
			if g.Reviewer == nil {
				return nil, errors.New("命令命中高风险管控名单且未配置 AI 审计员，拒绝自动执行")
			}
			wait = g.review
		case req.System && g.linux(ctx, req) && ReadOnly(*req.Command.Cmd):
			wait = g.autoApprove
		case req.Origin == "ai" && g.Reviewer != nil:
			wait = g.review
		}
		if err := wait(ctx, req, actor); err != nil {
			return nil, err
		}
	}
	// 等待期间主机归组或成员权限可能改变，审批不能越过此检查。
	actor, err = g.authorize(ctx, req)
	if err != nil {
		return nil, err
	}
	req.Command.IssuedBy = actor
	return g.Hub.IssueExec(ctx, req.Command)
}

func (g *Gate) log(ctx context.Context, actor, action, target, detail string) error {
	return audit.Checked(ctx, g.DB.AuditLog.Create(), actor, "server", action, target, detail)
}

func (g *Gate) await(ctx context.Context, req Request, username string) error {
	ttl := g.ApprovalTimeout
	if req.ApprovalTimeout > 0 {
		ttl = req.ApprovalTimeout
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	expires := time.Now().Add(ttl)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	a, err := g.DB.Approval.Create().SetGroupID(req.GroupID).SetNillableSessionID(req.SessionID).
		SetAssetID(req.Command.AssetID).SetRequestedBy(username).SetOrigin(approval.Origin(req.Origin)).
		SetCmd(*req.Command.Cmd).SetTimeoutMs(req.Command.TimeoutMS).SetExpiresAt(expires).Save(ctx)
	if err != nil {
		return err
	}
	g.notify(ctx, req, username)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		status := approval.StatusCancelled
		if !time.Now().Before(expires) {
			status = approval.StatusExpired
		}
		_, _ = g.DB.Approval.Update().Where(approval.IDEQ(a.ID), approval.StatusIn(approval.StatusPending, approval.StatusApproved)).SetStatus(status).Save(cleanup)
	}()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(time.Until(expires))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return pending(req)
		case <-ticker.C:
			current, err := g.DB.Approval.Get(ctx, a.ID)
			if err != nil {
				return err
			}
			switch current.Status {
			case approval.StatusApproved:
				// 原子消费，批准不能被重复使用；过期的批准同样不能执行。
				n, err := g.DB.Approval.Update().Where(approval.IDEQ(a.ID), approval.StatusEQ(approval.StatusApproved), approval.ExpiresAtGT(time.Now())).SetStatus(approval.StatusConsumed).Save(ctx)
				if err != nil {
					return err
				}
				if n != 1 {
					return errors.New("审批已过期或已消费")
				}
				return nil
			case approval.StatusPending:
			case approval.StatusExpired:
				return pending(req)
			case approval.StatusRejected:
				if req.Origin == "ai" {
					return errors.New("管理员没有批准执行这条命令，不要换写法重复同一操作")
				}
				return errors.New("审批未通过，命令未执行")
			default:
				return errors.New("审批未通过，命令未执行")
			}
		}
	}
}

// linux 只读判定按 sh -c 的语义做，Windows（PowerShell）和系统不明的主机不自动批准
func (g *Gate) linux(ctx context.Context, req Request) bool {
	a, err := g.DB.Asset.Get(ctx, req.Command.AssetID)
	return err == nil && a.Os != nil && strings.EqualFold(*a.Os, "linux")
}

// autoApprove 定时任务里被名单误伤的只读命令：半夜没人审批，等到过期只会让巡检缺项。
// 照常留一条审批记录（直接记为已消费、由 system 批准）并写审计，事后能查到哪些命令是自动放行的。
func (g *Gate) autoApprove(ctx context.Context, req Request, username string) error {
	tx, err := g.DB.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now()
	a, err := tx.Approval.Create().SetGroupID(req.GroupID).SetNillableSessionID(req.SessionID).
		SetAssetID(req.Command.AssetID).SetRequestedBy(username).SetOrigin(approval.Origin(req.Origin)).
		SetCmd(*req.Command.Cmd).SetTimeoutMs(req.Command.TimeoutMS).SetExpiresAt(now).
		SetStatus(approval.StatusConsumed).SetDecidedBy(SystemActor).SetDecidedAt(now).Save(ctx)
	if err != nil {
		return err
	}
	if err := audit.Checked(ctx, tx.AuditLog.Create(), SystemActor, "server", "approval_auto", a.ID.String(), "定时任务只读命令自动批准"); err != nil {
		return err
	}
	return tx.Commit()
}

// pending 等待到期时的说法。给模型的不能说成拒绝：它会把"被拒"当成障碍去改写命令绕过，
// 实际只是管理员还没处理，让它先做别的，最后把待批准的操作交代清楚。
func pending(req Request) error {
	if req.Origin != "ai" {
		return errors.New("审批超时，命令未执行")
	}
	return errors.New("这条命令仍在等待组管理员批准（已通知），暂未执行：可以先继续做不依赖它的工作，结束时在回复或报告里注明哪些操作在等待批准")
}

// notify 把新审批推给组管理员；推送失败只记日志，不影响等待。
func (g *Gate) notify(ctx context.Context, req Request, username string) {
	if g.Notify == nil {
		return
	}
	group, host := req.GroupID.String(), req.Command.AssetID.String()
	if grp, err := g.DB.Group.Get(ctx, req.GroupID); err == nil {
		group = grp.Name
	}
	if a, err := g.DB.Asset.Get(ctx, req.Command.AssetID); err == nil {
		host = a.Hostname
	}
	cmd := []rune(*req.Command.Cmd)
	if len(cmd) > 300 {
		cmd = append(cmd[:300], []rune("…")...)
	}
	title := "待批准：人工请求执行高风险命令"
	if req.Origin == "ai" {
		title = "待批准：AI 请求执行高风险命令"
	}
	text := fmt.Sprintf("组：%s\n主机：%s\n发起：%s\n命令：%s", group, host, username, string(cmd))
	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := g.Notify(sendCtx, title, text, "/approvals"); err != nil {
		slog.Error("审批通知发送失败", "group", req.GroupID, "err", err)
	}
}

type channelKey struct{}

// ViaChannel 标记审批经控制台以外的渠道决定（如飞书私聊卡片），审计来源记为该渠道。
func ViaChannel(ctx context.Context, channel string) context.Context {
	return context.WithValue(ctx, channelKey{}, channel)
}

// Decide 在数据库中原子决定并写审计；多个节点竞争只能成功一次。
func (g *Gate) Decide(ctx context.Context, id uuid.UUID, u *ent.User, approved bool) error {
	a, err := g.DB.Approval.Get(ctx, id)
	if err != nil {
		return err
	}
	if u == nil || !auth.Allowed(auth.GroupRole(ctx, g.DB, u, a.GroupID), "admin") {
		return errors.New("只有组内 admin 可以审批")
	}
	tx, err := g.DB.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	status := approval.StatusRejected
	if approved {
		status = approval.StatusApproved
	}
	n, err := tx.Approval.Update().Where(approval.IDEQ(id), approval.StatusEQ(approval.StatusPending), approval.ExpiresAtGT(time.Now())).SetStatus(status).SetDecidedBy(u.Username).SetDecidedAt(time.Now()).Save(ctx)
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("审批已结束或已过期")
	}
	source, _ := ctx.Value(channelKey{}).(string)
	if source == "" {
		source = "server"
	}
	if err := audit.Checked(ctx, tx.AuditLog.Create(), u.Username, source, "approval_decided", id.String(), string(status)); err != nil {
		return err
	}
	return tx.Commit()
}

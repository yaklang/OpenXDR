package commandgate

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"openxdr/server/ent/approval"
	"openxdr/server/internal/audit"
)

// ReviewerActor AI 审计员在审批记录与审计里的名字。用户名不允许取这个值。
const ReviewerActor = "ai-reviewer"

// Reviewer AI 发起、命中高风险名单的命令由它当场评审：审批没人会点，等下去只会让巡检和对话白白耗到期限。
// 返回是否批准与一句理由；出错按拒绝处理。
type Reviewer func(ctx context.Context, req Request) (approve bool, reason string, err error)

// reviewTimeout 一次评审的上限
const reviewTimeout = 2 * time.Minute

// hardDeny 切断平台自身或毁掉证据的操作：AI 发起的一律不执行、不送评审——审计员也是模型，这几类不赌它的判断。
// 只认出现在命令位置上的写法（cmdPos，与默认名单同一口径），`last reboot` 这类查询不受影响。
var hardDeny = []struct {
	why string
	re  *regexp.Regexp
}{
	{"删除文件或回收缓存", regexp.MustCompile(`(?i)` + cmdPos + `rm\b|` + cmdPos + `find\b[^;&|\n]*-delete\b|` + cmdPos + `docker\s+(?:image|builder)\s+prune\b|` + cmdPos + `apt-get\s+clean\b`)},
	{"停止或卸载 OpenXDR agent", regexp.MustCompile(`(?i)` + cmdPos + `(?:systemctl|service)\s+(?:stop|disable|mask|kill)\b[^;&|\n]*openxdr|` +
		cmdPos + `(?:pkill|killall|taskkill)\b[^;&|\n]*openxdr|` + cmdPos + `rm\b[^;&|\n]*(?:/usr/local/bin/openxdr|/var/lib/openxdr|/etc/systemd/system/openxdr)|` +
		`(?:Stop|Remove)-Service\b[^;&|\n]*openxdr`)},
	{"关机或重启", regexp.MustCompile(`(?i)` + cmdPos + `(?:shutdown|reboot|poweroff|halt)\b|` + cmdPos + `init\s+[06]\b|` +
		cmdPos + `systemctl\s+(?:reboot|poweroff|halt|kexec)\b|(?:Restart|Stop)-Computer\b`)},
	{"清空日志、命令历史或审计", regexp.MustCompile(`(?i)` + cmdPos + `journalctl\b[^;&|\n]*--vacuum|` +
		cmdPos + `(?:rm|truncate|shred)\b[^;&|\n]*(?:/var/log|\.bash_history|\.zsh_history)|>\s*/var/log/|` +
		cmdPos + `history\s+-c\b|` + cmdPos + `auditctl\s+(?:-D\b|-e\s*0\b)|` + cmdPos + `wevtutil\s+cl\b|Clear-EventLog\b`)},
	{"清空防火墙规则", regexp.MustCompile(`(?i)` + cmdPos + `(?:ip6?tables)(?:-legacy|-nft)?\s+(?:-F|--flush)\b|` +
		cmdPos + `nft\s+flush\s+ruleset\b|` + cmdPos + `ufw\s+(?:disable|reset)\b`)},
	{"格式化或覆写磁盘", regexp.MustCompile(`(?i)` + cmdPos + `mkfs(?:\.\w+)?\b|` + cmdPos + `dd\b[^;&|\n]*\bof=/dev/|` +
		`--no-preserve-root|` + cmdPos + `rm\s+-[a-z]*r[a-z]*\s+/(?:\s|$|\*)`)},
}

// hardDenied 命中硬拒绝清单时返回原因
func hardDenied(cmd string) string {
	for _, d := range hardDeny {
		if d.re.MatchString(cmd) {
			return d.why
		}
	}
	return ""
}

// review 交给 AI 审计员评审，结果按普通审批记下：批准记已消费、拒绝记已拒绝，决定人 ai-reviewer，理由写审计。
func (g *Gate) review(ctx context.Context, req Request, username string) error {
	reviewCtx, cancel := context.WithTimeout(ctx, reviewTimeout)
	approve, reason, err := g.Reviewer(reviewCtx, req)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		approve, reason = false, "审计员评审失败："+err.Error()
	}
	status, verdict := approval.StatusRejected, "rejected"
	if approve {
		status, verdict = approval.StatusConsumed, "approved"
	}
	tx, err := g.DB.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now()
	a, err := tx.Approval.Create().SetGroupID(req.GroupID).SetNillableSessionID(req.SessionID).
		SetAssetID(req.Command.AssetID).SetRequestedBy(username).SetOrigin(approval.Origin(req.Origin)).
		SetCmd(*req.Command.Cmd).SetTimeoutMs(req.Command.TimeoutMS).SetExpiresAt(now).
		SetStatus(status).SetDecidedBy(ReviewerActor).SetDecidedAt(now).Save(ctx)
	if err != nil {
		return err
	}
	if err := audit.Checked(ctx, tx.AuditLog.Create(), ReviewerActor, "server", "approval_ai_reviewed", a.ID.String(), verdict+": "+reason); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if !approve {
		return fmt.Errorf("AI 审计员没有批准这条命令：%s。不要换写法重复同一操作；确有必要就按理由调整做法，或在回复里说明由人处理", reason)
	}
	return nil
}

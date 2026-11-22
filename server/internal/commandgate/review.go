package commandgate

import (
	"context"
	"fmt"
	"regexp"
	"strings"
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
	// 删普通文件交 AI 审计员评审（默认名单 fileDeny）；系统目录、数据库与 Docker 数据、备份、SSH 钥匙、平台目录、
	// 数据卷与删库删表一律不执行。日志与 agent 目录各有专门条目
	{"删除系统目录、数据或备份", regexp.MustCompile(`(?i)` + cmdPos + `(?:rm|shred|unlink)\b[^;&|\n]*` + protectedPath + `|` +
		cmdPos + `find(?:\s+-\S+)*` + protectedPath + `[^;&|\n]*-delete\b|` +
		cmdPos + `docker\s+(?:-\S+\s+(?:[^-\s;&|]+\s+)?)*(?:volume\s+(?:rm|prune)\b|system\s+prune\b[^;&|\n]*--volumes)|` +
		`\bdrop\s+(?:database|schema|table)\b|` + cmdPos + `dropdb\b`)},
	{"停止或卸载 OpenXDR agent", regexp.MustCompile(`(?i)` + cmdPos + `systemctl\s+(?:-\S+\s+)*(?:stop|disable|mask|kill)\b[^;&|\n]*openxdr|` +
		cmdPos + `service\s+(?:[^;&|\n]*\bopenxdr[^;&|\n]*\s+(?:stop|disable)|(?:stop|disable)\b[^;&|\n]*openxdr)|` +
		cmdPos + `(?:pkill|killall|taskkill)\b[^;&|\n]*openxdr|` + cmdPos + `rm\b[^;&|\n]*(?:/usr/local/bin/openxdr|/var/lib/openxdr|/etc/systemd/system/openxdr)|` +
		`(?:Stop|Remove)-Service\b[^;&|\n]*openxdr`)},
	{"关机或重启", regexp.MustCompile(`(?i)` + cmdPos + `(?:shutdown|reboot|poweroff|halt)\b|` + cmdPos + `(?:tel)?init\s+[06]\b|` +
		cmdPos + `systemctl\s+(?:-\S+\s+)*(?:reboot|poweroff|halt|kexec)\b|(?:Restart|Stop)-Computer\b`)},
	{"清空日志、命令历史或审计", regexp.MustCompile(`(?i)` + cmdPos + `journalctl\b[^;&|\n]*--vacuum|` +
		cmdPos + `(?:rm|truncate|shred)\b[^;&|\n]*(?:/var/log|\.bash_history|\.zsh_history)|>\s*/var/log/|` +
		cmdPos + `history\s+-c\b|` + cmdPos + `auditctl\s+(?:-D\b|-e\s*0\b)|` + cmdPos + `wevtutil\s+cl\b|Clear-EventLog\b`)},
	{"清空防火墙规则", regexp.MustCompile(`(?i)` + cmdPos + `(?:ip6?tables)(?:-legacy|-nft)?\s+(?:[^;&|\n]*\s)?(?:-F|--flush)\b|` +
		cmdPos + `nft\s+(?:-\S+\s+)*flush\s+ruleset\b|` + cmdPos + `ufw\s+(?:-\S+\s+)*(?:disable|reset)\b`)},
	{"格式化或覆写磁盘", regexp.MustCompile(`(?i)` + cmdPos + `mkfs(?:\.\w+)?\b|` + cmdPos + `dd\b[^;&|\n]*\bof=/dev/|` +
		`--no-preserve-root|` +
		cmdPos + `rm\b[^;&|\n]*(?:-[a-zA-Z]*[rR]|--recursive)[^;&|\n]*\s+/(?:\s|$|\*)|` +
		cmdPos + `rm\b[^;&|\n]*\s+/(?:\s|\*|$)[^;&|\n]*(?:-[a-zA-Z]*[rR]|--recursive)`)},
}

// protectedPath 删除类命令参数里的受保护路径：系统目录、/var/lib（数据库与 Docker 数据）、备份、SSH 钥匙目录、平台部署目录
const protectedPath = `(?:\s|["'=])["']?(?:/(?:etc|usr|bin|sbin|lib(?:32|64)?|boot|var/lib|var/backups|root/\.ssh|home/[^/\s]+/\.ssh|opt/openxdr[^/\s]*)(?:[/\s"'*]|$)|[^\s;&|]*backups?(?:[/\s"'*.]|$))`

// unquoteWordBypass 剥除简单引号拼接与反斜杠转义绕过（如 \rm、r”m、r""m、/et\c、'rm'），
// 仅在引号内不含空白或 shell 分隔符时剥去引号，避免破坏原有引号边界语义。
func unquoteWordBypass(cmd string) string {
	var b strings.Builder
	b.Grow(len(cmd))
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if c == '\\' && i+1 < len(cmd) && !strings.ContainsRune(" \t\r\n", rune(cmd[i+1])) {
			b.WriteByte(cmd[i+1])
			i++
			continue
		}
		if c == '\'' || c == '"' {
			end := strings.IndexByte(cmd[i+1:], c)
			if end >= 0 {
				inner := cmd[i+1 : i+1+end]
				if !strings.ContainsAny(inner, " \t\r\n;|&`()") {
					// 双引号内若还有反斜杠转义（如 "r\m"），继续还原
					if c == '"' {
						inner = unquoteWordBypass(inner)
					}
					b.WriteString(inner)
					i += end + 1
					continue
				}
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// hardDenied 命中硬拒绝清单时返回原因
func hardDenied(cmd string) string {
	for _, d := range hardDeny {
		if d.re.MatchString(cmd) {
			return d.why
		}
	}
	if norm := unquoteWordBypass(cmd); norm != cmd {
		for _, d := range hardDeny {
			if d.re.MatchString(norm) {
				return d.why
			}
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

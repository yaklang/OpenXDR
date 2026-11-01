package automation

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/group"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/setting"
	"openxdr/server/ent/sshlogin"
	"openxdr/server/ent/trustedsource"
	"openxdr/server/internal/audit"
)

// 自动识别：平台定期从核对过出处的 SSH 登录里认出运维自动化，满足条件就生效，不用人去登记。
//
// 条件都要满足：公钥登录；来源是内网的单个固定地址（同一把钥匙不同地址分开判断）；窗口内登录有规律（天数、次数够）；
// 触发过告警，且全部已有结论、都是良性（人工判误报一个即可，只有 AI 结论时要够数），从没被判可疑以上。
// 生效后标「自动识别」、带依据、有有效期，持续满足就续期；生效与停用都通知、都落审计（操作者 system）。
//
// 它的告警一旦被判属实、恶意或可疑，立即停用，近期被它放过的告警重新送去研判——固定的条目也一样，
// 固定只挡续期与改条件，挡不住安全方向的收紧。人停用或删除过的身份永远不会被自动加回。

// 系统操作在审计与 revoked_by 里的名字，与自动结案一致
const actor = "system"

// 待发通知的种类
const (
	NoticeIdentified = "identified"
	NoticeRevoked    = "revoked"
)

// CauseVerdict 系统停用的原因：来源的告警被判属实、恶意或可疑
const CauseVerdict = "verdict"

// Notify 推送一条通知；path 是控制台内的相对链接
type Notify func(ctx context.Context, title, body, path string) error

// Auto 自动识别的后台任务，必须经 cluster.RunLeader 单活运行
type Auto struct {
	DB       *ent.Client
	SQL      *sql.DB
	Notify   Notify
	Interval time.Duration
	Config   Config
}

func (a *Auto) Run(ctx context.Context) {
	ticker := time.NewTicker(a.Interval)
	defer ticker.Stop()
	for {
		if err := a.Sweep(ctx, time.Now()); err != nil {
			slog.Error("运维自动化识别失败", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Sweep 一轮：收新登录、按结论停用、识别与续期、发通知。总开关关掉时只停识别与续期，停用与通知照常
func (a *Auto) Sweep(ctx context.Context, now time.Time) error {
	if err := a.collect(ctx, now); err != nil {
		return fmt.Errorf("收集 SSH 登录: %w", err)
	}
	assessments, facts, err := Assess(ctx, a.DB, a.SQL, a.Config, nil, now)
	if err != nil {
		return err
	}
	// 被判恶意即停用对人工登记的同样生效：「人登记过」不等于「被判恶意也不管」
	sources, err := a.DB.TrustedSource.Query().All(ctx)
	if err != nil {
		return err
	}
	if err := a.revoke(ctx, sources, facts, now); err != nil {
		return err
	}
	if a.Config.Enabled {
		if err := a.identify(ctx, assessments, now); err != nil {
			return err
		}
	}
	return a.notify(ctx)
}

const (
	cursorKey = "automation.login_cursor"
	// 事件晚到的余量：每轮从上次的位置往回多看这么久，按事件 ID 去重
	lateSlack = 10 * time.Minute
	// 补扫时每段的跨度：一次扫一整周的事件要几十秒，分段不长时间占着连接
	scanStep = 6 * time.Hour
)

// collect 把新到的、带登录归属的 SSH 成功登录增量收进 ssh_logins，并清掉窗口外的
func (a *Auto) collect(ctx context.Context, now time.Time) error {
	from := now.AddDate(0, 0, -a.Config.WindowDays)
	if row, err := a.DB.Setting.Get(ctx, cursorKey); err == nil {
		var at time.Time
		if json.Unmarshal(row.Value, &at) == nil && at.Add(-lateSlack).After(from) {
			from = at.Add(-lateSlack)
		}
	}
	for from.Before(now) {
		to := from.Add(scanStep)
		if to.After(now) {
			to = now
		}
		if _, err := a.SQL.ExecContext(ctx, `INSERT INTO ssh_logins (id, ts, group_id, asset_id, login_user, src_ip, auth_method, key_fp, key_type, recorded_at)
SELECT e.id, e.ts, s.group_id, e.asset_id, e.raw->'login_session'->>'user', e.raw->'login_session'->>'src_ip',
  COALESCE(e.raw->'login_session'->>'auth_method', ''),
  NULLIF(e.raw->'login_session'->>'key_fp', ''), NULLIF(e.raw->'login_session'->>'key_type', ''), now()
FROM events e JOIN assets s ON s.id = e.asset_id
WHERE e.ts > $1 AND e.ts <= $2 AND e.class_uid = 3002 AND e.source = 'agent'
  AND jsonb_typeof(e.raw->'login_session') = 'object' AND s.group_id IS NOT NULL
  AND COALESCE(e.raw->'login_session'->>'user', '') <> '' AND COALESCE(e.raw->'login_session'->>'src_ip', '') <> ''
ON CONFLICT (id) DO NOTHING`, from, to); err != nil {
			return err
		}
		from = to
	}
	value, _ := json.Marshal(now)
	n, err := a.DB.Setting.Update().Where(setting.IDEQ(cursorKey)).SetValue(value).Save(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		if err := a.DB.Setting.Create().SetID(cursorKey).SetValue(value).Exec(ctx); err != nil {
			return err
		}
	}
	_, err = a.DB.SSHLogin.Delete().Where(sshlogin.TsLT(now.AddDate(0, 0, -a.Config.WindowDays-1))).Exec(ctx)
	return err
}

// revoke 生效中的自动识别，只要它的告警（生效前同一身份的、生效后挂在它上面的）被判可疑以上就停用。
// 固定的也停：固定是人对「别再自动改它」的表态，不是对「被判恶意也别管」的授权
func (a *Auto) revoke(ctx context.Context, sources []*ent.TrustedSource, facts []fact, now time.Time) error {
	for _, t := range sources {
		if t.RevokedAt != nil || t.DeletedAt != nil {
			continue
		}
		var flagged *uuid.UUID
		for _, f := range facts {
			// 人确认过（重新启用或人工登记）之前的结论不算：人是看过这些之后才做的决定
			confirmed := t.ConfirmedAt
			if confirmed == nil && t.Origin != "auto" {
				confirmed = &t.CreatedAt
			}
			if f.verdict != bad || f.group != t.GroupID || (confirmed != nil && f.ts.Before(*confirmed)) {
				continue
			}
			// 同一把钥匙、同一个用户从别处登录被判恶意，同样说明这个身份不可信了
			mine := f.source != nil && *f.source == t.ID
			same := t.KeyFingerprint != nil && t.LoginUser != nil && f.login.KeyFP == *t.KeyFingerprint && f.login.User == *t.LoginUser
			if mine || same {
				flagged = f.incident
				break
			}
		}
		if flagged == nil {
			continue
		}
		err := a.tx(ctx, func(tx *ent.Tx) error {
			n, err := tx.TrustedSource.Update().Where(trustedsource.IDEQ(t.ID), trustedsource.RevokedAtIsNil()).
				SetRevokedAt(now).SetRevokedBy(actor).SetRevokeCause(CauseVerdict).SetNillableRevokeIncidentID(flagged).
				SetNotice(NoticeRevoked).Save(ctx)
			if err != nil || n == 0 {
				return err
			}
			// 被它放过、还没进事件的近期告警重新送去关联与研判：既然这个身份不可信了，这些也该有人看
			released, err := tx.Alert.Update().Where(alert.AutomationIDEQ(t.ID), alert.IncidentIDIsNil(), alert.AutomationWatch(false),
				alert.TsGT(now.AddDate(0, 0, -a.Config.WindowDays))).SetAutomationWatch(true).Save(ctx)
			if err != nil {
				return err
			}
			return audit.Checked(ctx, tx.AuditLog.Create(), actor, "server", "trusted_source_auto_revoked", t.ID.String(),
				fmt.Sprintf("%s 告警被判属实、恶意或可疑（事件 %s），自动停用；%d 条近期告警重新送去研判", t.Name, idText(flagged), released))
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// identify 满足条件的身份新建或重新启用自动识别，已生效的续期
func (a *Auto) identify(ctx context.Context, assessments []*Assessment, now time.Time) error {
	sources, err := a.DB.TrustedSource.Query().Where(trustedsource.OriginEQ("manual")).All(ctx)
	if err != nil {
		return err
	}
	all, err := a.DB.TrustedSource.Query().Where(trustedsource.OriginEQ("auto")).All(ctx)
	if err != nil {
		return err
	}
	ttl := time.Duration(a.Config.TTLDays) * 24 * time.Hour
	for _, as := range assessments {
		if as.KeyFP == "" {
			continue
		}
		var mine *ent.TrustedSource
		for _, t := range all {
			if t.GroupID == as.Group && t.KeyFingerprint != nil && *t.KeyFingerprint == as.KeyFP && t.LoginUser != nil && *t.LoginUser == as.User {
				mine = t
			}
		}
		switch {
		case mine == nil:
			if as.Reason != ReasonEligible || covered(sources, as, now) {
				continue
			}
			if err := a.create(ctx, as, now); err != nil {
				return err
			}
		case mine.DeletedAt != nil || mine.RevokedAt != nil || mine.Pinned:
			// 人否决过的、系统因结论停用的不自动加回；固定的不自动改
			continue
		case !mine.ExpiresAt.After(now):
			if as.Reason != ReasonEligible || covered(sources, as, now) {
				continue
			}
			if err := a.renew(ctx, mine, as, now, true); err != nil {
				return err
			}
		case as.Renewable() && mine.ExpiresAt.Before(now.Add(ttl-24*time.Hour)):
			// 一天续一次：续期也落审计，每轮都续会把审计刷屏
			if err := a.renew(ctx, mine, as, now, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// covered 组里已有生效的人工条目覆盖这个身份的全部来源地址，或人停用、删除过覆盖它的人工条目（人已经表过态）
func covered(sources []*ent.TrustedSource, as *Assessment, now time.Time) bool {
	all := true
	for _, addr := range as.Addresses {
		hit := false
		for _, t := range sources {
			if t.GroupID != as.Group {
				continue
			}
			if !(Source{ID: t.ID, KeyFingerprint: t.KeyFingerprint, SourceCIDR: t.SourceCidr, LoginUser: t.LoginUser}).Matches(as.Login(addr)) {
				continue
			}
			if t.RevokedAt != nil {
				return true
			}
			if t.ExpiresAt.After(now) {
				hit = true
			}
		}
		all = all && hit
	}
	return all
}

func (a *Auto) create(ctx context.Context, as *Assessment, now time.Time) error {
	name := fmt.Sprintf("%s@%s", as.User, strings.TrimSuffix(strings.TrimSuffix(as.CIDR, "/32"), "/128"))
	return a.tx(ctx, func(tx *ent.Tx) error {
		row, err := tx.TrustedSource.Create().SetGroupID(as.Group).SetName(name).SetCreatedBy(actor).SetOrigin("auto").
			SetExpiresAt(now.AddDate(0, 0, a.Config.TTLDays)).SetCreatedAt(now).
			SetKeyFingerprint(as.KeyFP).SetSourceCidr(as.CIDR).SetLoginUser(as.User).
			SetEvidence(as.Evidence(a.Config, now)).SetNotice(NoticeIdentified).Save(ctx)
		if err != nil {
			return err
		}
		return audit.Checked(ctx, tx.AuditLog.Create(), actor, "server", "trusted_source_auto_created", row.ID.String(),
			fmt.Sprintf("%s 组=%s %s 有效期=%d天", name, as.Group, describe(as), a.Config.TTLDays))
	})
}

// renew 续期；revive 为真时是过期后重新满足条件，重新生效要再通知一次
func (a *Auto) renew(ctx context.Context, t *ent.TrustedSource, as *Assessment, now time.Time, revive bool) error {
	return a.tx(ctx, func(tx *ent.Tx) error {
		upd := tx.TrustedSource.UpdateOneID(t.ID).SetExpiresAt(now.AddDate(0, 0, a.Config.TTLDays)).
			SetSourceCidr(as.CIDR).SetEvidence(as.Evidence(a.Config, now))
		action := "trusted_source_auto_renewed"
		if revive {
			upd.SetNotice(NoticeIdentified)
			action = "trusted_source_auto_revived"
		}
		if err := upd.Exec(ctx); err != nil {
			return err
		}
		return audit.Checked(ctx, tx.AuditLog.Create(), actor, "server", action, t.ID.String(),
			fmt.Sprintf("%s %s 有效期延至 %s", t.Name, describe(as), now.AddDate(0, 0, a.Config.TTLDays).Format(time.DateOnly)))
	})
}

func describe(as *Assessment) string {
	return fmt.Sprintf("指纹=%s 来源=%s 用户=%s 登录=%d次/%d天/%d台 结论=人工误报%d AI良性%d 告警%d",
		as.KeyFP, as.CIDR, as.User, as.Logins, as.Days, as.Hosts, as.HumanBenign, as.AIBenign, as.Alerts)
}

// notify 把待发的通知按种类各合成一条发出去，发成功才清标记，失败下轮重试
func (a *Auto) notify(ctx context.Context) error {
	pending, err := a.DB.TrustedSource.Query().Where(trustedsource.NoticeNotNil()).
		Order(ent.Asc(trustedsource.FieldCreatedAt)).Limit(50).All(ctx)
	if err != nil || len(pending) == 0 {
		return err
	}
	groups := map[uuid.UUID]string{}
	gs, err := a.DB.Group.Query().Select(group.FieldID, group.FieldName).All(ctx)
	if err != nil {
		return err
	}
	for _, g := range gs {
		groups[g.ID] = g.Name
	}
	var incidents []uuid.UUID
	for _, t := range pending {
		if t.RevokeIncidentID != nil {
			incidents = append(incidents, *t.RevokeIncidentID)
		}
	}
	titles := map[uuid.UUID]string{}
	if len(incidents) > 0 {
		incs, err := a.DB.Incident.Query().Where(incident.IDIn(incidents...)).Select(incident.FieldID, incident.FieldTitle).All(ctx)
		if err != nil {
			return err
		}
		for _, inc := range incs {
			if inc.Title != nil {
				titles[inc.ID] = *inc.Title
			}
		}
	}
	byKind := map[string][]*ent.TrustedSource{}
	for _, t := range pending {
		byKind[*t.Notice] = append(byKind[*t.Notice], t)
	}
	for _, kind := range []string{NoticeRevoked, NoticeIdentified} {
		rows := byKind[kind]
		if len(rows) == 0 {
			continue
		}
		title, body, path := message(kind, rows, groups, titles)
		if a.Notify != nil {
			if err := a.Notify(ctx, title, body, path); err != nil {
				slog.Error("运维自动化通知失败，下轮重试", "kind", kind, "err", err)
				continue
			}
		}
		ids := make([]uuid.UUID, len(rows))
		for i, t := range rows {
			ids[i] = t.ID
		}
		if err := a.DB.TrustedSource.Update().Where(trustedsource.IDIn(ids...), trustedsource.NoticeEQ(kind)).ClearNotice().Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// message 通知正文：说清是谁、凭什么、对你有什么影响、不认可怎么办
func message(kind string, rows []*ent.TrustedSource, groups map[uuid.UUID]string, titles map[uuid.UUID]string) (string, string, string) {
	var b strings.Builder
	if kind == NoticeRevoked {
		for _, t := range rows {
			why := "它触发的告警被判为属实、恶意或可疑"
			if t.RevokeIncidentID != nil && titles[*t.RevokeIncidentID] != "" {
				why += "（事件：" + titles[*t.RevokeIncidentID] + "）"
			}
			fmt.Fprintf(&b, "· %s（%s 组）：%s\n", t.Name, groups[t.GroupID], why)
		}
		b.WriteString("它的告警恢复正常研判与提醒，最近被它放过的告警也已重新送去研判。请确认这个登录身份有没有被盗用；确认没问题后，可以在「已知自动化」页重新启用。")
		path := "/trusted-sources"
		if len(rows) == 1 && rows[0].RevokeIncidentID != nil {
			path = "/incidents/" + rows[0].RevokeIncidentID.String()
		}
		return fmt.Sprintf("%d 个已知自动化已自动停用", len(rows)), b.String(), path
	}
	for _, t := range rows {
		line := fmt.Sprintf("· %s（%s 组）", t.Name, groups[t.GroupID])
		if e := t.Evidence; e != nil {
			line += fmt.Sprintf("：近 %d 天有 %d 天登录，共 %d 次、%d 台主机；之前的告警", e.WindowDays, e.Days, e.Logins, e.Hosts)
			var parts []string
			if e.HumanBenign > 0 {
				parts = append(parts, fmt.Sprintf("%d 个事件经人工判为误报", e.HumanBenign))
			}
			if e.AIBenign > 0 {
				parts = append(parts, fmt.Sprintf("%d 个事件经 AI 判为良性", e.AIBenign))
			}
			line += strings.Join(parts, "、")
		}
		b.WriteString(line + "\n")
	}
	b.WriteString("之后它的告警照常保留、随时可查，但不再生成事件、不再推送；拿凭据、清痕迹、关防护这类高危行为照常提醒。不认可的话，到「已知自动化」页停用或删除即可，之后不会再被自动加回。")
	return fmt.Sprintf("认出 %d 个日常自动化，已加入「已知自动化」", len(rows)), b.String(), "/trusted-sources"
}

func (a *Auto) tx(ctx context.Context, fn func(*ent.Tx) error) error {
	tx, err := a.DB.Tx(ctx)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func idText(id *uuid.UUID) string {
	if id == nil {
		return "-"
	}
	return id.String()
}

// sessionOf 事件体上的登录归属，要有用户与来源
func sessionOf(raw json.RawMessage) (Login, bool) {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return Login{}, false
	}
	l, ok := Session(m)
	return l, ok && l.User != "" && l.SrcIP != ""
}

// verdictOf 研判结论里的 verdict，解析不了当没有
func verdictOf(raw json.RawMessage) string {
	var v struct {
		Verdict string `json:"verdict"`
	}
	_ = json.Unmarshal(raw, &v)
	return v.Verdict
}

//go:build integration

package automation

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/trustedsource"
	"openxdr/server/internal/testdb"
)

// 指纹按序号造，格式与 ssh-keygen 一致（SHA256: + 43 位 base64）
func fpN(n int) string { return fmt.Sprintf("SHA256:%043d", n) }

type world struct {
	t      *testing.T
	ctx    context.Context
	db     *ent.Client
	group  uuid.UUID
	host   uuid.UUID
	base   time.Time
	sent   []string
	auto   *Auto
	failed bool
}

func newWorld(t *testing.T) *world {
	ctx, client := testdb.New(t)
	raw, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	g := client.Group.Create().SetName("ops").SaveX(ctx)
	host := client.Asset.Create().SetHostname("pve1").SetGroupID(g.ID).SaveX(ctx)
	w := &world{t: t, ctx: ctx, db: client, group: g.ID, host: host.ID, base: time.Now()}
	w.auto = &Auto{DB: client, SQL: raw, Config: DefaultConfig(), Notify: func(_ context.Context, title, body, _ string) error {
		if w.failed {
			return fmt.Errorf("推送失败")
		}
		w.sent = append(w.sent, title+"\n"+body)
		return nil
	}}
	return w
}

func session(user, ip, method, fp string) string {
	return fmt.Sprintf(`{"user":%q,"src_ip":%q,"auth_method":%q,"key_type":"ED25519","key_fp":%q}`, user, ip, method, fp)
}

// logins 在 days 天里每天登录 perDay 次
func (w *world) logins(days, perDay int, ls string) {
	for d := 0; d < days; d++ {
		for i := 0; i < perDay; i++ {
			ts := w.base.Add(-time.Duration(d)*24*time.Hour - time.Duration(i+1)*time.Minute)
			w.db.Event.Create().SetTs(ts).SetClassUID(3002).SetSource("agent").SetAssetID(w.host).
				SetRaw(json.RawMessage(`{"status_id":1,"login_session":` + ls + `}`)).ExecX(w.ctx)
		}
	}
}

// incident 造一个事件，status 与 AI 结论、结案来源按参数
func (w *world) incident(status, verdict string, resolvedBy, source string) uuid.UUID {
	c := w.db.Incident.Create().SetStatus(status).SetGraph(json.RawMessage(`{}`)).SetTitle("运维探测")
	if verdict != "" {
		c.SetAiVerdict(json.RawMessage(`{"verdict":"` + verdict + `"}`))
	}
	if resolvedBy != "" {
		c.SetResolvedBy(resolvedBy).SetResolvedAt(time.Now())
	}
	if source != "" {
		c.SetResolutionSource(source)
	}
	return c.SaveX(w.ctx).ID
}

// alert 会话里的进程触发一条告警
func (w *world) alert(ls string, sev int16, inc *uuid.UUID, src *uuid.UUID, watch bool) *ent.Alert {
	ev := w.db.Event.Create().SetTs(w.base.Add(-time.Hour)).SetClassUID(1007).SetSource("agent").SetAssetID(w.host).
		SetRaw(json.RawMessage(`{"process":{"cmd_line":"uname -a"},"login_session":` + ls + `}`)).SaveX(w.ctx)
	c := w.db.Alert.Create().SetTs(ev.Ts).SetRuleID("recon").SetSeverity(sev).SetEventID(ev.ID).SetAssetID(w.host).
		SetNillableIncidentID(inc).SetNillableAutomationID(src).SetAutomationWatch(watch)
	return c.SaveX(w.ctx)
}

// same 落库后只保留到微秒，比较时间放一点余量
func same(a, b time.Time) bool { return a.Sub(b).Abs() < time.Millisecond }

func (w *world) sweep(at time.Time) {
	w.t.Helper()
	if err := w.auto.Sweep(w.ctx, at); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) autoRow(fp string) *ent.TrustedSource {
	w.t.Helper()
	rows := w.db.TrustedSource.Query().Where(trustedsource.OriginEQ("auto"), trustedsource.KeyFingerprintEQ(fp)).AllX(w.ctx)
	if len(rows) > 1 {
		w.t.Fatalf("%s 有 %d 条自动识别", fp, len(rows))
	}
	if len(rows) == 0 {
		return nil
	}
	return rows[0]
}

func (w *world) audits(action string) int {
	return w.db.AuditLog.Query().Where(auditlog.ActionEQ(action), auditlog.UsernameEQ("system")).CountX(w.ctx)
}

// 满足条件的自动生效、带依据、通知一次、落审计；不满足的各自说得清原因
func TestAutoIdentify(t *testing.T) {
	w := newWorld(t)
	ok := session("root", "10.1.1.35", "publickey", fpN(1))
	w.logins(4, 6, ok)
	human := w.incident("false_positive", "benign", "lead", "")
	w.alert(ok, 5, &human, nil, false)

	// 只有 AI 结论：3 个低危良性事件够数
	aiOK := session("ops", "10.1.1.36", "publickey", fpN(2))
	w.logins(3, 8, aiOK)
	for i := 0; i < 3; i++ {
		inc := w.incident("triaged", "benign", "", "")
		w.alert(aiOK, 3, &inc, nil, false)
	}

	cases := map[string]string{}
	add := func(reason, ls string, days int, alerts func(ls string)) {
		w.logins(days, 6, ls)
		alerts(ls)
		cases[ls] = reason
	}
	benign := func(ls string) {
		inc := w.incident("false_positive", "benign", "lead", "")
		w.alert(ls, 3, &inc, nil, false)
	}
	add(ReasonNoKey, session("deploy", "10.1.1.40", "password", ""), 4, benign)
	add(ReasonPublic, session("root", "8.8.8.8", "publickey", fpN(3)), 4, benign)
	add(ReasonFlagged, session("root", "10.1.1.41", "publickey", fpN(4)), 4, func(ls string) {
		benign(ls)
		bad := w.incident("closed", "benign", "lead", "")
		w.alert(ls, 3, &bad, nil, false)
	})
	add(ReasonPending, session("root", "10.1.1.42", "publickey", fpN(5)), 4, func(ls string) {
		benign(ls)
		open := w.incident("open", "", "", "")
		w.alert(ls, 3, &open, nil, false)
	})
	add(ReasonPending, session("root", "10.1.1.43", "publickey", fpN(6)), 4, func(ls string) {
		// 高危事件的 AI 良性结论按「需人工复核」口径不作数
		inc := w.incident("triaged", "benign", "", "")
		w.alert(ls, 4, &inc, nil, false)
	})
	add(ReasonFewVerdicts, session("root", "10.1.1.44", "publickey", fpN(7)), 4, func(ls string) {
		for i := 0; i < 2; i++ {
			inc := w.incident("triaged", "benign", "", "")
			w.alert(ls, 3, &inc, nil, false)
		}
	})
	add(ReasonFewVerdicts, session("root", "10.1.1.45", "publickey", fpN(8)), 4, func(ls string) {
		// 人直接采纳 AI 结论结案、系统自动结案的都按 AI 结论算
		a := w.incident("false_positive", "benign", "lead", "ai_verdict")
		b := w.incident("false_positive", "benign", "system", "")
		w.alert(ls, 3, &a, nil, false)
		w.alert(ls, 3, &b, nil, false)
	})
	add(ReasonQuiet, session("root", "10.1.1.46", "publickey", fpN(9)), 4, func(string) {})
	add(ReasonIrregular, session("root", "10.1.1.47", "publickey", fpN(10)), 2, benign)

	w.sweep(w.base)

	row := w.autoRow(fpN(1))
	if row == nil || row.RevokedAt != nil || row.CreatedBy != "system" || row.SourceCidr == nil || *row.SourceCidr != "10.1.1.35/32" ||
		row.LoginUser == nil || *row.LoginUser != "root" || row.Notice != nil {
		t.Fatalf("满足条件应自动生效且通知已发: %+v", row)
	}
	if e := row.Evidence; e == nil || e.Days != 4 || e.Logins != 24 || e.HumanBenign != 1 || e.Hosts != 1 {
		t.Fatalf("依据不对: %+v", row.Evidence)
	}
	if d := row.ExpiresAt.Sub(w.base); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Fatalf("默认有效期应为 30 天，实际 %s", d)
	}
	if w.autoRow(fpN(2)) == nil {
		t.Fatal("3 个 AI 良性事件应够数")
	}
	for i := 3; i <= 10; i++ {
		if r := w.autoRow(fpN(i)); r != nil {
			t.Fatalf("%s 不该被识别: %+v", fpN(i), r)
		}
	}
	if len(w.sent) != 1 || !strings.Contains(w.sent[0], "认出 2 个日常自动化") || !strings.Contains(w.sent[0], "1 个事件经人工判为误报") {
		t.Fatalf("应合成一条生效通知: %q", w.sent)
	}
	if n := w.audits("trusted_source_auto_created"); n != 2 {
		t.Fatalf("生效应以 system 落审计，实际 %d 条", n)
	}

	assessments, _, err := Assess(w.ctx, w.db, w.auto.SQL, w.auto.Config, &w.group, w.base)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range assessments {
		for ls, want := range cases {
			l, _ := sessionOf(json.RawMessage(`{"login_session":` + ls + `}`))
			if l.User == a.User && l.KeyFP == a.KeyFP && (a.KeyFP != "" || a.Addresses[0] == l.SrcIP) && a.Reason != want {
				t.Errorf("%s：原因应为 %s，实际 %s", ls, want, a.Reason)
			}
		}
	}

	// 再扫一轮：不重复建、不重复通知
	w.sweep(w.base.Add(time.Minute))
	if len(w.sent) != 1 || w.db.TrustedSource.Query().CountX(w.ctx) != 2 {
		t.Fatalf("重复识别或重复通知: %d 条通知", len(w.sent))
	}

	// 自动识别之后，这个身份的新告警挂到条目上
	got, err := Of(w.ctx, w.auto.SQL, map[string]any{"login_session": map[string]any{"user": "root", "src_ip": "10.1.1.35", "key_fp": fpN(1)}}, &w.host, w.base)
	if err != nil || got == nil || *got != row.ID {
		t.Fatalf("自动识别应参与核对: %v %v", got, err)
	}
}

// 推送失败不落标记，下轮重试；生效不因推送失败而推迟
func TestAutoNoticeRetry(t *testing.T) {
	w := newWorld(t)
	ls := session("root", "10.1.1.35", "publickey", fpN(1))
	w.logins(4, 6, ls)
	inc := w.incident("false_positive", "benign", "lead", "")
	w.alert(ls, 3, &inc, nil, false)
	w.failed = true
	w.sweep(w.base)
	if row := w.autoRow(fpN(1)); row == nil || row.Notice == nil {
		t.Fatalf("推送失败应保留待发标记: %+v", row)
	}
	w.failed = false
	w.sweep(w.base.Add(time.Minute))
	if row := w.autoRow(fpN(1)); row.Notice != nil || len(w.sent) != 1 {
		t.Fatalf("重试成功后应清标记: %+v %d", row, len(w.sent))
	}
}

// 告警被判可疑以上立即停用（固定的、人工登记的也停）、通知、落审计，被放过的近期告警重新送去研判，且不会被自动加回；
// 人工条目只看登记之后的结论
func TestAutoRevoke(t *testing.T) {
	w := newWorld(t)
	a := session("root", "10.1.1.35", "publickey", fpN(1))
	b := session("ops", "10.1.1.36", "publickey", fpN(2))
	m := session("termix", "10.1.1.37", "publickey", fpN(3))
	for _, ls := range []string{a, b, m} {
		w.logins(4, 6, ls)
		inc := w.incident("false_positive", "benign", "lead", "")
		w.alert(ls, 3, &inc, nil, false)
	}
	manual := w.db.TrustedSource.Create().SetGroupID(w.group).SetName("Termix").SetCreatedBy("lead").SetCreatedAt(w.base.Add(-30 * time.Minute)).
		SetExpiresAt(w.base.AddDate(0, 0, 90)).SetKeyFingerprint(fpN(3)).SaveX(w.ctx)
	// 登记之前就有的恶意结论：人是看过之后才登记的，不因此停用
	old := w.incident("triaged", "malicious", "", "")
	w.alert(m, 3, &old, &manual.ID, true)
	w.sweep(w.base.Add(30 * time.Second))
	if got := w.db.TrustedSource.GetX(w.ctx, manual.ID); got.RevokedAt != nil {
		t.Fatal("登记之前的结论不应停用人工条目")
	}
	w.sweep(w.base)
	ra, rb := w.autoRow(fpN(1)), w.autoRow(fpN(2))
	if ra == nil || rb == nil || w.autoRow(fpN(3)) != nil {
		t.Fatal("a、b 应自动识别；m 已有人工条目覆盖，不该重复建")
	}
	w.db.TrustedSource.UpdateOneID(rb.ID).SetPinned(true).ExecX(w.ctx)
	w.sent = nil

	// a：生效后一条高危例外进了研判，被判可疑；另有一条被放过、还没进事件的告警
	suspicious := w.incident("triaged", "suspicious", "", "")
	w.alert(a, 4, &suspicious, &ra.ID, true)
	hidden := w.alert(a, 3, nil, &ra.ID, false)
	// b（固定）：生效前的旧事件被人改判属实
	bad := w.incident("closed", "benign", "lead", "")
	w.alert(b, 3, &bad, nil, false)
	// 人工条目登记之后的告警被判恶意：同样停用
	mal := w.incident("triaged", "malicious", "", "")
	after := w.alert(m, 3, &mal, &manual.ID, true)
	w.db.Alert.UpdateOneID(after.ID).SetTs(w.base.Add(-time.Minute)).ExecX(w.ctx)

	w.sweep(w.base.Add(time.Minute))
	ra, rb = w.autoRow(fpN(1)), w.autoRow(fpN(2))
	for _, r := range []*ent.TrustedSource{ra, rb} {
		if r.RevokedAt == nil || r.RevokedBy == nil || *r.RevokedBy != "system" || r.RevokeCause == nil || *r.RevokeCause != CauseVerdict {
			t.Fatalf("应由系统按结论停用: %+v", r)
		}
	}
	if ra.RevokeIncidentID == nil || *ra.RevokeIncidentID != suspicious || rb.RevokeIncidentID == nil || *rb.RevokeIncidentID != bad {
		t.Fatalf("停用应记下事件: %v %v", ra.RevokeIncidentID, rb.RevokeIncidentID)
	}
	if !w.db.Alert.Query().Where(alert.IDEQ(hidden.ID)).OnlyX(w.ctx).AutomationWatch {
		t.Fatal("被放过的近期告警应重新送去研判")
	}
	if got := w.db.TrustedSource.GetX(w.ctx, manual.ID); got.RevokedAt == nil || got.RevokeIncidentID == nil || *got.RevokeIncidentID != mal {
		t.Fatalf("人工条目登记后被判恶意也应停用: %+v", got)
	}
	if len(w.sent) != 1 || !strings.Contains(w.sent[0], "3 个已知自动化已自动停用") {
		t.Fatalf("应发一条停用通知: %q", w.sent)
	}
	if n := w.audits("trusted_source_auto_revoked"); n != 3 {
		t.Fatalf("停用应落审计，实际 %d", n)
	}

	// 之后照样满足登录规律，也不会被自动加回或复活
	w.sweep(w.base.Add(2 * time.Minute))
	if r := w.autoRow(fpN(1)); r.RevokedAt == nil {
		t.Fatal("停用的不应被自动启用")
	}
	if n := w.db.TrustedSource.Query().CountX(w.ctx); n != 3 {
		t.Fatalf("不应新建条目，实际 %d 条", n)
	}
}

// 持续满足就续期（一天一次）；长期不出现自然过期；固定的不续期；人停用、删除过的不被加回，过期的重新满足会再生效
func TestAutoRenewExpireAndUserDecisions(t *testing.T) {
	w := newWorld(t)
	a := session("root", "10.1.1.35", "publickey", fpN(1))
	p := session("ops", "10.1.1.36", "publickey", fpN(2))
	d := session("svc", "10.1.1.37", "publickey", fpN(3))
	x := session("bak", "10.1.1.38", "publickey", fpN(4))
	for _, ls := range []string{a, p, d, x} {
		w.logins(4, 6, ls)
		inc := w.incident("false_positive", "benign", "lead", "")
		w.alert(ls, 3, &inc, nil, false)
	}
	w.sweep(w.base)
	ra, rp, rd, rx := w.autoRow(fpN(1)), w.autoRow(fpN(2)), w.autoRow(fpN(3)), w.autoRow(fpN(4))
	if ra == nil || rp == nil || rd == nil || rx == nil {
		t.Fatal("四个身份都应识别")
	}
	pinnedUntil := w.base.AddDate(0, 0, 5)
	w.db.TrustedSource.UpdateOneID(rp.ID).SetPinned(true).SetExpiresAt(pinnedUntil).ExecX(w.ctx)
	w.db.TrustedSource.UpdateOneID(rd.ID).SetRevokedAt(w.base).SetRevokedBy("lead").ExecX(w.ctx)
	w.db.TrustedSource.UpdateOneID(rx.ID).SetRevokedAt(w.base).SetRevokedBy("lead").SetDeletedAt(w.base).SetDeletedBy("lead").ExecX(w.ctx)

	// 两天后仍在规律登录（窗口内还有 4 天里的 2 天 + 新的两天）
	w.base = w.base.Add(2 * 24 * time.Hour)
	w.logins(2, 6, a)
	w.logins(2, 6, p)
	w.logins(2, 6, d)
	w.logins(2, 6, x)
	w.sweep(w.base)
	if got := w.autoRow(fpN(1)); !got.ExpiresAt.After(ra.ExpiresAt.Add(24 * time.Hour)) {
		t.Fatalf("持续满足应续期: %s → %s", ra.ExpiresAt, got.ExpiresAt)
	}
	if n := w.audits("trusted_source_auto_renewed"); n != 1 {
		t.Fatalf("续期应落审计且只续未固定的那一条，实际 %d", n)
	}
	if got := w.autoRow(fpN(2)); !same(got.ExpiresAt, pinnedUntil) {
		t.Fatalf("固定的不应被续期覆盖: %s", got.ExpiresAt)
	}
	if got := w.autoRow(fpN(3)); got.RevokedAt == nil || *got.RevokedBy != "lead" {
		t.Fatal("人停用的不应被自动启用")
	}
	if got := w.autoRow(fpN(4)); got.DeletedAt == nil || got.RevokedAt == nil {
		t.Fatal("人删除的不应被自动加回")
	}
	if n := w.db.TrustedSource.Query().CountX(w.ctx); n != 4 {
		t.Fatalf("不应新建条目，实际 %d", n)
	}
	w.sent = nil

	// 之后不再登录：40 天后没有续期，自然过期，Of 不再认
	later := w.base.Add(40 * 24 * time.Hour)
	w.sweep(later)
	got := w.autoRow(fpN(1))
	if got.ExpiresAt.After(later) {
		t.Fatalf("长期不出现应过期: %s", got.ExpiresAt)
	}
	src, err := Of(w.ctx, w.auto.SQL, map[string]any{"login_session": map[string]any{"user": "root", "src_ip": "10.1.1.35", "key_fp": fpN(1)}}, &w.host, later)
	if err != nil || src != nil {
		t.Fatalf("过期后不应再认: %v %v", src, err)
	}

	// 过期后重新规律登录并且有新的良性结论：同一条重新生效并再通知一次
	// （登录都发生在上一轮之后：后台按到达增量收登录）
	w.base = later.Add(4 * 24 * time.Hour)
	w.logins(4, 6, a)
	inc := w.incident("false_positive", "benign", "lead", "")
	w.alert(a, 3, &inc, nil, false)
	w.sweep(w.base.Add(time.Minute))
	got = w.autoRow(fpN(1))
	if !got.ExpiresAt.After(w.base.AddDate(0, 0, 29)) || got.ID != ra.ID || len(w.sent) != 1 {
		t.Fatalf("过期后重新满足应复用原条目重新生效并通知: %+v %q", got, w.sent)
	}
	if n := w.audits("trusted_source_auto_revived"); n != 1 {
		t.Fatalf("重新生效应落审计，实际 %d", n)
	}
}

// 总开关关掉：不识别、不续期，但已识别条目被判恶意时照样停用
func TestAutoDisabled(t *testing.T) {
	w := newWorld(t)
	ls := session("root", "10.1.1.35", "publickey", fpN(1))
	w.logins(4, 6, ls)
	inc := w.incident("false_positive", "benign", "lead", "")
	w.alert(ls, 3, &inc, nil, false)
	w.auto.Config.Enabled = false
	w.sweep(w.base)
	if w.autoRow(fpN(1)) != nil {
		t.Fatal("关闭时不应识别")
	}
	w.auto.Config.Enabled = true
	w.sweep(w.base.Add(time.Minute))
	row := w.autoRow(fpN(1))
	w.auto.Config.Enabled = false
	mal := w.incident("triaged", "malicious", "", "")
	w.alert(ls, 4, &mal, &row.ID, true)
	w.sweep(w.base.Add(2 * time.Minute))
	if w.autoRow(fpN(1)).RevokedAt == nil {
		t.Fatal("关闭时仍应按结论停用")
	}
}

// 同一把钥匙从两个地址登录：按地址分开判断，各自是单个地址，不合成网段把人手动的会话一起放过
func TestAutoSplitsByAddress(t *testing.T) {
	w := newWorld(t)
	script := session("root", "10.1.1.35", "publickey", fpN(7))
	human := session("root", "10.1.1.3", "publickey", fpN(7))
	w.logins(4, 6, script)
	inc := w.incident("false_positive", "benign", "lead", "")
	w.alert(script, 3, &inc, nil, false)
	w.logins(4, 1, human)
	w.sweep(w.base)
	got, _, err := Assess(w.ctx, w.db, w.auto.SQL, w.auto.Config, &w.group, w.base)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("应按地址分成两个身份，实际 %d", len(got))
	}
	for _, a := range got {
		if len(a.Addresses) != 1 || a.CIDR != a.Addresses[0]+"/32" {
			t.Fatalf("每个身份只应有一个地址并记 /32: %+v", a)
		}
	}
	rows := w.db.TrustedSource.Query().AllX(w.ctx)
	if len(rows) != 1 || rows[0].SourceCidr == nil || *rows[0].SourceCidr != "10.1.1.35/32" {
		t.Fatalf("只有脚本那个地址该被认出来: %+v", rows)
	}
}

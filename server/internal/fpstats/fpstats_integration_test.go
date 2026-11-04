//go:build integration

package fpstats

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/suppression"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

type fixture struct {
	ctx  context.Context
	db   *ent.Client
	host uuid.UUID
	t    *testing.T
}

// incident 造一个只含一条告警的事件：status / 结案人 / 来源按参数，事件体为 raw（空则不带事件体）
func (f *fixture) incident(rule, status, by, source, raw string) {
	now := time.Now()
	c := f.db.Incident.Create().SetStatus(status).SetGraph(json.RawMessage(`{}`)).SetCreatedAt(now.Add(-time.Hour))
	if by != "" {
		c.SetResolvedBy(by).SetResolvedAt(now).SetResolution("x")
	}
	if source != "" {
		c.SetResolutionSource(source)
	}
	inc := c.SaveX(f.ctx)
	a := f.db.Alert.Create().SetTs(now.Add(-time.Hour)).SetRuleID(rule).SetSeverity(2).SetAssetID(f.host).SetIncidentID(inc.ID)
	if raw != "" {
		ev := f.db.Event.Create().SetTs(now).SetClassUID(4003).SetSource("agent").SetAssetID(f.host).SetRaw(json.RawMessage(raw)).SaveX(f.ctx)
		a.SetEventID(ev.ID)
	}
	a.SaveX(f.ctx)
}

func (f *fixture) times(n int, rule, status, by, source, raw string) {
	for range n {
		f.incident(rule, status, by, source, raw)
	}
}

func (f *fixture) drafts(rule string) []*ent.Suppression {
	return f.db.Suppression.Query().Where(suppression.RuleIDEQ(rule), suppression.CreatedByEQ(CreatedBy)).AllX(f.ctx)
}

const dns = `{"query":{"hostname":"Updates.Example.com"},"process":{"file":{"path":"/usr/bin/apt"}}}`

func TestSweep(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	host := db.Asset.Create().SetHostname("pve1").SetGroupID(group.ID).SaveX(ctx)
	f := &fixture{ctx: ctx, db: db, host: host.ID, t: t}
	var submitted []uuid.UUID
	s := &Stats{DB: db, Window: 30 * 24 * time.Hour, MinCount: 5, MinRatio: 90, Days: 30, Cooldown: 30 * 24 * time.Hour,
		Proposed: func(id uuid.UUID) { submitted = append(submitted, id) }}

	// 达到阈值：5 次人工误报（含一次采纳 AI 研判），按域名 + 进程映像收窄
	f.times(4, "hit", "false_positive", "alice", "", dns)
	f.incident("hit", "false_positive", "bob", "ai_verdict", dns)
	// 不够数
	f.times(4, "few", "false_positive", "alice", "", dns)
	// 有一次判属实
	f.times(5, "real", "false_positive", "alice", "", dns)
	f.incident("real", "closed", "carol", "", dns)
	// 采纳 AI 结案建议与系统自动结案的不计入
	f.times(4, "aiprop", "false_positive", "alice", "", dns)
	f.times(3, "aiprop", "false_positive", "alice", "ai_proposal", dns)
	f.times(3, "aiprop", "false_positive", "system", "", dns)
	// 外部工单系统回写的误报也不计入
	f.times(4, "external", "false_positive", "alice", "", dns)
	f.times(3, "external", "false_positive", "ticket-bot", "external_integration", dns)
	// 误报率不够：5 / 6
	f.times(5, "ratio", "false_positive", "alice", "", dns)
	f.incident("ratio", "triaged", "", "", dns)
	// 事件体过了保留期的未结案命中不知道是哪个值，从严算进每个值
	f.times(8, "purged", "false_positive", "alice", "", dns)
	f.incident("purged", "open", "", "", "")
	// 实体分散：每次文件路径都不同、也没有进程映像 → 整条规则，明确标注
	for i := range 6 {
		f.incident("spread", "false_positive", "alice", "", `{"file":{"path":"/tmp/x`+string(rune('a'+i))+`"}}`)
	}
	// 高危及以上的规则不出草案
	f.times(5, "critical", "false_positive", "alice", "", dns)
	db.Alert.Update().Where(alert.RuleIDEQ("critical")).SetSeverity(5).ExecX(ctx)
	// shell 映像不算实体：命中全出自 bash 也只能给整条规则
	f.times(5, "shell", "false_positive", "alice", "", `{"process":{"file":{"path":"/usr/bin/bash"}}}`)
	// 平台合成规则实体分散时不给整条规则草案（等于关掉这台主机上的首次出现检测）
	for i := range 6 {
		f.incident("xdr:new-process", "false_positive", "alice", "", `{"file":{"path":"/opt/n`+string(rune('a'+i))+`"}}`)
	}
	// 已有生效的同范围抑制（更宽：只按域名）
	f.times(5, "covered", "false_positive", "alice", "", dns)
	db.Suppression.Create().SetRuleID("covered").SetAssetID(host.ID).SetStatus("active").
		SetConditions([]suppress.Condition{{Field: "query.hostname", Op: "equals", Value: "updates.example.com"}}).SaveX(ctx)

	// 临时构建目录每次带随机后缀（如 go test 的 /tmp/go-build<digits>/b001/*.test）：按前缀 contains 收窄
	for i := 0; i < 5; i++ {
		p := `/tmp/go-build1000` + string(rune('0'+i)) + `/b001/pkg.test`
		f.incident("gotest", "false_positive", "alice", "", `{"process":{"file":{"path":"`+p+`"},"cmd_line":"`+p+` -test.paniconexit0"}}`)
	}

	if n, err := s.Sweep(ctx, time.Now()); err != nil || n != 4 || len(submitted) != 4 {
		t.Fatalf("应生成 4 条草案，得到 %d %v", n, err)
	}
	for _, rule := range []string{"few", "real", "aiprop", "external", "ratio", "purged", "covered", "critical", "xdr:new-process"} {
		if d := f.drafts(rule); len(d) != 0 {
			t.Errorf("%s 不该生成草案：%+v", rule, d[0])
		}
	}

	hit := f.drafts("hit")
	if len(hit) != 1 {
		t.Fatalf("hit 应有 1 条草案，得到 %d", len(hit))
	}
	d := hit[0]
	want := []suppress.Condition{
		{Field: "query.hostname", Op: "equals", Value: "Updates.Example.com"},
		{Field: "process.file.path", Op: "equals", Value: "/usr/bin/apt"},
	}
	if d.Status != "proposed" || d.AssetID == nil || *d.AssetID != host.ID || !subset(want, d.Conditions) || len(d.Conditions) != 2 {
		t.Errorf("草案范围不对：%+v", d)
	}
	if d.ExpiresAt == nil || d.ExpiresAt.Sub(d.CreatedAt) != 30*24*time.Hour {
		t.Errorf("建议有效期应为 30 天：%v", d.ExpiresAt)
	}
	ev := d.Evidence
	if ev == nil || ev.Scope != "entity" || ev.FalsePositives != 5 || ev.RatioPercent != 100 || len(ev.Incidents) != 5 {
		t.Fatalf("依据不对：%+v", ev)
	}
	if d.Reason == nil || !strings.Contains(*d.Reason, "alice、bob") && !strings.Contains(*d.Reason, "bob、alice") {
		t.Errorf("理由应写明谁判的：%v", d.Reason)
	}

	spread := f.drafts("spread")
	if len(spread) != 1 || len(spread[0].Conditions) != 0 || spread[0].Evidence.Scope != "rule" ||
		!strings.Contains(*spread[0].Reason, "【整条规则】") {
		t.Errorf("实体分散时应给整条规则的草案并标注：%+v", spread)
	}

	if shell := f.drafts("shell"); len(shell) != 1 || len(shell[0].Conditions) != 0 {
		t.Errorf("通用 shell 映像不该当实体收窄：%+v", shell)
	}

	gotest := f.drafts("gotest")
	wantGoTest := []suppress.Condition{{Field: "process.file.path", Op: "contains", Value: "/tmp/go-build"}}
	if len(gotest) != 1 || !subset(wantGoTest, gotest[0].Conditions) || len(gotest[0].Conditions) != 1 {
		t.Errorf("临时构建目录应按前缀 contains 收窄：%+v", gotest)
	}

	// 草案未批准不生效
	store := suppress.New(db, time.Minute)
	store.Reload(ctx)
	var raw map[string]any
	_ = json.Unmarshal([]byte(dns), &raw)
	if store.Suppressed("hit", &host.ID, raw, time.Now()) || store.Suppressed("spread", &host.ID, map[string]any{}, time.Now()) {
		t.Fatal("待批准的草案不能生效")
	}

	// 已有待批草案不重复
	if n, err := s.Sweep(ctx, time.Now()); err != nil || n != 0 {
		t.Fatalf("重复统计不应再生成，得到 %d %v", n, err)
	}

	// 拒绝后冷却期内不再生成，过了冷却期再提
	db.Suppression.UpdateOne(d).SetStatus("rejected").SetReviewedAt(time.Now()).SetReviewedBy("admin").ExecX(ctx)
	if n, err := s.Sweep(ctx, time.Now()); err != nil || n != 0 {
		t.Fatalf("冷却期内不应再生成，得到 %d %v", n, err)
	}
	db.Suppression.UpdateOne(d).SetReviewedAt(time.Now().AddDate(0, 0, -31)).ExecX(ctx)
	if n, err := s.Sweep(ctx, time.Now()); err != nil || n != 1 {
		t.Fatalf("冷却期过后应重新生成，得到 %d %v", n, err)
	}

	// 门槛为 0 关闭
	if n, err := (&Stats{DB: db}).Sweep(ctx, time.Now()); err != nil || n != 0 {
		t.Fatalf("MinCount=0 应关闭，得到 %d %v", n, err)
	}
}

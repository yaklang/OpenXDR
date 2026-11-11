//go:build integration

package facts

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/fact"
	"openxdr/server/internal/testdb"
)

const royal = "SHA256:mtwVQQEIr75wGTFfVAuMn6y/LsfD5ULsqChRXqfXqJY"

func TestIntentOwnershipAndCoverage(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	host := db.Asset.Create().SetHostname("dd").SetGroupID(g.ID).SaveX(ctx)
	far := db.Asset.Create().SetHostname("far").SetGroupID(g.ID).SaveX(ctx)
	now := time.Now().UTC().Truncate(time.Second)
	kei, mallory := "integration:kei", "user:mallory"
	db.Fact.Create().SetKind("key").SetSubject(royal).SetHolder(kei).SetContent("凯伊运维钥匙").SetCreatedBy("admin").ExecX(ctx)
	db.Fact.Create().SetKind("channel").SetSubject("10.1.1.3/32").SetHolder(kei).SetContent("WireGuard 出口").SetCreatedBy("admin").ExecX(ctx)
	// 过期、停用、别的组的事实都不生效
	db.Fact.Create().SetKind("asset_role").SetAssetID(host.ID).SetGroupID(g.ID).SetContent("WAF").SetCreatedBy("admin").ExecX(ctx)
	db.Fact.Create().SetKind("decision").SetSubject("备份").SetGroupID(g.ID).SetContent("过期").SetCreatedBy("admin").SetExpiresAt(now.Add(-time.Hour)).ExecX(ctx)
	db.Fact.Create().SetKind("decision").SetSubject("备份").SetGroupID(g.ID).SetContent("停用").SetCreatedBy("admin").SetRetiredAt(now).ExecX(ctx)
	db.Fact.Create().SetKind("decision").SetSubject("别组").SetGroupID(other.ID).SetContent("别组").SetCreatedBy("admin").ExecX(ctx)
	all := func(uuid.UUID) bool { return true }
	req := IntentRequest{KeyFingerprint: royal, SourceAddr: "10.1.1.3", Assets: []uuid.UUID{host.ID}, Category: "deploy", StartsAt: now, Duration: time.Hour}

	if _, err := Register(ctx, db, mallory, "", req, all, nil, now); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("别人名下的通道不能登记：%v", err)
	}
	bad := req
	bad.SourceAddr = "10.1.1.161"
	if _, err := Register(ctx, db, kei, "", bad, all, nil, now); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("来源不在名下通道里不能登记：%v", err)
	}
	for name, mut := range map[string]func(*IntentRequest){
		"超时长":   func(r *IntentRequest) { r.Duration = 5 * time.Hour },
		"没主机":   func(r *IntentRequest) { r.Assets = nil },
		"未知用途":  func(r *IntentRequest) { r.Category = "anything" },
		"补登太晚":  func(r *IntentRequest) { r.StartsAt = now.Add(-3 * time.Hour) },
		"预登记将来": func(r *IntentRequest) { r.StartsAt = now.Add(time.Hour) },
	} {
		r := req
		mut(&r)
		var inv ErrInvalid
		if _, err := Register(ctx, db, kei, "", r, all, nil, now); !errors.As(err, &inv) {
			t.Errorf("%s 应被拒绝：%v", name, err)
		}
	}
	if _, err := Register(ctx, db, kei, "", req, func(uuid.UUID) bool { return false }, nil, now); !errors.Is(err, ErrForbiddenHost) {
		t.Fatalf("没有主机权限不能登记：%v", err)
	}
	var notes []string
	notify := func(_ context.Context, title, body, _ string) error { notes = append(notes, title+body); return nil }
	in, err := Register(ctx, db, kei, "10.1.1.3", req, all, notify, now)
	if err != nil || in.Late || len(notes) != 1 || !strings.Contains(notes[0], "dd") {
		t.Fatalf("登记应成功并推送：%v %+v %v", err, in, notes)
	}
	late := req
	late.StartsAt = now.Add(-90 * time.Minute)
	late.Duration = 3 * time.Hour
	if in, err := Register(ctx, db, kei, "", late, all, nil, now); err != nil || !in.Late {
		t.Fatalf("2 小时内可以补登并标记：%v", err)
	}

	logins := []Login{
		{KeyFP: royal, SrcIP: "10.1.1.3", AssetID: host.ID, At: now.Add(10 * time.Minute)},   // 覆盖
		{KeyFP: royal, SrcIP: "10.1.1.161", AssetID: host.ID, At: now.Add(10 * time.Minute)}, // 来源不对
		{KeyFP: royal, SrcIP: "10.1.1.3", AssetID: far.ID, At: now.Add(10 * time.Minute)},    // 主机不对
		{KeyFP: royal, SrcIP: "10.1.1.3", AssetID: host.ID, At: now.Add(2 * time.Hour)},      // 时间窗外
	}
	b, err := Lookup(ctx, db, []uuid.UUID{g.ID}, []uuid.UUID{host.ID, far.ID}, logins, now)
	if err != nil {
		t.Fatal(err)
	}
	matched := map[uuid.UUID]int{}
	for _, m := range b.Intents {
		if m.Login.SrcIP != "10.1.1.3" || m.Login.AssetID != host.ID {
			t.Fatalf("不该覆盖：%+v", m.Login)
		}
		matched[m.Intent.ID]++
	}
	if len(b.Intents) != 2 {
		t.Fatalf("正常登记与补登各覆盖一次：%d", len(b.Intents))
	}
	var kinds []string
	for _, f := range b.Facts {
		kinds = append(kinds, f.Kind+":"+f.Content)
	}
	if got := strings.Join(kinds, ","); got != "asset_role:WAF,channel:WireGuard 出口,key:凯伊运维钥匙" {
		t.Fatalf("只取有效、本组、相关的事实：%s", got)
	}
	text := Render(b, map[uuid.UUID]string{host.ID: "dd"})
	if !strings.Contains(text, "事后补登") || !strings.Contains(text, "部署发布") || strings.Contains(text, in.Note+"x") {
		t.Fatalf("渲染不对：%s", text)
	}
	if err := Cite(ctx, db, b, now); err != nil {
		t.Fatal(err)
	}
	if n := db.Fact.Query().Where(fact.CitedCountEQ(1)).CountX(ctx); n != 3 {
		t.Fatalf("被引用的三条事实各记一次：%d", n)
	}

	// 提前结束的意图到结束为止：正常那条结束后只剩补登的一条
	db.Intent.UpdateOneID(in.ID).SetEndedAt(now.Add(5 * time.Minute)).ExecX(ctx)
	b, _ = Lookup(ctx, db, []uuid.UUID{g.ID}, []uuid.UUID{host.ID}, logins[:1], now)
	if len(b.Intents) != 1 || !b.Intents[0].Intent.Late {
		t.Fatalf("提前结束的意图不再覆盖结束之后的登录：%+v", b.Intents)
	}
}

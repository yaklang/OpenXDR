//go:build integration

package aiconf

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

// 保存 → 读取 → 重置的整条链路：密钥加密落库、生效值与界面视图一致、重置回到环境变量
func TestSaveGetViewReset(t *testing.T) {
	ctx, db := testdb.New(t)
	s := &Store{DB: db, Vault: newVault(t), Default: env}

	if err := s.Save(ctx, Patch{
		BaseURL: ptr("https://console/v1/"), Model: ptr("console-model"), PTR: ptr(false), VTAlertMin: ptr(0),
		APIKey: ptr("sk-console-secret-9876"),
	}); err != nil {
		t.Fatal(err)
	}
	// 库里只有密文，没有明文
	row := db.Setting.GetX(ctx, settingKey)
	if strings.Contains(string(row.Value), "sk-console-secret-9876") {
		t.Fatalf("密钥明文落库: %s", row.Value)
	}

	got := s.Get(ctx)
	want := env
	want.BaseURL, want.Model, want.PTR, want.VTAlertMin, want.APIKey = "https://console/v1", "console-model", false, 0, "sk-console-secret-9876"
	if got != want {
		t.Fatalf("生效配置\n got  %+v\n want %+v", got, want)
	}

	v, err := s.View(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantSrc := map[string]string{"baseUrl": "console", "model": "console", "piModel": "env", "ptr": "console",
		"vtAlertMin": "console", "apiKey": "console", "vtKey": "env"}
	for k, src := range wantSrc {
		if v.Source[k] != src {
			t.Errorf("来源 %s = %q, want %q", k, v.Source[k], src)
		}
	}
	if !v.APIKeySet || v.APIKeyHint != "9876" || !v.VTKeySet || v.VTKeyHint != "0002" || !v.CanSaveSecrets {
		t.Errorf("视图密钥信息不对: %+v", v)
	}
	// 视图序列化出去不能带任何密钥明文
	out, _ := json.Marshal(v)
	if strings.Contains(string(out), "sk-console-secret") || strings.Contains(string(out), env.VTKey) {
		t.Fatalf("视图泄露密钥: %s", out)
	}

	// 清空 VT 密钥：环境变量有值也不再生效
	if err := s.Save(ctx, Patch{VTKey: ptr("")}); err != nil {
		t.Fatal(err)
	}
	if got := s.Get(ctx); got.VTKey != "" || got.APIKey != "sk-console-secret-9876" {
		t.Fatalf("清空 VT 密钥后: %+v", got)
	}
	if v, _ := s.View(ctx); v.VTKeySet || v.Source["vtKey"] != "console" {
		t.Fatalf("清空后视图: %+v", v)
	}

	// 重置回环境变量
	if err := s.Save(ctx, Patch{Reset: []string{"baseUrl", "model", "ptr", "vtAlertMin", "apiKey", "vtKey"}}); err != nil {
		t.Fatal(err)
	}
	if got := s.Get(ctx); got != env {
		t.Fatalf("全部重置后应等于环境变量: %+v", got)
	}
}

// 没配 HOST_CREDENTIAL_KEY：带密钥的修改整体拒绝，同一次提交里的其他项也不能落库；清空密钥与非密钥项照常可存
func TestSaveWithoutVault(t *testing.T) {
	ctx, db := testdb.New(t)
	s := &Store{DB: db, Default: env}

	err := s.Save(ctx, Patch{Model: ptr("sneaky"), APIKey: ptr("sk-plain")})
	if !errors.Is(err, ErrNoVault) {
		t.Fatalf("应返回 ErrNoVault: %v", err)
	}
	if n := db.Setting.Query().CountX(ctx); n != 0 {
		t.Fatalf("被拒绝的修改不应落库，现有 %d 行", n)
	}
	if err := s.Save(ctx, Patch{Model: ptr("ok-model"), APIKey: ptr("")}); err != nil {
		t.Fatalf("非密钥项与清空密钥应允许: %v", err)
	}
	got := s.Get(ctx)
	if got.Model != "ok-model" || got.APIKey != "" {
		t.Fatalf("保存后: %+v", got)
	}
	if v, _ := s.View(ctx); v.CanSaveSecrets {
		t.Fatal("没有钥匙时视图应标明不能保存密钥")
	}
}

// 不合法的修改在落库前拒绝
func TestSaveRejectsInvalid(t *testing.T) {
	ctx, db := testdb.New(t)
	s := &Store{DB: db, Vault: newVault(t), Default: env}
	if err := s.Save(ctx, Patch{BaseURL: ptr("javascript:alert(1)")}); err == nil {
		t.Fatal("非法地址应拒绝")
	}
	if n := db.Setting.Query().CountX(ctx); n != 0 {
		t.Fatalf("拒绝后不应落库，现有 %d 行", n)
	}
}

// 换了 HOST_CREDENTIAL_KEY 后，库里旧密文解不开，退回环境变量而不是空或乱码
func TestRotatedKeyFallsBackToEnv(t *testing.T) {
	ctx, db := testdb.New(t)
	old := &Store{DB: db, Vault: newVault(t), Default: env}
	if err := old.Save(ctx, Patch{APIKey: ptr("sk-old-vault-key")}); err != nil {
		t.Fatal(err)
	}
	rotated := &Store{DB: db, Vault: newVault(t), Default: env}
	if got := rotated.Get(ctx); got.APIKey != env.APIKey {
		t.Fatalf("新钥匙解不开旧密文时应退回环境变量: %q", got.APIKey)
	}
	// 界面要如实说明生效的是环境变量，提示也是环境变量密钥的末四位
	v, err := rotated.View(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.Source["apiKey"] != "env" || v.APIKeyHint != tail(env.APIKey) {
		t.Fatalf("解不开的密钥应显示为环境变量: source=%q hint=%q", v.Source["apiKey"], v.APIKeyHint)
	}
}

// 库里配置损坏按未保存处理，用环境变量
func TestCorruptSettingUsesEnv(t *testing.T) {
	ctx, db := testdb.New(t)
	db.Setting.Create().SetID(settingKey).SetValue(json.RawMessage(`"not an object"`)).ExecX(ctx)
	s := &Store{DB: db, Default: env}
	if got := s.Get(ctx); got != env {
		t.Fatalf("损坏配置应按未保存处理: %+v", got)
	}
}

// 缓存期内其他节点改库不会立刻生效；本节点 Save 立即作废缓存
func TestGetCacheAndSaveInvalidation(t *testing.T) {
	ctx, db := testdb.New(t)
	s := &Store{DB: db, Default: env}
	if got := s.Get(ctx); got.Model != env.Model {
		t.Fatalf("初始: %+v", got)
	}
	// 模拟另一个节点直接改库
	other := &Store{DB: db, Default: env}
	if err := other.Save(ctx, Patch{Model: ptr("from-other-node")}); err != nil {
		t.Fatal(err)
	}
	if got := s.Get(ctx); got.Model != env.Model {
		t.Fatalf("缓存期内应沿用旧值: %+v", got)
	}
	if err := s.Save(ctx, Patch{PiModel: ptr("local")}); err != nil {
		t.Fatal(err)
	}
	if got := s.Get(ctx); got.Model != "from-other-node" || got.PiModel != "local" {
		t.Fatalf("本节点保存后应立即读到最新: %+v", got)
	}
}

// 用量统计：Pi 会话消息与平台调用两路合并，按天、用途、模型聚合；只算助手消息、带 usage、在时间窗内的
func TestUsage(t *testing.T) {
	ctx, db := testdb.New(t)
	sqlDB, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Skip("缺时区数据:", err)
	}
	now := time.Now()
	day := now.In(loc).Format("2006-01-02")

	group := db.Group.Create().SetName("ops").SaveX(ctx)
	chat := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator("u").SetModel("pi-default").SetTitle("排查").SaveX(ctx)
	task := db.AgentSession.Create().SetKind("task").SetGroupID(group.ID).SetInitiator("system").SetModel("pi-task").SaveX(ctx)
	msg := func(s *ent.AgentSession, seq int, role, content string, at time.Time) {
		db.SessionMessage.Create().SetSessionID(s.ID).SetSeq(seq).SetRole(role).SetContent(json.RawMessage(content)).SetCreatedAt(at).ExecX(ctx)
	}
	msg(chat, 1, "user", `{"usage":{"input":999,"output":999}}`, now)
	msg(chat, 2, "assistant", `{"usage":{"input":100,"output":20,"cacheRead":50}}`, now)
	msg(chat, 3, "assistant", `{"model":"pi-override","usage":{"input":7,"output":3}}`, now)
	msg(chat, 4, "assistant", `{"text":"没有 usage 不算"}`, now)
	msg(chat, 5, "assistant", `{"usage":{"input":1000,"output":1000}}`, now.AddDate(0, 0, -40))
	msg(task, 1, "assistant", `{"usage":{"input":1,"output":1}}`, now)

	db.AIUsage.Create().SetFeature("triage").SetModel("m1").SetInput(10).SetOutput(2).SetTs(now).ExecX(ctx)
	db.AIUsage.Create().SetFeature("triage").SetModel("m1").SetInput(5).SetOutput(1).SetTs(now).ExecX(ctx)
	db.AIUsage.Create().SetFeature("triage").SetModel("m1").SetInput(500).SetOutput(500).SetTs(now.AddDate(0, 0, -40)).ExecX(ctx)

	// 记录器写一行，等同平台调用
	Recorder(db, "annotate")("m2", 4, 4)

	ov, err := Usage(ctx, sqlDB, 30, "Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]UsageRow{}
	for _, r := range ov.Rows {
		got[r.Feature+"/"+r.Model] = r
	}
	want := map[string]UsageRow{
		"chat/pi-default":  {Day: day, Feature: "chat", Model: "pi-default", Input: 100, Output: 20, CacheRead: 50, Calls: 1},
		"chat/pi-override": {Day: day, Feature: "chat", Model: "pi-override", Input: 7, Output: 3, Calls: 1},
		"task/pi-task":     {Day: day, Feature: "task", Model: "pi-task", Input: 1, Output: 1, Calls: 1},
		"triage/m1":        {Day: day, Feature: "triage", Model: "m1", Input: 15, Output: 3, Calls: 2},
		"annotate/m2":      {Day: day, Feature: "annotate", Model: "m2", Input: 4, Output: 4, Calls: 1},
	}
	if len(got) != len(want) {
		t.Fatalf("聚合行数 %d, want %d: %+v", len(got), len(want), ov.Rows)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s\n got  %+v\n want %+v", k, got[k], w)
		}
	}

	if len(ov.Top) != 2 {
		t.Fatalf("Top 会话数 %d: %+v", len(ov.Top), ov.Top)
	}
	top := ov.Top[0]
	if top.ID != chat.ID || top.Tokens != 130 || top.Calls != 2 || top.Title != "排查" || top.Group != "ops" || top.Kind != "chat" {
		t.Fatalf("用量最多的会话: %+v", top)
	}
	if ov.Top[1].ID != task.ID || ov.Top[1].Title != "" {
		t.Fatalf("第二名: %+v", ov.Top[1])
	}
}

func TestAbuseCHKeyLifecycle(t *testing.T) {
	ctx, db := testdb.New(t)
	s := &Store{DB: db, Vault: newVault(t), Default: Config{AbuseCHKey: "env-abuse-key-1234"}}
	key := "console-abuse-key-9876"
	if err := s.Save(ctx, Patch{AbuseCHKey: &key}); err != nil {
		t.Fatal(err)
	}
	if s.Get(ctx).AbuseCHKey != key {
		t.Fatal("控制台密钥未生效")
	}
	stored := db.Setting.GetX(ctx, settingKey)
	if strings.Contains(string(stored.Value), key) {
		t.Fatal("密钥不能明文落库")
	}
	view, err := s.View(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !view.AbuseCHKeySet || view.AbuseCHKeyHint != "9876" || view.Source["abuseCHKey"] != "console" {
		t.Fatalf("视图状态不正确: %+v", view)
	}
	body, _ := json.Marshal(view)
	if strings.Contains(string(body), key) {
		t.Fatal("接口视图不能回显密钥")
	}
	if err := s.Save(ctx, Patch{AbuseCHKey: ptr("")}); err != nil {
		t.Fatal(err)
	}
	if s.Get(ctx).AbuseCHKey != "" {
		t.Fatal("清空密钥后不能偷偷退回环境变量")
	}
	if err := s.Save(ctx, Patch{Reset: []string{"abuseCHKey"}}); err != nil {
		t.Fatal(err)
	}
	if s.Get(ctx).AbuseCHKey != s.Default.AbuseCHKey {
		t.Fatal("重置应恢复环境变量")
	}
	s.Vault = nil
	if err := s.Save(ctx, Patch{AbuseCHKey: &key}); !errors.Is(err, ErrNoVault) {
		t.Fatal("无加密钥匙时必须拒绝保存密钥")
	}
	if s.Get(ctx).AbuseCHKey != s.Default.AbuseCHKey {
		t.Fatal("被拒绝的保存不能改变原配置")
	}
}

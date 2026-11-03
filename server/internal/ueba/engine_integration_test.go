//go:build integration

package ueba

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

func procEvent(t *testing.T, ctx context.Context, c *ent.Client, assetID uuid.UUID, exe string, ts time.Time) *ent.Event {
	t.Helper()
	raw := fmt.Sprintf(`{"process":{"pid":1,"name":"x","file":{"path":"%s"}}}`, exe)
	ev, err := c.Event.Create().
		SetTs(ts).SetClassUID(classProcess).SetSource("agent").
		SetAssetID(assetID).SetRaw(json.RawMessage(raw)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func newEngine(c *ent.Client) *Engine {
	return &Engine{
		DB: c, Suppress: suppress.New(c, time.Hour),
		LearningPeriod: 7 * 24 * time.Hour, Interval: time.Second,
	}
}

// 学习期内只建基线不告警；学习期满后新出现的可执行文件才升为告警；
// 已入基线的组合永不重复告警。
func TestFirstSeenLifecycle(t *testing.T) {
	ctx, client := testdb.New(t)
	asset, err := client.Asset.Create().SetHostname("h1").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(client)

	// 阶段一：首次观测，全部进基线，零告警
	now := time.Now()
	procEvent(t, ctx, client, asset.ID, "/usr/bin/bash", now.Add(-8*24*time.Hour))
	procEvent(t, ctx, client, asset.ID, "/usr/bin/sshd", now.Add(-8*24*time.Hour))
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := client.ProcessBaseline.Query().Count(ctx); n != 2 {
		t.Fatalf("应建 2 条基线，实际 %d", n)
	}
	if n, _ := client.Alert.Query().Count(ctx); n != 0 {
		t.Fatalf("学习期内不应告警，实际 %d 条", n)
	}

	// 阶段二：8 天后（学习期满）新程序出现 → low 告警；老程序再跑不告警
	procEvent(t, ctx, client, asset.ID, "/tmp/miner", now)
	procEvent(t, ctx, client, asset.ID, "/usr/bin/bash", now)
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	alerts, err := client.Alert.Query().All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].RuleID != sigma.RuleNewProcess {
		t.Fatalf("应产出 1 条首次出现告警，实际 %+v", alerts)
	}
	if alerts[0].Severity != 2 {
		t.Errorf("首次出现应为 low(2)，实际 %d", alerts[0].Severity)
	}

	// 阶段三：同一程序再次出现，基线已有，不再告警
	procEvent(t, ctx, client, asset.ID, "/tmp/miner", now.Add(time.Minute))
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := client.Alert.Query().Where(alert.RuleIDEQ(sigma.RuleNewProcess)).Count(ctx); n != 1 {
		t.Errorf("重复出现不应再告警，实际 %d 条", n)
	}
	if n, _ := client.ProcessBaseline.Query().Count(ctx); n != 3 {
		t.Errorf("基线应为 3 条，实际 %d", n)
	}
}

// 新接入的资产从零开始学习：即使别的资产已过学习期，它也不受连坐。
func TestLearningIsPerAsset(t *testing.T) {
	ctx, client := testdb.New(t)
	old, _ := client.Asset.Create().SetHostname("old").Save(ctx)
	fresh, _ := client.Asset.Create().SetHostname("fresh").Save(ctx)
	e := newEngine(client)

	now := time.Now()
	// old 资产 8 天前已有基线
	procEvent(t, ctx, client, old.ID, "/usr/bin/bash", now.Add(-8*24*time.Hour))
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	// fresh 资产今天才接入，跑了一个程序
	procEvent(t, ctx, client, fresh.ID, "/opt/app/server", now)
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := client.Alert.Query().Count(ctx); n != 0 {
		t.Errorf("新资产在学习期内不应告警，实际 %d 条", n)
	}
}

// merged-usr 下 /bin/x 与 /usr/bin/x 是同一文件：旧基线里存的写法也要认，不重复告警。
func TestUsrMergedPathsShareBaseline(t *testing.T) {
	ctx, client := testdb.New(t)
	asset, _ := client.Asset.Create().SetHostname("h1").Save(ctx)
	e := newEngine(client)

	now := time.Now()
	// 旧版本写入的未归一化基线
	if err := client.ProcessBaseline.Create().SetAssetID(asset.ID).
		SetExePath("/bin/rm").SetFirstSeen(now.Add(-8 * 24 * time.Hour)).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	procEvent(t, ctx, client, asset.ID, "/usr/bin/rm", now)
	procEvent(t, ctx, client, asset.ID, "/bin/rm", now)
	procEvent(t, ctx, client, asset.ID, "/bin/awk", now)
	procEvent(t, ctx, client, asset.ID, "/usr/bin/awk", now)
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	alerts, _ := client.Alert.Query().All(ctx)
	if len(alerts) != 1 {
		t.Fatalf("只有 awk 是首次出现，应 1 条告警，实际 %d", len(alerts))
	}
	if n, _ := client.ProcessBaseline.Query().Count(ctx); n != 2 {
		t.Errorf("基线应为旧 /bin/rm 与新 /usr/bin/awk 两条，实际 %d", n)
	}
}

// 可信自动化来源的会话里跑出的新程序：照常学进基线，告警挂到来源上（不进关联）
func TestFirstSeenFromTrustedSource(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	g := client.Group.Create().SetName("ops").SaveX(ctx)
	asset := client.Asset.Create().SetHostname("h1").SetGroupID(g.ID).SaveX(ctx)
	const fp = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
	src := client.TrustedSource.Create().SetGroupID(g.ID).SetName("Termix").SetCreatedBy("lead").
		SetKeyFingerprint(fp).SetExpiresAt(time.Now().Add(24 * time.Hour)).SaveX(ctx)
	e := newEngine(client)
	e.SQL = db

	now := time.Now()
	procEvent(t, ctx, client, asset.ID, "/usr/bin/bash", now.Add(-8*24*time.Hour))
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	client.Event.Create().SetTs(now).SetClassUID(classProcess).SetSource("agent").SetAssetID(asset.ID).
		SetRaw(json.RawMessage(`{"process":{"pid":2,"name":"probe","file":{"path":"/tmp/probe"}},
"login_session":{"uid":"9","user":"root","src_ip":"10.1.1.35","key_fp":"` + fp + `","auth_method":"publickey"}}`)).SaveX(ctx)
	procEvent(t, ctx, client, asset.ID, "/tmp/other", now)
	// 容器健康检查里跑出的新程序同理：标注健康检查，不进关联
	client.Event.Create().SetTs(now).SetClassUID(classProcess).SetSource("agent").SetAssetID(asset.ID).
		SetRaw(json.RawMessage(`{"process":{"pid":3,"name":"nc","file":{"path":"/usr/bin/nc"}},
"container":{"runtime":"docker","uid":"4f1c2a3b5d6e","healthcheck":true}}`)).SaveX(ctx)
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	alerts := client.Alert.Query().AllX(ctx)
	var trusted, plain, healthcheck int
	for _, a := range alerts {
		switch {
		case a.AutomationID != nil && *a.AutomationID == src.ID:
			trusted++
		case a.Healthcheck:
			healthcheck++
		case a.AutomationID == nil:
			plain++
		}
	}
	if len(alerts) != 3 || trusted != 1 || plain != 1 || healthcheck != 1 {
		t.Fatalf("可信会话的一条挂到来源上，健康检查的一条标注，另一条照常: %+v", alerts)
	}
	if n := client.ProcessBaseline.Query().CountX(ctx); n != 4 {
		t.Fatalf("可信会话的新程序也要学进基线，实际 %d 条", n)
	}
}

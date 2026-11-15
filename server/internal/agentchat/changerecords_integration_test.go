//go:build integration

package agentchat

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/changerecords"
	"openxdr/server/internal/testdb"
)

func TestIncidentSubjectIncludesCorroboratingChanges(t *testing.T) {
	ctx, db := testdb.New(t)
	grp := db.Group.Create().SetName("ops").SaveX(ctx)
	host := db.Asset.Create().SetHostname("gateway").SetIPAddrs([]string{"10.1.1.100"}).SetGroupID(grp.ID).SaveX(ctx)

	now := time.Now().UTC().Truncate(time.Second)
	src := db.ChangeSource.Create().SetProvider("github").SetRepo("ZacharyZcR/RoyalSecurity-Network").SetEnabled(true).SaveX(ctx)
	rec := db.ChangeRecord.Create().
		SetSourceID(src.ID).
		SetRepo(src.Repo).
		SetSha("8c168720abcdef0123456789abcdef0123456789").
		SetCommittedAt(now.Add(-20 * time.Minute)).
		SetAuthor("ZacharyZcR").
		SetTitle("下线 dl 站点，回收 node34-36 的隧道钥与 WireGuard peer").
		SetFiles([]string{"configs/gateway/Caddyfile"}).
		SetFileCount(1).
		SaveX(ctx)
	db.ChangeRecordAsset.Create().
		SetChangeRecordID(rec.ID).
		SetAssetID(host.ID).
		SetCommittedAt(rec.CommittedAt).
		SetClues([]string{"host:gateway"}).
		SaveX(ctx)

	title := "gateway 异常命令"
	inc := db.Incident.Create().SetTitle(title).SetStatus("open").SetCreatedAt(now).SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(host.ID).SetRuleID("test-rule").SetSeverity(3).SetCount(1).SetTs(now).SaveX(ctx)

	svc := &Service{DB: db}
	sub, err := svc.incidentSubject(ctx, inc.ID, grp.ID, map[uuid.UUID]string{host.ID: host.Hostname})
	if err != nil {
		t.Fatal(err)
	}
	note, _ := sub["corroborating_changes_note"].(string)
	if !strings.Contains(note, changerecords.SourceDisclaimer) {
		t.Fatalf("缺少非权威来源说明: %+v", sub)
	}
	items, ok := sub["corroborating_changes"].([]changerecords.PromptItem)
	if !ok || len(items) != 1 || items[0].ShortSHA != "8c168720" || items[0].FileCount != 1 {
		t.Fatalf("incidentSubject 未携带预期变更记录: %+v", sub)
	}
}

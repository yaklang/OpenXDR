//go:build integration

package triage

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/testdb"
)

func TestProcessBaselineAssetScopeAndLegacyPath(t *testing.T) {
	ctx, db := testdb.New(t)
	a, b := uuid.New(), uuid.New()
	db.Asset.Create().SetID(a).SetHostname("baseline-a").SaveX(ctx)
	db.Asset.Create().SetID(b).SetHostname("baseline-b").SaveX(ctx)
	e := scopedToolEngine(ctx, db, a)
	first := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	row := db.ProcessBaseline.Create().SetAssetID(a).SetExePath("/bin/tool").SetFirstSeen(first).SaveX(ctx)
	db.ProcessBaseline.Create().SetAssetID(a).SetExePath("/usr/bin/tool").SetFirstSeen(first.Add(time.Hour)).SaveX(ctx)
	for _, tc := range []struct {
		asset uuid.UUID
		path  string
		found bool
	}{
		{a, "/usr/bin/tool", true}, {a, "/bin/tool", true}, {b, "/bin/tool", false}, {a, "/bin/other", false},
	} {
		result, err := e.toolProcessBaseline(ctx, fmt.Sprintf(`{"asset_id":%q,"exe_path":%q}`, tc.asset, tc.path))
		if err != nil {
			t.Fatal(err)
		}
		facts := result.(map[string]any)
		if tc.found {
			if facts["baseline_id"] != row.ID.String() || facts["baseline_first_recorded_at"] != first.Format(time.RFC3339Nano) {
				t.Fatal(facts)
			}
		} else if facts["baseline_status"] != "unknown" || facts["baseline_first_recorded_at"] != nil {
			t.Fatal(facts)
		}
	}
	db.Close()
	if _, err := e.toolProcessBaseline(ctx, fmt.Sprintf(`{"asset_id":%q,"exe_path":"/bin/tool"}`, a)); err == nil {
		t.Fatal("断库不能作为基线未命中")
	}
}

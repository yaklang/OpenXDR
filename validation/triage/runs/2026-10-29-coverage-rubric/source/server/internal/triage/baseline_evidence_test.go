package triage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/ueba"
)

func TestBaselineEvidenceIsNotInstallationTime(t *testing.T) {
	assetID := uuid.New()
	for _, row := range []*ent.ProcessBaseline{nil, {ID: uuid.New(), AssetID: assetID, ExePath: "/usr/bin/tool", FirstSeen: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)}} {
		result := baselineEvidence(assetID, "/bin/tool", row)
		raw, _ := json.Marshal(result)
		messages := []Message{{Role: "tool", Content: string(raw)}}
		for _, field := range []string{"baseline_first_recorded_at", "installed_at", "first_execution_at"} {
			claim := `,"evidence_claims":[{"evidence_id":"query-1","field":"` + field + `","value":"2020-01-01T00:00:00Z"}]}`
			_, err := bindEvidence(Message{Content: strings.TrimSuffix(validVerdict, "}") + claim}, messages)
			valid := row != nil && field == "baseline_first_recorded_at"
			if (err == nil) != valid {
				t.Fatalf("field=%s row=%v err=%v", field, row, err)
			}
		}
		if row == nil && result["baseline_status"] != "unknown" {
			t.Fatal(result)
		}
	}
}

func TestBaselinePathsAndInput(t *testing.T) {
	paths := ueba.BaselinePaths("/bin/tool")
	if len(paths) != 2 || paths[0] != "/usr/bin/tool" || paths[1] != "/bin/tool" {
		t.Fatal(paths)
	}
	for _, path := range []string{"/bin/tool", `C:\Windows\tool.exe`, `\\host\share\tool.exe`} {
		if !absoluteExecutablePath(path) {
			t.Fatal(path)
		}
	}
	e := Engine{}
	for _, path := range []string{"tool", "", `C:tool.exe`, "/bin/\x00tool"} {
		args, _ := json.Marshal(map[string]string{"asset_id": uuid.NewString(), "exe_path": path})
		if _, err := e.toolProcessBaseline(context.Background(), string(args)); err == nil {
			t.Fatal(path)
		}
	}
}

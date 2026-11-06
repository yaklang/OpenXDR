package findings

import (
	"testing"
	"time"
)

func TestBlockedDelayGrowsDespiteEvidenceUpdates(t *testing.T) {
	for _, blocker := range []string{"permission", "external_dependency"} {
		t.Run(blocker, func(t *testing.T) {
			w := Work{Blocker: blocker}
			for round, hours := range []int{6, 12, 24, 48, 72, 72} {
				evidenceAt := time.Now().Add(time.Duration(round) * time.Hour)
				w.EvidenceAt = &evidenceAt
				want := time.Duration(hours) * time.Hour
				if blocker == "external_dependency" {
					want = min(want, 12*time.Hour)
				}
				before := w.BlockedRounds
				if got := BlockedDelay(&w, false); got != want {
					t.Fatal(got, want)
				}
				if w.BlockedRounds != before {
					t.Fatal("保存计划不应累计轮次")
				}
				if got := BlockedDelay(&w, true); got != want {
					t.Fatal(got, want)
				}
			}
		})
	}
}
func TestBlockedDelayResets(t *testing.T) {
	for _, change := range []string{"clear", "change"} {
		t.Run(change, func(t *testing.T) {
			w := Work{Blocker: "permission"}
			for range 4 {
				BlockedDelay(&w, true)
			}
			switch change {
			case "clear":
				w.Blocker = ""
			case "change":
				w.Blocker = "unsupported"
			}
			want := 6 * time.Hour
			if change == "clear" {
				want = 0
			}
			if got := BlockedDelay(&w, false); got != want || w.BlockedRounds != 0 {
				t.Fatal(got, w.BlockedRounds)
			}
		})
	}
}

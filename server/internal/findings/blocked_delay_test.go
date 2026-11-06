package findings

import (
	"testing"
	"time"
)

func TestBlockedDelaySequence(t *testing.T) {
	for _, blocker := range []string{"permission", "external_dependency"} {
		t.Run(blocker, func(t *testing.T) {
			w := Work{Blocker: blocker}
			for _, hours := range []int{6, 12, 24, 48, 72, 72} {
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
	now := time.Now()
	for _, change := range []string{"clear", "change", "evidence", "first_evidence"} {
		t.Run(change, func(t *testing.T) {
			w := Work{Blocker: "permission"}
			if change != "first_evidence" {
				w.EvidenceAt = &now
			}
			for range 4 {
				BlockedDelay(&w, true)
			}
			switch change {
			case "clear":
				w.Blocker = ""
			case "change":
				w.Blocker = "unsupported"
			default:
				later := now.Add(time.Minute)
				w.EvidenceAt = &later
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

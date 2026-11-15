package findings

import (
	"testing"
	"time"
)

func TestRepairSpentRecoversAfterWindow(t *testing.T) {
	now := time.Now()
	recent, old := now.Add(-time.Hour), now.Add(-RepairBudgetWindow-time.Hour)
	for name, c := range map[string]struct {
		w    Work
		want int
	}{
		"恢复期内照常计数":       {Work{RepairAttempts: 3, RepairAt: &recent}, 3},
		"过了恢复期不再计入":      {Work{RepairAttempts: 3, RepairAt: &old}, 0},
		"没记预留时间的旧计数按已恢复": {Work{RepairAttempts: 3}, 0},
	} {
		if got := c.w.RepairSpent(now); got != c.want {
			t.Errorf("%s：得到 %d，应为 %d", name, got, c.want)
		}
	}
}

package schedule

import (
	"strings"
	"testing"
)

func TestFollowupRequiresRuntimeCapability(t *testing.T) {
	valid := "id: ops-followup\nruntime_capability: finding_work_v1\nschedule: '*/30 * * * *'\nprompt: followup\n"
	if _, err := parseSpec([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(valid, "runtime_capability: finding_work_v1\n", "", 1), strings.Replace(valid, "finding_work_v1", "unknown", 1), strings.Replace(valid, "id: ops-followup", "id: unrelated", 1)} {
		if _, err := parseSpec([]byte(bad)); err == nil {
			t.Fatal("错误运行时任务仍被接受")
		}
	}
}

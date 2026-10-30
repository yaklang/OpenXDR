package eventai

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"openxdr/server/ent"
)

func TestRemoteIP(t *testing.T) {
	for tuple, want := range map[string]string{
		"tcp:10.0.0.1:40000>203.0.113.9:443": "203.0.113.9",
		"udp:fe80::1:53>2001:db8::5:53":      "2001:db8::5",
		"garbage":                            "",
		"tcp:1.1.1.1:1>":                     "",
	} {
		if got := remoteIP(tuple); got != want {
			t.Errorf("%s → %q，应为 %q", tuple, got, want)
		}
	}
}

func TestParse(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	groups := []Group{{Relation: "ancestor", Events: []*ent.Event{{ID: a}}}, {Relation: "nearby", Events: []*ent.Event{{ID: b}}}}
	answer := "分析如下：{\"verdict\":\"suspicious\",\"title\":\"bash 反弹 shell\",\"summary\":\"由 sshd 拉起的 bash 连向外部 4444\"," +
		"\"points\":[\"连接远端 4444\",\"\",\"父进程 sshd\"],\"related\":[{\"id\":\"" + a.String() + "\",\"why\":\"父进程\"},{\"id\":\"" + uuid.NewString() + "\",\"why\":\"编的\"},{\"id\":\"" + a.String() + "\",\"why\":\"重复\"}],\"next\":[\"查 sshd 登录来源\"]}"
	x, err := Parse(answer, groups)
	if err != nil || x.Verdict != "suspicious" || len(x.Points) != 2 || len(x.Related) != 1 || x.Related[0].ID != a || len(x.Next) != 1 {
		t.Fatalf("%+v %v", x, err)
	}
	if x, _ := Parse(`{"verdict":"evil","title":"x"}`, nil); x.Verdict != "unknown" {
		t.Fatalf("未知判定应归为 unknown: %q", x.Verdict)
	}
	for _, bad := range []string{"没有 JSON", `{"verdict":"benign"}`, `{bad json}`} {
		if _, err := Parse(bad, groups); err == nil {
			t.Errorf("应拒绝: %s", bad)
		}
	}
}

func TestMessagesTruncates(t *testing.T) {
	big := &ent.Event{ID: uuid.New(), Raw: []byte(`{"x":"` + strings.Repeat("a", 9000) + `"}`)}
	cand := &ent.Event{ID: uuid.New(), Raw: []byte(`{"y":"` + strings.Repeat("b", 2000) + `"}`)}
	system, user := Messages(big, map[string]any{"hostname": "web"}, []Group{{Relation: "nearby", Events: []*ent.Event{cand}}}, "en", HotOnlyCoverage)
	if !strings.Contains(system, "English") || len(user) > 6000 || !strings.Contains(user, cand.ID.String()) || !strings.Contains(user, `"relation":"nearby"`) {
		t.Fatalf("长度 %d", len(user))
	}
	// 候选只查热表是恒真事实：覆盖说明固定追加在数据之后，不按目标冷热分支
	if !strings.Contains(user, CandidatesHotOnlyNote) {
		t.Fatalf("解读输入应包含候选来源的固定覆盖说明: %q", user)
	}
	if _, user := Messages(big, nil, nil, "", Coverage{CandidatesHotOnly: false}); strings.Contains(user, CandidatesHotOnlyNote) {
		t.Fatalf("调用方未声明候选只查热表时不应出现该说明: %q", user)
	}
}

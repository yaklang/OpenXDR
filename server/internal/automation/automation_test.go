package automation

import (
	"testing"

	"github.com/google/uuid"

	"openxdr/server/internal/sigma"
)

const fp = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"

func TestSession(t *testing.T) {
	raw := map[string]any{"login_session": map[string]any{
		"uid": "12", "user": "root", "src_ip": "10.1.1.35", "key_fp": fp, "auth_method": "publickey",
	}}
	l, ok := Session(raw)
	if !ok || l.User != "root" || l.SrcIP != "10.1.1.35" || l.KeyFP != fp || l.Method != "publickey" {
		t.Fatalf("解析错误: %+v %v", l, ok)
	}
	if _, ok := Session(map[string]any{}); ok {
		t.Fatal("没有登录归属不应认出")
	}
	if _, ok := Session(map[string]any{"login_session": "x"}); ok {
		t.Fatal("类型不对不应认出")
	}
	if _, ok := Session(map[string]any{"login_session": map[string]any{"user": "root"}}); ok {
		t.Fatal("只有用户名不够认")
	}
}

func TestHealthcheck(t *testing.T) {
	mk := func(c any) map[string]any { return map[string]any{"container": c} }
	if !Healthcheck(mk(map[string]any{"runtime": "docker", "uid": "4f1c2a3b5d6e", "healthcheck": true})) {
		t.Fatal("docker 健康检查应认出")
	}
	for _, raw := range []map[string]any{
		{},
		mk("x"),
		mk(map[string]any{"runtime": "docker", "uid": "4f1c2a3b5d6e"}),
		mk(map[string]any{"runtime": "docker", "healthcheck": "true"}),
		mk(map[string]any{"runtime": "lxc", "healthcheck": true}),
	} {
		if Healthcheck(raw) {
			t.Fatalf("不该认出: %v", raw)
		}
	}
}

func TestWatch(t *testing.T) {
	rules := []*sigma.Rule{
		{ID: "recon", Tactics: []string{"discovery"}, Techniques: []string{"T1082"}},
		{ID: "revshell", Severity: 5, Tactics: []string{"execution", "command-and-control"}, Techniques: []string{"T1059.004"}},
		{ID: "dump", Tactics: []string{"credential-access"}, Techniques: []string{"T1003.008"}},
		{ID: "logclear", Tactics: []string{"defense-evasion"}, Techniques: []string{"T1070.002"}},
		{ID: "auditoff", Tactics: []string{"defense-evasion"}, Techniques: []string{"T1562.012"}},
		{ID: "wipe", Tactics: []string{"impact"}},
		{ID: "lookalike", Techniques: []string{"T10700"}},
		{ID: "rootca-low", Severity: 2, Tactics: []string{"defense-impairment"}, Techniques: []string{"T1553.004"}},
		{ID: "chmod-med", Severity: 3, Tactics: []string{"defense-impairment"}, Techniques: []string{"T1222.002"}},
		{ID: "sed-med", Severity: 3, Tactics: []string{"impact"}, Techniques: []string{"T1565.001"}},
		{ID: "timestomp-med", Severity: 3, Tactics: []string{"defense-evasion"}, Techniques: []string{"T1070.006"}},
		{ID: "histdel-high", Severity: 4, Tactics: []string{"impact"}, Techniques: []string{"T1565.001"}},
		{ID: "ufw-med", Severity: 3, Tactics: []string{"defense-impairment"}, Techniques: []string{"T1686"}},
		{ID: "dump-low", Severity: 2, Tactics: []string{"credential-access"}, Techniques: []string{"T1003.008"}},
		{ID: "auditoff-low", Severity: 2, Tactics: []string{"defense-evasion"}, Techniques: []string{"T1562.012"}},
		{ID: "wipe-low", Severity: 2, Tactics: []string{"impact"}, Techniques: []string{"T1485"}},
		{ID: "chmod-plus-auditoff", Severity: 2, Tactics: []string{"defense-impairment"}, Techniques: []string{"T1222.002", "T1562.001"}},
	}
	cases := map[string]bool{
		"recon": false, "revshell": false, "lookalike": false,
		"rootca-low": false, "chmod-med": false, "sed-med": false, "timestomp-med": false,
		"dump": true, "logclear": true, "auditoff": true, "wipe": true,
		"histdel-high": true, "ufw-med": true,
		"dump-low": true, "auditoff-low": true, "wipe-low": true, "chmod-plus-auditoff": true,
		"intel:ip:1.2.3.4":           true,
		"不在命中列表里":                    true,
		sigma.RuleLateralSpray:       true,
		sigma.RuleControlPlaneChange: true,
		sigma.RuleCoreAgentSilent:    true,
		sigma.RuleAuditTamper:        true,
	}
	for id, want := range cases {
		if got := Watch(id, rules); got != want {
			t.Errorf("%s: Watch=%v，期望 %v", id, got, want)
		}
	}
	// 确知的高危例外：查不到的规则不兜底
	known := map[string]bool{
		"recon": false, "rootca-low": false, "chmod-med": false, "sed-med": false,
		"dump": true, "histdel-high": true, "ufw-med": true,
		"intel:ip:1.2.3.4": true, "不在命中列表里": false,
		sigma.RuleLateralSpray: true, sigma.RuleBruteforceSuccess: true,
		sigma.RuleControlPlaneChange: true, sigma.RuleCoreAgentSilent: true, sigma.RuleAuditTamper: true,
		sigma.RuleNewProcess: false,
	}
	for id, want := range known {
		if got := KnownCritical(id, rules); got != want {
			t.Errorf("%s: KnownCritical=%v，期望 %v", id, got, want)
		}
	}
}

func TestNormalize(t *testing.T) {
	ok := []struct {
		in   Criteria
		cidr string
	}{
		{Criteria{KeyFingerprint: fp}, ""},
		{Criteria{KeyFingerprint: " " + fp + " ", SourceCIDR: "10.1.1.35", LoginUser: "root"}, "10.1.1.35/32"},
		{Criteria{SourceCIDR: "10.1.1.77/24"}, "10.1.1.0/24"},
		{Criteria{SourceCIDR: "::ffff:10.1.1.35"}, "10.1.1.35/32"},
		{Criteria{SourceCIDR: "fd00::1/64"}, "fd00::/64"},
		{Criteria{KeyFingerprint: fp, SourceCIDR: "10.0.0.0/8"}, "10.0.0.0/8"},
	}
	for _, c := range ok {
		got, err := c.in.Normalize()
		if err != nil {
			t.Fatalf("%+v: %v", c.in, err)
		}
		if got.SourceCIDR != c.cidr || (c.in.KeyFingerprint != "" && got.KeyFingerprint != fp) {
			t.Fatalf("%+v 规范化成 %+v", c.in, got)
		}
	}
	bad := []Criteria{
		{},
		{LoginUser: "root"},
		{KeyFingerprint: "SHA256:short"},
		{KeyFingerprint: "MD5:aa:bb"},
		{SourceCIDR: "not-an-ip"},
		{SourceCIDR: "10.0.0.0/8"},
		{SourceCIDR: "0.0.0.0/0"},
		{SourceCIDR: "fd00::/48"},
		{KeyFingerprint: fp, LoginUser: "a b"},
	}
	for _, c := range bad {
		if _, err := c.Normalize(); err == nil {
			t.Fatalf("%+v 应被拒绝", c)
		}
	}
}

func TestCommonPrefix(t *testing.T) {
	cases := []struct {
		addrs []string
		want  string
	}{
		{[]string{"10.1.1.35"}, "10.1.1.35/32"},
		{[]string{"10.1.1.3", "10.1.1.35"}, "10.1.1.0/24"},
		{[]string{"10.1.1.3", "10.1.2.3"}, ""},
		{[]string{"fd00::1"}, "fd00::1/128"},
		{[]string{"fd00::1", "fd00::2"}, "fd00::/64"},
		{[]string{"::ffff:10.1.1.9"}, "10.1.1.9/32"},
		{[]string{"not-an-ip"}, ""},
	}
	for _, c := range cases {
		if got := commonPrefix(c.addrs); got != c.want {
			t.Errorf("%v: %q，期望 %q", c.addrs, got, c.want)
		}
	}
}

func TestAllInternal(t *testing.T) {
	cases := []struct {
		addrs []string
		want  bool
	}{
		{[]string{"10.1.1.3", "192.168.1.2"}, true},
		{[]string{"100.100.1.1"}, true},
		{[]string{"fd00::1"}, true},
		{[]string{"8.8.8.8"}, false},
		{[]string{"2001:db8::1"}, false},
		{[]string{"10.1.1.3", "8.8.8.8"}, false},
		{nil, false},
	}
	for _, c := range cases {
		if got := allInternal(c.addrs); got != c.want {
			t.Errorf("%v: %v，期望 %v", c.addrs, got, c.want)
		}
	}
}

func TestReason(t *testing.T) {
	c := DefaultConfig()
	inc := uuid.New()
	ok := Assessment{KeyFP: fp, Addresses: []string{"10.1.1.35"}, CIDR: "10.1.1.35/32", Days: 3, Logins: 20, Alerts: 1, HumanBenign: 1}
	cases := []struct {
		edit func(*Assessment)
		want string
	}{
		{func(*Assessment) {}, ReasonEligible},
		{func(a *Assessment) { a.KeyFP = "" }, ReasonNoKey},
		{func(a *Assessment) { a.Addresses = []string{"1.1.1.1"} }, ReasonPublic},
		{func(a *Assessment) { a.CIDR = "" }, ReasonScattered},
		{func(a *Assessment) { a.Flagged = &inc }, ReasonFlagged},
		{func(a *Assessment) { a.Days = 2 }, ReasonIrregular},
		{func(a *Assessment) { a.Logins = 19 }, ReasonIrregular},
		{func(a *Assessment) { a.Alerts, a.HumanBenign = 0, 0 }, ReasonQuiet},
		{func(a *Assessment) { a.Pending = 1 }, ReasonPending},
		{func(a *Assessment) { a.HumanBenign, a.AIBenign = 0, 2 }, ReasonFewVerdicts},
		{func(a *Assessment) { a.HumanBenign, a.AIBenign = 0, 3 }, ReasonEligible},
	}
	for i, tc := range cases {
		a := ok
		tc.edit(&a)
		if got := c.reason(&a); got != tc.want {
			t.Errorf("#%d: %s，期望 %s", i, got, tc.want)
		}
	}
}

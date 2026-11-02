package intel

import (
	"io"
	"os"
	"testing"
)

func parseFixture(t *testing.T, name string, parse func(io.Reader) ([]Entry, error)) []Entry {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	entries, err := parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func TestParseFeeds(t *testing.T) {
	feodo := parseFixture(t, "feodo.txt", parseList)
	if len(feodo) != 5 || feodo[0] != (Entry{Kind: "ip", Value: "162.243.103.246"}) {
		t.Errorf("Feodo 应解析出 5 个 IP，实际 %v", feodo)
	}

	urlhaus := parseFixture(t, "urlhaus.txt", parseHostsFile)
	if len(urlhaus) == 0 || urlhaus[0].Kind != "domain" || urlhaus[0].Value != "123.ywxww.net" {
		t.Errorf("URLhaus 应解析出域名，实际 %v", urlhaus)
	}

	tf := parseFixture(t, "threatfox.csv", parseThreatFox)
	got := map[string]string{}
	for _, e := range tf {
		got[e.Kind+":"+e.Value] = e.Note
	}
	for _, want := range []string{
		"domain:fyumg68489.workers.dev",
		"ip:152.42.212.170",
		"hash:24f58f4db5552583f9be9d51b71cc9edcc3cdc8ea347528d36408bf1ed2ba56d",
		"ip:124.29.194.167",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("ThreatFox 缺少 %s，实际 %v", want, got)
		}
	}
	if _, ok := got["domain:r.88bravo.com"]; ok {
		t.Error("主机是域名的 URL 不应入库，挂在公共平台上会误伤")
	}
	if got["ip:152.42.212.170"] != "ThreatFox：Jackskid" {
		t.Errorf("应带上恶意软件家族作为备注，实际 %q", got["ip:152.42.212.170"])
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		kind, value string
		ok          bool
		want        string
	}{
		{"ip", "8.8.8.8", true, "8.8.8.8"},
		{"ip", "10.1.1.3", false, ""},
		{"ip", "192.168.0.1", false, ""},
		{"ip", "127.0.0.1", false, ""},
		{"ip", "0.0.0.0", false, ""},
		{"ip", "100.64.0.0", false, ""},
		{"ip", "100.100.100.100", false, ""},
		{"ip", "100.127.255.255", false, ""},
		{"ip", "::ffff:100.64.0.1", false, ""},
		{"ip", "100.63.255.255", true, "100.63.255.255"},
		{"ip", "100.128.0.0", true, "100.128.0.0"},
		{"ip", "::ffff:1.2.3.4", true, "1.2.3.4"},
		{"domain", "Evil.Example.COM.", true, "evil.example.com"},
		{"domain", "localhost", false, ""},
		{"domain", "bad_domain.com", false, ""},
		{"domain", "1.2.3.4", false, ""},
		{"hash", "D41D8CD98F00B204E9800998ECF8427E", true, "d41d8cd98f00b204e9800998ecf8427e"},
		{"hash", "xyz", false, ""},
	}
	for _, c := range cases {
		e, ok := normalize(c.kind, c.value)
		if ok != c.ok || (ok && e.Value != c.want) {
			t.Errorf("normalize(%s, %q) = (%v, %v)，期望 (%q, %v)", c.kind, c.value, e, ok, c.want, c.ok)
		}
	}
}

func TestFeedEntriesDedupe(t *testing.T) {
	in := []Entry{{Kind: "ip", Value: "1.2.3.4", Note: "a"}, {Kind: "ip", Value: "1.2.3.4", Note: "b"}, {Kind: "domain", Value: "1.2.3.4"}}
	var collected feedEntries
	for _, e := range in {
		if err := collected.add(e); err != nil {
			t.Fatal(err)
		}
	}
	out := collected.entries
	if len(out) != 2 || out[0].Note != "a" {
		t.Errorf("同值只留第一条，实际 %v", out)
	}
}

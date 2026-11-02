package intel

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"
)

// 外部源可返回任意字节；格式错误可以拒绝，但不能崩溃或产出无效 IOC。
func FuzzFeedText(f *testing.F) {
	parsers := []func(io.Reader) ([]Entry, error){parseList, parseHostsFile, parseThreatFox}
	for i, file := range []string{"feodo.txt", "urlhaus.txt", "threatfox.csv"} {
		data, err := os.ReadFile("testdata/" + file)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(byte(i), data)
		f.Add(byte(i), []byte("\x00\xff\n# comment\r\n\"unfinished"))
	}
	f.Fuzz(func(t *testing.T, format byte, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		entries, err := parsers[int(format)%len(parsers)](bytes.NewReader(data))
		checkFeedEntries(t, entries, err)
	})
}

func FuzzThreatFoxZIP(f *testing.F) {
	valid := feedZIP(f, "full.csv")
	f.Add(valid)
	f.Add(valid[:len(valid)/2])
	f.Add(feedZIP(f, "one.csv", "two.csv"))
	f.Add([]byte("not a ZIP"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		entries, err := parseThreatFoxZIP(bytes.NewReader(data))
		checkFeedEntries(t, entries, err)
	})
}

func checkFeedEntries(t *testing.T, entries []Entry, err error) {
	t.Helper()
	if err != nil && len(entries) != 0 {
		t.Fatal("解析失败不能返回部分情报")
	}
	if len(entries) > maxFeedEntries {
		t.Fatal("解析结果超过条目上限")
	}
	seen := map[[2]string]bool{}
	for _, entry := range entries {
		key := [2]string{entry.Kind, entry.Value}
		if seen[key] {
			t.Fatalf("重复 IOC: %+v", entry)
		}
		seen[key] = true
		if entry.Value != strings.ToLower(strings.TrimSpace(entry.Value)) {
			t.Fatalf("未规范化的 IOC: %+v", entry)
		}
		switch entry.Kind {
		case "ip":
			addr, err := netip.ParseAddr(entry.Value)
			if err != nil || addr.IsPrivate() || !addr.IsGlobalUnicast() || addr.Is4In6() || cgnat.Contains(addr) {
				t.Fatalf("无效的公网 IP: %+v", entry)
			}
		case "hash":
			decoded, err := hex.DecodeString(entry.Value)
			if err != nil || (len(decoded) != 16 && len(decoded) != 20 && len(decoded) != 32) {
				t.Fatalf("无效的文件哈希: %+v", entry)
			}
		case "domain":
			if len(entry.Value) > 253 || !strings.Contains(entry.Value, ".") || strings.ContainsAny(entry.Value, "/:@ \t\r\n") {
				t.Fatalf("无效的域名: %+v", entry)
			}
		default:
			t.Fatalf("未知 IOC 类型: %+v", entry)
		}
	}
}

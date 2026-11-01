package intel

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestFeedParsersBoundUniqueEntries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		line  func(int) string
		parse func(io.Reader) ([]Entry, error)
	}{
		{"IP列表", func(i int) string { return fmt.Sprintf("11.%d.%d.%d\n", i>>16, (i>>8)&255, i&255) }, parseList},
		{"hosts列表", func(i int) string { return fmt.Sprintf("127.0.0.1 host-%d.example.test\n", i) }, parseHostsFile},
		{"ThreatFox", func(i int) string { return fmt.Sprintf("1,now,host-%d.example.test,domain,x,x,x,fixture\n", i) }, parseThreatFox},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body strings.Builder
			for i := range maxFeedEntries {
				body.WriteString(tc.line(i))
			}
			// 已满时重复行仍可接收，保留现有的按唯一 IOC 计数语义。
			body.WriteString(strings.Repeat(tc.line(0), 1000))
			entries, err := tc.parse(strings.NewReader(body.String()))
			if err != nil || len(entries) != maxFeedEntries {
				t.Fatalf("上限内的唯一条目必须完整保留: count=%d err=%v", len(entries), err)
			}
			body.WriteString(tc.line(maxFeedEntries))
			body.WriteString(strings.Repeat(tc.line(0), 100_000))
			reader := strings.NewReader(body.String())
			entries, err = tc.parse(reader)
			if !errors.Is(err, errFeedEntryLimit) || len(entries) != 0 {
				t.Fatalf("超限必须拒绝整份结果: count=%d err=%v", len(entries), err)
			}
			// CSV 在解析前仍需有界的文本预处理；纯文本源应立即停止读取。
			if tc.name != "ThreatFox" && reader.Len() == 0 {
				t.Fatal("达到条目上限后仍读完了整份文本源")
			}
		})
	}
}

package intel

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func BenchmarkFeedList(b *testing.B) {
	var unique strings.Builder
	for i := range 200_000 {
		fmt.Fprintf(&unique, "11.%d.%d.%d\n", i>>16, (i>>8)&255, i&255)
	}
	for _, tc := range []struct {
		name, body string
		oversized  bool
	}{
		{"重复50万条", strings.Repeat("8.8.8.8\n", 500_000), false},
		{"唯一20万条", unique.String(), true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			f := &Feeds{HTTP: &http.Client{Transport: feedTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
			})}}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				entries, err := f.fetch(context.Background(), Feed{URL: "https://feed.example.test/list", parse: parseList})
				if tc.oversized && (err == nil || len(entries) != 0) {
					b.Fatal("超过唯一条目上限必须拒绝")
				}
				if !tc.oversized && (err != nil || len(entries) != 1) {
					b.Fatalf("重复条目应合并: count=%d err=%v", len(entries), err)
				}
			}
		})
	}
}

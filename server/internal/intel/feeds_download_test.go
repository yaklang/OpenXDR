package intel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type feedTransport func(*http.Request) (*http.Response, error)

func (f feedTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type failedFeedReader struct{}

func (failedFeedReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// 已解析的前半份数据不能掩盖断流、过长行或损坏的 CSV。
func TestFeedDownloadRejectsPartialData(t *testing.T) {
	csv, err := os.ReadFile("testdata/threatfox.csv")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		feed Feed
		body io.Reader
	}{
		{"断流", Feed{parse: parseList}, io.MultiReader(strings.NewReader("8.8.8.8\n"), failedFeedReader{})},
		{"长行", Feed{parse: parseList}, strings.NewReader("8.8.8.8\n#" + strings.Repeat("x", 1<<20))},
		{"CSV损坏", Feed{parse: parseThreatFox}, strings.NewReader(string(csv) + "\n\"unterminated\n")},
		{"超出下载上限", Feed{parse: parseList}, strings.NewReader("8.8.8.8\n" + strings.Repeat("#ignored\n", maxFeedBytes/9+2))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &Feeds{HTTP: &http.Client{Transport: feedTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(tc.body), Header: make(http.Header)}, nil
			})}}
			tc.feed.URL = "https://feed.example.test/list"
			entries, err := f.fetch(context.Background(), tc.feed)
			if err == nil || len(entries) != 0 {
				t.Fatalf("不完整下载必须失败且不返回部分条目: count=%d err=%v", len(entries), err)
			}
		})
	}
}

func TestFeedDownloadCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &Feeds{HTTP: &http.Client{Transport: feedTransport(func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() })}}
	_, err := f.fetch(ctx, Feed{URL: "https://feed.example.test/list", parse: parseList})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("取消应透传: %v", err)
	}
}

// 已收到有效条目后取消，必须中断读流，不能把半份下载当成成功。
func TestFeedDownloadCancelledDuringBody(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
		parse        func(io.Reader) ([]Entry, error)
	}{
		{"IP列表", "8.8.8.8\n", parseList},
		{"hosts列表", "127.0.0.1 malware.example.com\n", parseHostsFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, tc.prefix)
				w.(http.Flusher).Flush()
				close(started)
				<-r.Context().Done()
			}))
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			f := &Feeds{HTTP: srv.Client()}
			done := make(chan error, 1)
			go func() {
				entries, err := f.fetch(ctx, Feed{URL: srv.URL, parse: tc.parse})
				if len(entries) != 0 {
					err = fmt.Errorf("取消后仍返回 %d 条部分情报", len(entries))
				}
				done <- err
			}()
			select {
			case <-started:
				cancel()
			case <-ctx.Done():
				t.Fatal("未开始读取测试数据")
			}
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("读流取消应透传且不返回部分数据: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("取消后下载没有结束")
			}
		})
	}
}

func TestFeedDownloadEntryLimit(t *testing.T) {
	for _, count := range []int{maxFeedEntries, maxFeedEntries + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var body strings.Builder
			for i := range count {
				fmt.Fprintf(&body, "11.%d.%d.%d\n", i>>16, (i>>8)&255, i&255)
			}
			f := &Feeds{HTTP: &http.Client{Transport: feedTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body.String())), Header: make(http.Header)}, nil
			})}}
			entries, err := f.fetch(context.Background(), Feed{URL: "https://feed.example.test/list", parse: parseList})
			if count == maxFeedEntries && (err != nil || len(entries) != count) {
				t.Fatalf("上限内应完整接收: count=%d err=%v", len(entries), err)
			}
			if count > maxFeedEntries && (err == nil || len(entries) != 0) {
				t.Fatalf("超限不能悄悄截断: count=%d err=%v", len(entries), err)
			}
		})
	}
}

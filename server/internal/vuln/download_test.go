package vuln

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDownload(t *testing.T) {
	chunkSize, chunkTimeout = 1000, 200*time.Millisecond
	t.Cleanup(func() { chunkSize, chunkTimeout = 8<<20, 90*time.Second })
	var mu sync.RWMutex
	data := make([]byte, 3500)
	rand.Read(data)
	var calls atomic.Int32
	mode := "range"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		mu.RLock()
		curMode, curData := mode, data
		mu.RUnlock()
		switch {
		case curMode == "flaky" && strings.HasPrefix(r.Header.Get("Range"), "bytes=1000-") && n == 2:
			http.Error(w, "boom", http.StatusBadGateway) // 第二段第一次失败
			return
		case curMode == "stall" && strings.HasPrefix(r.Header.Get("Range"), "bytes=2000-") && n == 3:
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Second): // 第三段第一次卡住，超过每段时限
			}
		case curMode == "norange":
			w.Write(curData)
			return
		}
		http.ServeContent(w, r, "all.zip", time.Time{}, bytes.NewReader(curData))
	}))
	t.Cleanup(srv.Close)
	s := &Syncer{}
	for _, m := range []string{"range", "flaky", "stall", "norange"} {
		mu.Lock()
		mode = m
		mu.Unlock()
		calls.Store(0)
		var out bytes.Buffer
		if err := s.download(context.Background(), srv.URL, &out); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		if !bytes.Equal(out.Bytes(), data) {
			t.Fatalf("%s: 内容不一致（%d / %d 字节）", m, out.Len(), len(data))
		}
	}
	// 大小恰好是分段整数倍：靠 416 收尾
	mu.Lock()
	data = data[:3000]
	mode = "range"
	mu.Unlock()
	var out bytes.Buffer
	if err := s.download(context.Background(), srv.URL, &out); err != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("整数倍大小下载不对: %v %d", err, out.Len())
	}
}

func TestDownloadRetry200TruncatesFile(t *testing.T) {
	// 构造一个合法 ZIP 作为第二次完整响应
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	fw, err := zw.Create("CVE-2026-0001.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte(`{"id":"CVE-2026-0001"}`)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	validZIP := zipBuf.Bytes()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			// 第一次 200 OK：先发半截数据然后直接断开连接，模拟流中途断链
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("ResponseWriter 不支持 Hijack")
				return
			}
			conn, rw, err := hj.Hijack()
			if err != nil {
				t.Errorf("Hijack 失败: %v", err)
				return
			}
			half := validZIP[:len(validZIP)/2]
			fmt.Fprintf(rw, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(validZIP))
			_, _ = rw.Write(half)
			_ = rw.Flush()
			_ = conn.Close()
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(validZIP)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(validZIP)
	}))
	t.Cleanup(srv.Close)

	tmp, err := os.CreateTemp(t.TempDir(), "osv-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()

	s := &Syncer{}
	if err := s.download(context.Background(), srv.URL, tmp); err != nil {
		t.Fatalf("200 重试下载失败: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("期望请求 2 次（首包截断 + 重试成功），实际=%d", calls.Load())
	}

	got, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, validZIP) {
		t.Fatalf("重试后文件内容被污染: got=%d bytes want=%d bytes", len(got), len(validZIP))
	}
	zr, err := zip.OpenReader(tmp.Name())
	if err != nil {
		t.Fatalf("重试后的 ZIP 无法打开: %v", err)
	}
	defer zr.Close()
	if len(zr.File) != 1 || zr.File[0].Name != "CVE-2026-0001.json" {
		t.Fatalf("ZIP 条目异常: %+v", zr.File)
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	body, err := io.ReadAll(rc)
	if err != nil || string(body) != `{"id":"CVE-2026-0001"}` {
		t.Fatalf("ZIP 条目内容异常: %q %v", string(body), err)
	}
}

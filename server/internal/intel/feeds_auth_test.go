package intel

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func feedZIP(t testing.TB, names ...string) []byte {
	t.Helper()
	csv, err := os.ReadFile("testdata/threatfox.csv")
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, name := range names {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(csv); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestThreatFoxZIP(t *testing.T) {
	valid := feedZIP(t, "full.csv")
	for _, tc := range []struct {
		name string
		data []byte
		ok   bool
	}{
		{"CSV压缩包", valid, true},
		{"多个文件", feedZIP(t, "one.csv", "two.csv"), false},
		{"错误类型", feedZIP(t, "index.html"), false},
		{"截断", valid[:len(valid)/2], false},
		{"空压缩包", feedZIP(t), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseThreatFoxZIP(bytes.NewReader(tc.data))
			if tc.ok && (err != nil || len(got) != 6) {
				t.Fatalf("有效 CSV 压缩包未完整解析: count=%d err=%v", len(got), err)
			}
			if !tc.ok && (err == nil || len(got) != 0) {
				t.Fatalf("损坏包不能返回部分情报: count=%d err=%v", len(got), err)
			}
		})
	}
}

func TestAuthenticatedFeedRequest(t *testing.T) {
	key := "test-auth-key-12345678"
	for _, feed := range Catalog {
		if feed.authURL == "" {
			continue
		}
		t.Run(feed.ID, func(t *testing.T) {
			called := false
			f := &Feeds{AuthKey: func(context.Context) string { return key }, HTTP: &http.Client{Transport: feedTransport(func(r *http.Request) (*http.Response, error) {
				called = true
				if r.URL.String() != feed.authURL+key+"/"+feed.authFile {
					t.Errorf("下载地址不符合源契约")
				}
				var data []byte
				if feed.ID == "threatfox" {
					data = feedZIP(t, "full.csv")
				} else {
					data = []byte("127.0.0.1 malware.example.com\n")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
			})}}
			if _, err := f.fetch(context.Background(), feed); err != nil || !called {
				t.Fatalf("认证下载失败: %v", err)
			}
			called = false
			f.AuthKey = nil
			if _, err := f.fetch(context.Background(), feed); err == nil || called {
				t.Fatal("未配置密钥时不应请求已停用的匿名接口")
			}
			f.AuthKey = func(context.Context) string { return key }
			f.HTTP.Transport = feedTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("failed " + feed.authURL + key) })
			if _, err := f.fetch(context.Background(), feed); err == nil || strings.Contains(err.Error(), key) {
				t.Fatalf("错误必须隐藏认证地址: %v", err)
			}
		})
	}
}

func TestAuthenticatedFeedDoesNotFollowRedirect(t *testing.T) {
	var secondCalls int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { secondCalls++ }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer source.Close()
	f := &Feeds{AuthKey: func(context.Context) string { return "secret-key" }, HTTP: source.Client()}
	_, err := f.fetch(context.Background(), Feed{authURL: source.URL + "/", authFile: "list", parse: parseList})
	if err == nil || secondCalls != 0 {
		t.Fatal("带密钥的重定向必须拒绝")
	}
	if f.HTTP.CheckRedirect != nil {
		t.Fatal("不能修改调用方共享的 HTTP 客户端")
	}
}

func TestThreatFoxZIPRejectsOversizedExpansion(t *testing.T) {
	var body bytes.Buffer
	writer := zip.NewWriter(&body)
	if _, err := writer.CreateRaw(&zip.FileHeader{Name: "full.csv", Method: zip.Store, UncompressedSize64: maxFeedBytes + 1}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if entries, err := parseThreatFoxZIP(bytes.NewReader(body.Bytes())); err == nil || len(entries) != 0 {
		t.Fatal("超限的解压大小必须在展开前拒绝")
	}
}

// ZIP 目录完整且 CSV 内容合法，也必须消费到 EOF 才能发现 CRC 损坏。
func TestThreatFoxZIPChecksum(t *testing.T) {
	csv, err := os.ReadFile("testdata/threatfox.csv")
	if err != nil {
		t.Fatal(err)
	}
	for _, corrupt := range []bool{false, true} {
		checksum := crc32.ChecksumIEEE(csv)
		if corrupt {
			checksum ^= 1
		}
		var body bytes.Buffer
		writer := zip.NewWriter(&body)
		file, err := writer.CreateRaw(&zip.FileHeader{
			Name: "full.csv", Method: zip.Store, CRC32: checksum,
			CompressedSize64: uint64(len(csv)), UncompressedSize64: uint64(len(csv)),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(csv); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		entries, err := parseThreatFoxZIP(bytes.NewReader(body.Bytes()))
		if corrupt && (err == nil || len(entries) != 0) {
			t.Fatal("CRC 损坏时不能接受已解析的 CSV 条目")
		}
		if !corrupt && (err != nil || len(entries) != 6) {
			t.Fatalf("相同内容在 CRC 正确时应被完整接受: count=%d err=%v", len(entries), err)
		}
	}
}

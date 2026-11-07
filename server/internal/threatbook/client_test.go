package threatbook

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestQueryContract(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.String() != "https://api.threatbook.cn/v3/ip/query" {
			t.Fatalf("错误接口: %s %s", r.Method, r.URL)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("apikey") != "test-secret" || r.Form.Get("resource") != "8.8.8.8" {
			t.Fatalf("请求字段错误")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"response_code":0,"ips":{"8.8.8.8":{"judgments":["Scanner"],"intelligences":{"open_source":[{"expired":true}]},"flow_id":18446744073709551615}}}`)), Header: make(http.Header)}, nil
	})}
	result, err := Query(context.Background(), client, "test-secret", "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || result.Provider != "threatbook" || len(result.Judgments) != 1 || result.QueriedAt.IsZero() || result.ExpiresAt.Sub(result.QueriedAt) != 24*time.Hour || !strings.Contains(string(result.Data), "18446744073709551615") {
		t.Fatalf("分析结果错误: %+v", result)
	}
}

func TestRejectProviderFailures(t *testing.T) {
	for _, body := range []string{`{}`, `{"response_code":-4,"verbose_msg":"test-secret"}`, `{"response_code":0,"ips":{}}`, `{"response_code":0,"ips":{"8.8.8.8":null}}`, `not json`, strings.Repeat("x", (256<<10)+1)} {
		client := &http.Client{Transport: transport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		if _, err := Query(context.Background(), client, "test-secret", "8.8.8.8"); err == nil || strings.Contains(err.Error(), "test-secret") {
			t.Fatalf("坏响应不应成功或泄漏密钥: %v", err)
		}
	}
	for _, status := range []int{302, 401, 403, 429, 500} {
		client := &http.Client{Transport: transport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("secret")), Header: http.Header{"Location": []string{"https://other.invalid"}}}, nil
		})}
		if _, err := Query(context.Background(), client, "test-secret", "8.8.8.8"); err == nil {
			t.Fatalf("HTTP %d 不应当作成功", status)
		}
	}
}

func TestPublicIP(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "192.0.2.1", "198.18.0.1", "::1", "fe80::1", "fd00::1", "2001:db8::1", "invalid"} {
		if _, err := PublicIP(ip); err == nil {
			t.Errorf("不应向外查询 %s", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if _, err := PublicIP(ip); err != nil {
			t.Errorf("公网地址 %s: %v", ip, err)
		}
	}
}

func TestQuotaReservation(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	var q quota
	if q.reserve(now, 1, 2) != nil {
		t.Fatal("首条应通过")
	}
	if q.reserve(now, 1, 2) != ErrQuota {
		t.Fatal("分钟超限应拒绝")
	}
	if q.reserve(now.Add(time.Minute), 1, 2) != nil {
		t.Fatal("新分钟应允许")
	}
	if q.reserve(now.Add(2*time.Minute), 1, 2) != ErrQuota {
		t.Fatal("日额度超限应拒绝")
	}
	if q.reserve(now.Add(24*time.Hour), 1, 2) != nil {
		t.Fatal("新日期应恢复额度")
	}
	if q.reserve(now, 0, 2) != ErrQuota {
		t.Fatal("零额度应拒绝")
	}
}

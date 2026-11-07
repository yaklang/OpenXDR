//go:build integration

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"openxdr/server/ent"
	"openxdr/server/ent/auditlog"
	"openxdr/server/internal/testdb"
	"openxdr/server/internal/threatbook"
)

// lookupTLS 将固定官方地址接到测试 TLS 服务，不增加可在生产配置的模拟端点。
type lookupTLS struct {
	target    *url.URL
	transport http.RoundTripper
}

func (l lookupTLS) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != "api.threatbook.cn" || r.URL.Path != "/v3/ip/query" {
		return nil, fmt.Errorf("查询使用了错误的供应商接口")
	}
	request := r.Clone(r.Context())
	request.URL.Scheme, request.URL.Host = l.target.Scheme, l.target.Host
	request.Host = l.target.Host
	return l.transport.RoundTrip(request)
}

func TestThreatBookHTTPAndPostgres(t *testing.T) {
	ctx, db := testdb.New(t)
	conn, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.ParseForm() != nil || r.Form.Get("apikey") != "mock-key" || r.Form.Get("resource") != "8.8.8.8" {
			http.Error(w, "协议字段错误", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"response_code":0,"ips":{"8.8.8.8":{"judgments":["Scanner"],"intelligences":{"open_source":[{"source":"test fixture","expired":true}]}}}}`)
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	tlsClient := upstream.Client()
	client := &http.Client{Transport: lookupTLS{target: target, transport: tlsClient.Transport}}
	service := &threatbook.Service{DB: conn, Key: func(context.Context) string { return "mock-key" }, Client: client, PerMinute: 1, PerDay: 1}
	api := httptest.NewServer(asAdmin(ThreatBookLookup(db, service)))
	defer api.Close()
	lookup := func(ip string, expected int) []byte {
		t.Helper()
		response, err := http.Post(api.URL, "application/json", strings.NewReader(`{"ip":"`+ip+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != expected {
			t.Fatalf("状态 %d，预期 %d: %s", response.StatusCode, expected, body)
		}
		return body
	}
	for _, cached := range []bool{false, true} {
		raw := lookup("8.8.8.8", 200)
		var result threatbook.Result
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		if result.Cached != cached || result.Provider != "threatbook" || result.IP != "8.8.8.8" || len(result.Judgments) != 1 || result.Judgments[0] != "Scanner" {
			t.Fatalf("查询结果不符: %s", raw)
		}
		if strings.Contains(string(raw), "mock-key") {
			t.Fatal("查询结果泄漏密钥")
		}
	}
	lookup("1.1.1.1", 429)
	lookup("10.0.0.1", 400)
	if calls.Load() != 1 {
		t.Fatalf("缓存、额度或内网限制失效，供应商调用 %d 次", calls.Load())
	}
	if count := db.AuditLog.Query().Where(auditlog.ActionEQ("intel.threatbook.lookup")).CountX(ctx); count != 2 {
		t.Fatalf("两次成功查询均应审计: %d", count)
	}
	if count := db.Intel.Query().CountX(ctx); count != 0 {
		t.Fatalf("供应商标签不得自动写入 IOC: %d", count)
	}
	viewer := httptest.NewServer(as(&ent.User{Role: "viewer"}, ThreatBookLookup(db, service)))
	defer viewer.Close()
	response, err := http.Post(viewer.URL, "application/json", strings.NewReader(`{"ip":"8.8.8.8"}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatalf("viewer 不应消耗查询额度: %d", response.StatusCode)
	}
	if calls.Load() != 1 {
		t.Fatal("越权请求触发了外部查询")
	}
}

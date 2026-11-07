//go:build integration

package threatbook

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"openxdr/server/internal/testdb"
	"os"
	"strings"
	"testing"
)

func TestSharedCacheAndQuota(t *testing.T) {
	ctx, _ := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	calls := 0
	client := &http.Client{Transport: transport(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"response_code":0,"ips":{"8.8.8.8":{"judgments":["Info"]}}}`))}, nil
	})}
	service := Service{DB: db, Key: func(context.Context) string { return "secret" }, Client: client, PerMinute: 1, PerDay: 1}
	first, err := service.Lookup(ctx, "8.8.8.8")
	if err != nil || first.Cached {
		t.Fatalf("首查: %v %+v", err, first)
	}
	other := service
	cached, err := other.Lookup(ctx, "8.8.8.8")
	if err != nil || !cached.Cached || calls != 1 {
		t.Fatalf("跨实例应共享缓存: %v %+v calls=%d", err, cached, calls)
	}
	if _, err := other.Lookup(ctx, "1.1.1.1"); err != ErrQuota {
		t.Fatalf("跨实例共享额度: %v", err)
	}
	// 缓存过期后不能拿旧结果伪装成新查询，额度耗尽就拒绝。
	if _, err := db.ExecContext(ctx, `UPDATE settings SET value=jsonb_set(value,'{expiresAt}','"2000-01-01T00:00:00Z"') WHERE id='threatbook:cache:8.8.8.8'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Lookup(ctx, "8.8.8.8"); err != ErrQuota {
		t.Fatalf("过期缓存不应返回: %v", err)
	}
	if calls != 1 {
		t.Fatal("额度耗尽后仍调用供应商")
	}
}

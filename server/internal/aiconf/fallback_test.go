package aiconf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestFallbackValidation(t *testing.T) {
	for _, v := range []string{"a,,b", "a,a", "a b", strings.Repeat("a", 129), "1,2,3,4,5,6,7,8,9"} {
		if (Patch{FallbackModels: &v}).Check() == nil {
			t.Fatalf("应拒绝 %q", v)
		}
	}
	for _, v := range []string{"", "one,two", "org/model"} {
		if err := (Patch{FallbackModels: &v}).Check(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestModelsDiscoveryAndRedirect(t *testing.T) {
	leaked := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	redirect := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" || r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("地址或认证错误")
		}
		if redirect {
			http.Redirect(w, r, target.URL, 302)
			return
		}
		w.Write([]byte(`{"data":[{"id":"b"},{"id":"a"},{"id":"b"},{"id":"bad name"}]}`))
	}))
	defer srv.Close()
	c := Config{BaseURL: srv.URL + "/v1", APIKey: "secret"}
	models, err := Models(context.Background(), c)
	if err != nil || !reflect.DeepEqual(models, []string{"a", "b"}) {
		t.Fatalf("%v %v", models, err)
	}
	redirect = true
	if _, err = Models(context.Background(), c); err == nil || leaked {
		t.Fatal("不应向重定向目标发送请求")
	}
}

package native

import (
	"crypto/subtle"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"sync"
)

// HTTPHandler 处理根路径与专用诱饵前缀，可挂载到独立监听器或明确隔离的服务路由。
// 不读取 Cookie、表单、Authorization 或任意客户端内容，不代理业务请求。
func HTTPHandler(m Manifest, record func(string) error) (http.Handler, error) {
	if m.Kind != "http" || len(m.Marker) != 64 || record == nil {
		return nil, fmt.Errorf("HTTP 诱饵配置无效")
	}
	text, err := Text(m.Kind, m.Profile, m.Marker)
	if err != nil {
		return nil, err
	}
	page := template.Must(template.New("decoy").Parse(`<!doctype html><html lang="zh"><meta charset="utf-8"><title>维护资料</title><main><h1>维护资料</h1><pre>{{.Text}}</pre><nav><a href="{{.Base}}/archive">归档</a> · <a href="{{.Base}}/status">状态</a>{{if .Verify}} · <a href="{{.Base}}/verify/{{.Marker}}">核实标记</a>{{end}}</nav></main></html>`))
	base := "/decoy/" + m.ID
	var mu sync.Mutex
	used, failed := false, false
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(405)
			return
		}
		// 独立监听时根路径也是诱饵页，扫描器访问 / 就能发现；挂到业务路由时只有专用前缀会进来。
		prefix, rest := base, strings.TrimPrefix(r.URL.Path, base)
		if rest == r.URL.Path {
			prefix = ""
		}
		kind := "http_page"
		isVerify := strings.HasPrefix(rest, "/verify/")
		if !isVerify && rest != "" && rest != "/" && rest != "/archive" && rest != "/status" {
			http.NotFound(w, r)
			return
		}
		// 排队而不是回 429：并发抓取的扫描器拿到“繁忙”既丢观察，也暴露诱饵特征。
		mu.Lock()
		defer mu.Unlock()
		if failed {
			http.Error(w, "诱饵不可用", 503)
			return
		}
		if isVerify {
			if m.Profile != "decoy" || used || subtle.ConstantTimeCompare([]byte(rest[len("/verify/"):]), []byte(m.Marker)) != 1 {
				http.NotFound(w, r)
				return
			}
			kind = "marker_used"
		}
		// HEAD 没有读取正文，不生成页面展示或标记使用记录。
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == http.MethodHead {
			return
		}
		if err := record(kind); err != nil {
			failed = true
			http.Error(w, "事件保存失败", 503)
			return
		}
		if isVerify {
			used = true
			_, _ = w.Write([]byte("核实已记录；此操作不授予访问权限。"))
			return
		}
		_ = page.Execute(w, struct {
			Text, Base, Marker string
			Verify             bool
		}{text, prefix, m.Marker, m.Profile == "decoy"})
	}), nil
}

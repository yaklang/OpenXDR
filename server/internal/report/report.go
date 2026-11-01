// Package report 报告渲染：Pi 提交的 Markdown 转 HTML，再交给 headless Chromium 打印成 PDF。
// Markdown 来自模型，视为不可信输入：goldmark 默认不输出原始 HTML、滤掉 javascript: 等危险链接，
// 页面再由调用方加 CSP 兜底。
package report

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"openxdr/server/internal/worklimit"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
)

var md = goldmark.New(goldmark.WithExtensions(extension.GFM))

// CSP 同时用于独立文件和 HTTP 页面，禁止报告加载外部资源。
const CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"

var pdfSlots = worklimit.New(2, 8)

var page = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="` + CSP + `"><title>{{.Title}}</title>
<style>
body{font-family:"Noto Sans CJK SC","PingFang SC","Microsoft YaHei",sans-serif;max-width:960px;margin:2em auto;padding:0 1em;color:#1f2328;line-height:1.6}
h1,h2,h3{border-bottom:1px solid #d0d7de;padding-bottom:.3em}
table{border-collapse:collapse;margin:1em 0}th,td{border:1px solid #d0d7de;padding:4px 10px}th{background:#f6f8fa}
code{background:#f6f8fa;padding:.1em .3em;border-radius:4px;font-size:90%}
pre{background:#f6f8fa;padding:1em;overflow-x:auto}pre code{background:none;padding:0}
.meta{color:#656d76;font-size:90%}
.level{display:inline-block;padding:0 .5em;border-radius:4px;font-size:90%;color:#fff}
.level-ok{background:#1a7f37}.level-attention{background:#9a6700}.level-urgent{background:#cf222e}
.summary{border-left:4px solid #0969da;background:#f6f8fa;padding:.6em 1em;margin:1em 0;font-weight:600}
details.evidence-fold{margin-top:1.5em;border:1px solid #d0d7de;border-radius:6px;padding:.6em 1em;background:#fafbfc}
details.evidence-fold>summary{cursor:pointer;font-weight:600;color:#0969da;user-select:none}
@media print{body{margin:0;max-width:none}pre{white-space:pre-wrap}}
</style></head><body>
<h1>{{.Title}}</h1>
<p class="meta">{{with .LevelText}}<span class="level level-{{$.Level}}">{{.}}</span> {{end}}{{with .Source}}{{.}} · {{end}}生成时间 {{.CreatedAt.Format "2006-01-02 15:04:05"}}</p>
{{with .Summary}}<p class="summary">{{.}}</p>{{end}}
{{.Body}}
{{with .FoldBody}}<details class="evidence-fold"><summary>🔍 展开详细取证、推断与未验证边界</summary>{{.}}</details>{{end}}
</body></html>
`))

// Page 一份报告的页头与正文。页头由平台渲染，各报告格式一致；正文是模型写的 Markdown
type Page struct {
	Title, Summary, Level, Source, Markdown string
	CreatedAt                               time.Time
}

var levelText = map[string]string{"ok": "无需处理", "attention": "需处理", "urgent": "紧急"}

// HTML 渲染成独立页面。
func HTML(p Page) ([]byte, error) {
	topMD, foldMD := SplitFold(p.Markdown)
	var body, foldBody bytes.Buffer
	if err := md.Convert([]byte(topMD), &body); err != nil {
		return nil, err
	}
	if foldMD != "" {
		if err := md.Convert([]byte(foldMD), &foldBody); err != nil {
			return nil, err
		}
	}
	var out bytes.Buffer
	err := page.Execute(&out, struct {
		Page
		LevelText string
		Body      template.HTML // goldmark 已转义，原始 HTML 被省略
		FoldBody  template.HTML
	}{p, levelText[p.Level], template.HTML(body.String()), template.HTML(foldBody.String())})
	return out.Bytes(), err
}

// Chromium 可执行文件名或路径，main 按 CHROMIUM_PATH 设置。
var Chromium = "chromium"

// ErrNoChromium 未找到 Chromium，PDF 不可用。
var ErrNoChromium = errors.New("未找到 Chromium，PDF 渲染不可用")

// PDF 用 headless Chromium 打印 HTML。
// 页面 CSP 禁止外部资源；代理与 DNS 阻断作为额外防线。
func PDF(ctx context.Context, html []byte) ([]byte, error) {
	bin, err := exec.LookPath(Chromium)
	if err != nil {
		return nil, ErrNoChromium
	}
	release, err := pdfSlots.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	dir, err := os.MkdirTemp("", "openxdr-report-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	in, out := filepath.Join(dir, "report.html"), filepath.Join(dir, "report.pdf")
	printHTML := bytes.ReplaceAll(html, []byte(`<details class="evidence-fold">`), []byte(`<details class="evidence-fold" open>`))
	if err := os.WriteFile(in, printHTML, 0o600); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"--headless", "--no-sandbox", "--disable-gpu", "--no-pdf-header-footer",
		"--user-data-dir="+filepath.Join(dir, "profile"),
		// IP 地址不经过 DNS；同时禁用直连及隐式 loopback 代理绕过。
		"--host-resolver-rules=MAP * ~NOTFOUND",
		"--proxy-server=http://127.0.0.1:0", "--proxy-bypass-list=<-loopback>",
		"--disable-background-networking",
		"--print-to-pdf="+out, "file://"+in)
	if msg, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("chromium 渲染失败: %w: %s", err, tail(msg))
	}
	return os.ReadFile(out)
}

func tail(b []byte) []byte {
	if len(b) > 512 {
		return b[len(b)-512:]
	}
	return b
}

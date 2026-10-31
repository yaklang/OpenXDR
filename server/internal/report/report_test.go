package report

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTMLEscapesUntrustedMarkdown(t *testing.T) {
	out, err := HTML(Page{Title: "巡检 <b>", Summary: "摘要 <i>", Level: "urgent", Source: "每日主机巡检", CreatedAt: time.Now(),
		Markdown: "# 模型自己写的标题\n## 结论\n\n<script>alert(1)</script>\n\n[x](javascript:alert(1))\n\n| 主机 | 状态 |\n|---|---|\n| web01 | 正常 |\n"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, bad := range []string{"<script>", "javascript:", "<b>", "<i>", "模型自己写的标题"} {
		if strings.Contains(s, bad) {
			t.Errorf("输出不应包含 %q", bad)
		}
	}
	// 页头由平台渲染：标题、级别、来源、一句话结论；正文开头重复的一级标题去掉
	for _, want := range []string{"<h2>结论</h2>", "<table>", "<h1>巡检 &lt;b&gt;</h1>", `class="level level-urgent">紧急`, "每日主机巡检 · ", `<p class="summary">摘要 &lt;i&gt;</p>`} {
		if !strings.Contains(s, want) {
			t.Errorf("输出缺少 %q", want)
		}
	}
}

func TestPDFWithoutChromium(t *testing.T) {
	old := Chromium
	Chromium = "openxdr-no-such-chromium"
	defer func() { Chromium = old }()
	_, err := PDF(context.Background(), []byte("<p>x</p>"))
	if !errors.Is(err, ErrNoChromium) {
		t.Fatalf("缺 Chromium 应报 ErrNoChromium，得到 %v", err)
	}
}

// 数字 IP 外链无需 DNS；用本地 HTTP 接收器验证真实 Chromium 不会请求它。
func TestPDFBlocksIPImages(t *testing.T) {
	if _, err := exec.LookPath(Chromium); err != nil {
		t.Skip("未安装 Chromium")
	}
	var requests atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.Write([]byte("image")) }))
	defer endpoint.Close()
	html, err := HTML(Page{Title: "报告", Markdown: "![外链](" + endpoint.URL + "/probe)", CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	pdf, err := PDF(context.Background(), html)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(pdf), "%PDF-") {
		t.Fatal("未生成 PDF")
	}
	if requests.Load() != 0 {
		t.Fatal("Chromium 访问了 IP 外链")
	}
}

func TestStandaloneHTMLHasCSP(t *testing.T) {
	html, err := HTML(Page{Title: "报告", Markdown: "![外链](http://127.0.0.1/probe)", CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	csp := strings.Index(s, `http-equiv="Content-Security-Policy"`)
	body := strings.Index(s, "<body>")
	if csp < 0 || csp > body || !strings.Contains(s, CSP) {
		t.Fatal("独立 HTML 缺少前置 CSP")
	}
}

// 统一格式：必需的节缺了带骨架拒绝，编号写法与模型自写的一级标题都容忍
func TestNormalize(t *testing.T) {
	body := "# 自写标题\n## 一、结论\n良性\n## 需要人处理\n无\n## 证据\nss 输出\n## 未验证\n无\n"
	title, summary, md, err := Normalize("  pve1/pve2 每日巡检 ", " 两台主机均正常 ", body)
	if err != nil || title != "pve1/pve2 每日巡检" || summary != "两台主机均正常" || strings.HasPrefix(md, "# 自写标题") {
		t.Fatalf("应通过并整理：%q %q %q %v", title, summary, md, err)
	}
	for name, c := range map[string][3]string{
		"标题过长":  {strings.Repeat("长", MaxTitle+1), "结论", body},
		"没有结论":  {"标题", "", body},
		"结论换行":  {"标题", "第一行\n第二行", body},
		"结论过长":  {"标题", strings.Repeat("长", MaxSummary+1), body},
		"缺未验证节": {"标题", "结论", "## 结论\n良性\n## 需要人处理\n无\n"},
		"正文为空":  {"标题", "结论", "# 只有标题"},
	} {
		if _, _, _, err := Normalize(c[0], c[1], c[2]); err == nil {
			t.Errorf("%s 应拒绝", name)
		}
	}
	if _, _, _, err := Normalize("标题", "结论", "## 结论\n良性\n"); err == nil || !strings.Contains(err.Error(), "## 需要人处理、## 未验证") || !strings.Contains(err.Error(), Template) {
		t.Errorf("缺节时应列出缺的节并带回骨架：%v", err)
	}
	// 带 Emoji 的章节标题同样兼容，且证据/推断/未验证折叠进 details
	emojiBody := "## 📌 结论\n🟢 正常\n## 🤖 已执行的操作\n- 同步 2 项待办\n## ⚡ 需要人处理\n无\n## 🔍 证据\nss 输出\n## 未验证\n无\n"
	if _, _, _, err := Normalize("标题", "一句话结论", emojiBody); err != nil {
		t.Fatalf("Emoji 章节标题应通过 Normalize：%v", err)
	}
	top, fold := SplitFold(emojiBody)
	if !strings.Contains(top, "已执行的操作") || strings.Contains(top, "ss 输出") || !strings.Contains(fold, "ss 输出") {
		t.Fatalf("SplitFold 拆分不符：top=%q fold=%q", top, fold)
	}
	html, err := HTML(Page{Title: "巡检", Summary: "正常", Markdown: emojiBody, CreatedAt: time.Now()})
	if err != nil || !strings.Contains(string(html), `<details class="evidence-fold">`) {
		t.Fatalf("HTML 应包含可折叠证据区块：%v", err)
	}
}

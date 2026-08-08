package api

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRenderReportFull(t *testing.T) {
	ts := time.Date(2026, 8, 8, 14, 30, 0, 0, time.UTC)
	last := ts.Add(2 * time.Minute)
	d := reportData{
		ID:        uuid.MustParse("019fe07d-87b8-74f3-b677-c91be5f89793"),
		Title:     "反弹 shell @ web01",
		CreatedAt: ts,
		Status:    "triaged",
		Hosts:     []string{"web01", "db01"},
		Processes: []string{"bash (4242)"},
		Overflow:  7,
		Alerts: []reportAlert{{
			Ts: ts, LastTs: &last, Count: 3, Severity: 5,
			Rule: "Linux Reverse Shell Indicators", Evidence: `{"process":{"cmd_line":"bash -i"}}`,
		}},
		Commands: []reportCommand{{
			CreatedAt: last, Kind: "isolate", Status: "succeeded",
			DryRun: false, IssuedBy: "kei", Detail: "已隔离",
		}},
	}
	d.HasVerdict = true
	d.Verdict.Verdict = "malicious"
	d.Verdict.Confidence = 92
	d.Verdict.Summary = "确认为反弹 shell 外连"
	d.Verdict.KillChain = []string{"下载载荷", "建立反连"}
	d.Verdict.Actions = []string{"隔离主机", "重置凭据"}

	out := renderReport(d)
	for _, want := range []string{
		"# 安全事件报告：反弹 shell @ web01",
		"019fe07d-87b8-74f3-b677-c91be5f89793",
		"| 当前状态 | 已研判 |",
		"| 最高级别 | 严重 |",
		"web01, db01",
		"**恶意**（置信度 92%）",
		"确认为反弹 shell 外连",
		"1. 下载载荷",
		"- 进程 `bash (4242)`",
		"08-08 14:30:00 ~ 14:32:00", // 去重窗口跨度
		"Linux Reverse Shell Indicators",
		"另有 7 条告警",
		"| isolate | 真实执行 | succeeded | kei |",
		"- 隔离主机",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("报告缺少 %q\n---\n%s", want, out)
		}
	}
}

func TestRenderReportNoVerdictNoActions(t *testing.T) {
	d := reportData{ID: uuid.New(), CreatedAt: time.Now(), Status: "open"}
	out := renderReport(d)
	for _, want := range []string{"尚未研判", "无告警明细", "未下发处置指令"} {
		if !strings.Contains(out, want) {
			t.Errorf("报告缺少 %q", want)
		}
	}
	// 没有攻击链与建议时不该留空标题
	for _, unwanted := range []string{"## 攻击链", "## 处置建议", "## 涉及实体"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("空内容不该出现标题 %q", unwanted)
		}
	}
}

// 表格单元格必须转义竖线与换行，否则 Markdown 表格结构被破坏
func TestMdCellEscaping(t *testing.T) {
	got := mdCell("a|b\nc")
	if strings.Contains(got, "\n") {
		t.Errorf("换行未处理: %q", got)
	}
	if !strings.Contains(got, `\|`) {
		t.Errorf("竖线未转义: %q", got)
	}
	if mdCell("") != "-" {
		t.Errorf("空值应显示为 -，实际 %q", mdCell(""))
	}
	long := mdCell(strings.Repeat("x", 300))
	if len([]byte(long)) > 165 {
		t.Errorf("超长内容未截断: %d 字节", len(long))
	}
}

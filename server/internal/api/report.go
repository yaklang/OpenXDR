package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	entcommand "openxdr/server/ent/command"
	"openxdr/server/internal/sigma"
)

// reportData 渲染报告需要的全部素材。数据组装与文字生成分开，
// 渲染是纯函数，可以脱离数据库单测。
type reportData struct {
	ID        uuid.UUID
	Title     string
	CreatedAt time.Time
	Status    string
	Verdict   struct {
		Verdict    string   `json:"verdict"`
		Confidence int      `json:"confidence"`
		Summary    string   `json:"summary"`
		KillChain  []string `json:"kill_chain"`
		Actions    []string `json:"actions"`
		Error      string   `json:"error"`
	}
	HasVerdict bool
	Hosts      []string
	Processes  []string
	Alerts     []reportAlert
	Commands   []reportCommand
	Overflow   int
}

type reportAlert struct {
	Ts       time.Time
	LastTs   *time.Time
	Count    int
	Severity int16
	Rule     string
	Evidence string
}

type reportCommand struct {
	CreatedAt time.Time
	Kind      string
	Status    string
	DryRun    bool
	IssuedBy  string
	Detail    string
}

var severityName = map[int16]string{1: "信息", 2: "低危", 3: "中危", 4: "高危", 5: "严重"}

var verdictName = map[string]string{
	"malicious": "恶意", "suspicious": "可疑", "benign": "良性",
}

var statusName = map[string]string{
	"open": "待研判", "triaged": "已研判", "closed": "已关闭", "false_positive": "误报",
}

// renderReport 生成事件报告。给人看的东西，字段顺序按汇报时的阅读顺序排：
// 先结论，再证据，最后处置。
func renderReport(d reportData) string {
	var b strings.Builder
	title := d.Title
	if title == "" {
		title = d.ID.String()
	}
	fmt.Fprintf(&b, "# 安全事件报告：%s\n\n", title)

	fmt.Fprintf(&b, "| 项 | 值 |\n|---|---|\n")
	fmt.Fprintf(&b, "| 事件 ID | `%s` |\n", d.ID)
	fmt.Fprintf(&b, "| 发生时间 | %s |\n", d.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "| 当前状态 | %s |\n", nameOr(statusName, d.Status))
	fmt.Fprintf(&b, "| 最高级别 | %s |\n", nameOr(severityName, maxSeverity(d.Alerts)))
	fmt.Fprintf(&b, "| 告警条数 | %d |\n", len(d.Alerts))
	if len(d.Hosts) > 0 {
		fmt.Fprintf(&b, "| 涉及主机 | %s |\n", strings.Join(d.Hosts, ", "))
	}
	b.WriteString("\n")

	b.WriteString("## 研判结论\n\n")
	switch {
	case !d.HasVerdict:
		b.WriteString("尚未研判（未启用 AI 研判，或事件刚产生）。\n\n")
	case d.Verdict.Error != "":
		fmt.Fprintf(&b, "研判输出无法解析：%s\n\n", d.Verdict.Error)
	default:
		fmt.Fprintf(&b, "**%s**（置信度 %d%%）\n\n",
			nameOr(verdictName, d.Verdict.Verdict), d.Verdict.Confidence)
		if d.Verdict.Summary != "" {
			fmt.Fprintf(&b, "%s\n\n", d.Verdict.Summary)
		}
	}

	if len(d.Verdict.KillChain) > 0 {
		b.WriteString("## 攻击链\n\n")
		for i, step := range d.Verdict.KillChain {
			fmt.Fprintf(&b, "%d. %s\n", i+1, step)
		}
		b.WriteString("\n")
	}

	if len(d.Hosts) > 0 || len(d.Processes) > 0 {
		b.WriteString("## 涉及实体\n\n")
		for _, h := range d.Hosts {
			fmt.Fprintf(&b, "- 主机 `%s`\n", h)
		}
		for _, p := range d.Processes {
			fmt.Fprintf(&b, "- 进程 `%s`\n", p)
		}
		b.WriteString("\n")
	}

	b.WriteString("## 告警时间线\n\n")
	if len(d.Alerts) == 0 {
		b.WriteString("无告警明细。\n\n")
	} else {
		b.WriteString("| 时间 | 级别 | 规则 | 次数 | 证据 |\n|---|---|---|---|---|\n")
		for _, a := range d.Alerts {
			span := a.Ts.Format("01-02 15:04:05")
			if a.LastTs != nil && a.LastTs.After(a.Ts) {
				span += " ~ " + a.LastTs.Format("15:04:05")
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %d | %s |\n",
				span, nameOr(severityName, a.Severity), a.Rule, a.Count, mdCell(a.Evidence))
		}
		b.WriteString("\n")
	}
	if d.Overflow > 0 {
		fmt.Fprintf(&b, "> 另有 %d 条告警因图规模上限未纳入实体关系图。\n\n", d.Overflow)
	}

	b.WriteString("## 处置记录\n\n")
	if len(d.Commands) == 0 {
		b.WriteString("未下发处置指令。\n\n")
	} else {
		b.WriteString("| 时间 | 动作 | 模式 | 状态 | 操作人 | 结果 |\n|---|---|---|---|---|---|\n")
		for _, c := range d.Commands {
			mode := "真实执行"
			if c.DryRun {
				mode = "演练"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
				c.CreatedAt.Format("01-02 15:04:05"), c.Kind, mode, c.Status,
				c.IssuedBy, mdCell(c.Detail))
		}
		b.WriteString("\n")
	}

	if len(d.Verdict.Actions) > 0 {
		b.WriteString("## 处置建议\n\n")
		for _, a := range d.Verdict.Actions {
			fmt.Fprintf(&b, "- %s\n", a)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "---\n\n由 OpenXDR 生成于 %s\n", time.Now().Format("2006-01-02 15:04:05"))
	return b.String()
}

// maxSeverity 事件级别取告警最高级。不单独存字段：能算出来的状态
// 多存一份就是多一处不一致的机会。
func maxSeverity(alerts []reportAlert) int16 {
	var max int16
	for _, a := range alerts {
		if a.Severity > max {
			max = a.Severity
		}
	}
	return max
}

func nameOr[K comparable](m map[K]string, key K) string {
	if v, ok := m[key]; ok {
		return v
	}
	return fmt.Sprint(key)
}

// mdCell 表格单元格：换行与竖线会破坏表格结构，超长内容截断。
func mdCell(s string) string {
	s = strings.NewReplacer("\n", " ", "\r", "", "|", "\\|").Replace(s)
	if len(s) > 160 {
		s = s[:157] + "…"
	}
	if s == "" {
		return "-"
	}
	return "`" + s + "`"
}

func mapReport(api *http.ServeMux, db *ent.Client, rules *sigma.Engine) {
	api.HandleFunc("GET /api/incidents/{id}/report", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "无效的 incident id", http.StatusBadRequest)
			return
		}
		d, err := collectReport(r, db, rules, id)
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="incident-%s.md"`, id))
		_, _ = w.Write([]byte(renderReport(d)))
	})
}

func collectReport(r *http.Request, db *ent.Client, rules *sigma.Engine, id uuid.UUID) (reportData, error) {
	ctx := r.Context()
	inc, err := db.Incident.Get(ctx, id)
	if err != nil {
		return reportData{}, err
	}

	d := reportData{
		ID: inc.ID, CreatedAt: inc.CreatedAt, Status: inc.Status,
	}
	if inc.Title != nil {
		d.Title = *inc.Title
	}
	if len(inc.AiVerdict) > 0 {
		d.HasVerdict = json.Unmarshal(inc.AiVerdict, &d.Verdict) == nil
		if !d.HasVerdict {
			d.HasVerdict = true
			d.Verdict.Error = "输出不是合法 JSON"
		}
	}

	// 实体：从关系图里取，图已经是关联引擎归并过的结果
	var graph struct {
		Nodes []struct {
			Type  string `json:"type"`
			Label string `json:"label"`
		} `json:"nodes"`
		Overflow int `json:"overflow"`
	}
	if json.Unmarshal(inc.Graph, &graph) == nil {
		d.Overflow = graph.Overflow
		seen := map[string]bool{}
		for _, n := range graph.Nodes {
			if n.Label == "" || seen[n.Type+n.Label] {
				continue
			}
			seen[n.Type+n.Label] = true
			switch n.Type {
			case "asset":
				d.Hosts = append(d.Hosts, n.Label)
			case "process":
				d.Processes = append(d.Processes, n.Label)
			}
		}
		sort.Strings(d.Hosts)
		sort.Strings(d.Processes)
	}

	alerts, err := db.Alert.Query().
		Where(alert.IncidentIDEQ(id)).
		Order(ent.Asc(alert.FieldTs)).
		Limit(500).
		WithEvent().
		All(ctx)
	if err != nil {
		return reportData{}, err
	}
	for _, a := range alerts {
		rule := a.RuleID
		if title := rules.TitleOf(a.RuleID); title != "" {
			rule = title
		}
		evidence := ""
		if a.Edges.Event != nil {
			evidence = string(a.Edges.Event.Raw)
		}
		d.Alerts = append(d.Alerts, reportAlert{
			Ts: a.Ts, LastTs: a.LastTs, Count: a.Count, Severity: a.Severity,
			Rule: rule, Evidence: evidence,
		})
	}

	cmds, err := db.Command.Query().
		Where(entcommand.IncidentIDEQ(id)).
		Order(ent.Asc(entcommand.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return reportData{}, err
	}
	for _, c := range cmds {
		rc := reportCommand{
			CreatedAt: c.CreatedAt, Kind: c.Kind, Status: c.Status,
			DryRun: c.DryRun, IssuedBy: c.IssuedBy,
		}
		if c.Detail != nil {
			rc.Detail = *c.Detail
		}
		d.Commands = append(d.Commands, rc)
	}
	return d, nil
}

package triage

import (
	"encoding/json"
	"fmt"
)

type actionDefinition struct {
	Code    string `json:"code"`
	Verdict string `json:"verdict,omitempty"`
	Text    string `json:"text"`
}

var actionDefinitions = []actionDefinition{
	{Code: "verify_source", Text: "在现有权限范围内，向相关资产负责人逐一核实本事件涉及资产及证据中各客户端的应用归属、变更授权与业务用途，分别记录可核验的依据；不把转发器或一个客户端的归属结论套用到其他客户端。"},
	{Code: "collect_original_records", Text: "由人工从可用的原始日志来源补取完整记录；平台事件检索的 raw 模式只改变搜索范围，不能取消正文裁剪或扩大返回上限。"},
	{Code: "trace_process", Text: "核实事件中的 process_guid 后查询进程血缘；查询失败或记录缺失时由人工补证，不把缺失当作无父进程。"},
	{Code: "inspect_history", Text: "查询本事件涉及资产的告警历史和最近采集状态，核对时间范围；最近状态不能证明事发时的采集覆盖。"},
	{Code: "inspect_baseline", Text: "按资产与完整程序路径查询 UEBA 基线；基线首次记录不是安装时间或实际首次执行时间，未命中仍为未知。"},
	{Code: "monitor", Text: "持续监测本事件相关资产与行为，收集新增证据后重新研判。"},
	{Code: "preserve_evidence", Text: "保留本事件的日志和相关现场证据，供后续调查复核。"},
	{Code: "review_closure", Verdict: "benign", Text: "由分析师核对本次操作的合法依据后决定是否良性结案；本次结论不扩展为长期白名单或未来授权。"},
	{Code: "review_response", Verdict: "malicious", Text: "由授权人员核对本事件已确认受影响的资产与目标，审核隔离、阻断、清除及凭据保护等响应方案；执行仍须满足现有权限、审批和审计要求。"},
	{Code: "hunt_related", Verdict: "malicious", Text: "使用本事件已确认的指标排查其他资产；缺失的程序哈希等指标须先获取验证，不把暂存文件哈希当作程序哈希，不预判其他资产已受影响。"},
}

// ActionContract 与实际校验和生成文案共用同一份定义。
func ActionContract() string {
	raw, _ := json.Marshal(actionDefinitions)
	return string(raw)
}

// bindActions 新结论不接收模型自写的建议文案，历史存档不经过此入口。
func bindActions(verdict map[string]any) error {
	if _, exists := verdict["actions"]; exists {
		return fmt.Errorf("actions 由服务端生成，只能提交 action_codes")
	}
	codes, ok := verdict["action_codes"].([]any)
	if !ok || len(codes) == 0 || len(codes) > len(actionDefinitions) {
		return fmt.Errorf("action_codes 必须是非空且有界的建议代码数组")
	}
	known := make(map[string]actionDefinition, len(actionDefinitions))
	for _, a := range actionDefinitions {
		known[a.Code] = a
	}
	seen := make(map[string]bool)
	actions := make([]string, 0, len(codes))
	for _, value := range codes {
		code, ok := value.(string)
		definition, exists := known[code]
		if !ok || !exists || seen[code] {
			return fmt.Errorf("建议代码无效或重复")
		}
		if definition.Verdict != "" && verdict["verdict"] != definition.Verdict {
			return fmt.Errorf("建议代码与结论不匹配")
		}
		seen[code] = true
		actions = append(actions, definition.Text)
	}
	verdict["actions"] = actions
	return nil
}

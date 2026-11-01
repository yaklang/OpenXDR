// Package decoy 保留平台部署与观察复核策略；载体实现位于独立引擎模块。
package decoy

import "openxdr/server/deception/contract"

type Profile = contract.Profile
type Manifest = contract.Manifest
type Observation = contract.Observation

var Profiles = contract.Profiles
var Lookup = contract.Lookup
var ValidEvent = contract.ValidEvent

const LeaseTTL = contract.LeaseTTL

// ObservationRulePrefix 是人工提交观察的保留规则前缀，不能单独触发自动隔离。
const ObservationRulePrefix = "decoy.observation."

// AutoReview 判断观察是否直接开单：只有标记命中，访问与打开噪声大（扫描、杀毒、备份），仍由人工提交。
func AutoReview(kind string) bool {
	return kind == "marker_used" || kind == "ssh_marker_followed" || kind == "dygk_triggered"
}

func ReviewSeverity(kind string) (int16, bool) {
	switch kind {
	case "marker_used", "ssh_marker_followed", "dygk_triggered":
		return 3, true
	case "http_page", "file_opened", "shell_started", "shell_action", "ssh_authentication_attempt", "ssh_marker_rejected":
		return 2, true
	}
	return 0, false
}

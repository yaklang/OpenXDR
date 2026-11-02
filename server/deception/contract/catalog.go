// Package contract 定义独立欺骗引擎的版本化能力与事实契约。
package contract

import (
	"fmt"
	"time"
)

type Profile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Layer    string `json:"layer"`
	Template string `json:"template"`
	Evidence string `json:"evidence"`
	Kind     string `json:"kind"`
}

func Profiles() []Profile {
	var out []Profile
	for _, kind := range []string{"ssh", "http", "file", "shell"} {
		for _, p := range SSHProfiles() {
			version := p.Template
			if kind != "ssh" {
				version = kind + "-" + p.ID + "-v1"
			}
			evidence := p.Evidence
			if kind != "ssh" {
				evidence = "此载体尚未进行模型效果验收；事件只记录访问事实"
			}
			out = append(out, Profile{p.ID, p.Name, p.Layer, version, evidence, kind})
		}
	}
	return out
}
func Lookup(kind, id string) (Profile, error) {
	for _, p := range Profiles() {
		if p.Kind == kind && p.ID == id {
			return p, nil
		}
	}
	return Profile{}, fmt.Errorf("未知载体或策略")
}

var sshProfiles = [...]Profile{
	{ID: "decoy", Name: "诱饵识别", Layer: "decoy", Template: "identify-v1", Evidence: "只记录同一诱饵的有效标记使用；不能据此确认 AI 身份"},
	{ID: "pause", Name: "暂停注入", Layer: "injection", Template: "operator-close-v1", Evidence: "GLM + BoxPwnr 靶场重复观察到暂停；服务端不能独立确认模型已暂停"},
	{ID: "padding", Name: "输出填充", Layer: "padding", Template: "padding-8k-v1", Evidence: "固定 8 KiB 原创文本；不混入指令，尚未验证独立拖延效果"},
}

func SSHProfiles() []Profile {
	return append([]Profile(nil), sshProfiles[:]...)
}

type Manifest struct {
	AssetID  string `json:"assetId"`
	GroupID  string `json:"groupId"`
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Profile  string `json:"profile"`
	Template string `json:"template"`
	Port     int    `json:"port"`
	Resource string `json:"resource"`
	Marker   string `json:"marker"`
}
type Observation struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// 不接收 IP、密码、用户名、命令原文或任意工具输出。
}

func ValidEvent(carrier, event string) bool {
	switch carrier {
	case "ssh":
		return event == "ssh_banner_prepared" || event == "ssh_authentication_attempt" || event == "ssh_marker_followed" || event == "ssh_marker_rejected" || event == "ssh_marker_unavailable"
	case "http":
		return event == "http_page" || event == "marker_used"
	case "file":
		return event == "file_installed" || event == "file_removed" || event == "file_opened"
	case "shell":
		return event == "shell_started" || event == "shell_action" || event == "marker_used"
	}
	return false
}

// SampleWindow 内同类访问事件只上报一条。爆破与爬虫每秒能产生多条事件，
// 逐条上报几分钟就会耗尽每日 1000 条配额，触发上报失败停服；首条仍立即上报。
// 最坏情况每类每日 144 条，单载体可抽样事件不超过 4 类，留在配额以内。
const SampleWindow = 10 * time.Minute

// Sampled 判断事件是否只抽样上报；标记命中与文件安装、删除等生命周期事件逐条上报。
func Sampled(event string) bool {
	switch event {
	case "http_page", "file_opened", "shell_action", "ssh_banner_prepared", "ssh_authentication_attempt", "ssh_marker_rejected", "ssh_marker_unavailable":
		return true
	}
	return false
}

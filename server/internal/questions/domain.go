package questions

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// sharedDomains 共享托管、外带（OAST）与隧道类域：同一父域下是互不相干的租户（客户的一个 COS 桶、谁都能注册的外带子域），
// 这些域及其所有子域只能按完整主机名授权，不提供父域范围——授权客户的一个桶不能变成授权整个云厂商。
// 有意写死在代码里不做成可配置：放宽它等于放宽授权口径，要走代码评审
var sharedDomains = []string{
	// 云对象存储与托管
	"myqcloud.com", "aliyuncs.com", "amazonaws.com", "cloudfront.net", "azureedge.net", "windows.net",
	"googleapis.com", "appspot.com", "herokuapp.com", "vercel.app", "netlify.app", "github.io",
	// 隧道
	"trycloudflare.com", "ngrok.io", "ngrok-free.app",
	// 外带 / 回连探测
	"oast.pro", "oast.fun", "oast.live", "oast.site", "oast.online", "oast.me", "interact.sh",
	"requestrepo.com", "burpcollaborator.net", "dnslog.cn", "ceye.io", "webhook.site", "pipedream.net",
}

// Shared 主机名是否落在共享托管、外带或隧道类域下
func Shared(host string) bool {
	for _, d := range sharedDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// RegistrableDomain 注册域，只用于界面分组展示；拿不到时返回主机名本身
func RegistrableDomain(host string) string {
	if root, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return root
	}
	return host
}

// DomainScopes 作答可选的父域范围：从上一级父域逐级往上取到注册域为止；共享类域一个都不给
func DomainScopes(host string) []string {
	if Shared(host) {
		return nil
	}
	root := RegistrableDomain(host)
	var out []string
	for d := host; d != root; {
		_, parent, ok := strings.Cut(d, ".")
		if !ok || !strings.HasSuffix(parent, root) {
			break
		}
		out = append(out, parent)
		d = parent
	}
	return out
}

// treeSubjects 能覆盖这个主机名的「父域及其全部子域」事实主题：主机名自身与作答时可能选出的父域，
// 后缀链只往上、不往下：父域事实能答子域问题，反过来不行；共享类域没有父域范围
func treeSubjects(kind, host string) []string {
	if Shared(host) {
		return nil
	}
	// 「x 及其全部子域」也覆盖 x 本身
	out := []string{FactSubject(kind, "domain-tree", host)}
	for _, d := range DomainScopes(host) {
		out = append(out, FactSubject(kind, "domain-tree", d))
	}
	return out
}

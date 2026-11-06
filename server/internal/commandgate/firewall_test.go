package commandgate

import "testing"

func TestFirewallQueries(t *testing.T) {
	for _, cmd := range []string{
		"iptables -S", "iptables -L -n -v", "iptables -t nat -nvL",
		"ip6tables --list", "iptables-nft -t filter -S INPUT",
		"iptables-legacy -L INPUT --line-numbers", "nft list ruleset",
		"nft -a list table inet filter", "nft -nn list chain ip filter INPUT",
		"nft list set inet filter allowed_ips", "nft list tables",
		"iptables -S | grep DROP", "pct exec 203 -- nft list ruleset",
	} {
		if !ReadOnly(cmd) {
			t.Errorf("只读查询被拒：%s", cmd)
		}
	}
	for _, cmd := range []string{
		"iptables", "iptables -t nat", "iptables -L -Z", "iptables -nvL -Z",
		"iptables -S -F", "iptables -P INPUT ACCEPT", "iptables -A INPUT -j ACCEPT",
		"iptables -L --modprobe /tmp/helper", "iptables -L -M /tmp/helper",
		"iptables --list --zero", "iptables -S --unknown", "iptables -t",
		"iptables -S; reboot", "iptables -S > /tmp/rules", "iptables -L $(reboot)",
		"nft -f /tmp/rules", "nft -i", "nft list ruleset flush ruleset",
		"nft list table inet 'filter;flush ruleset'", "nft reset counters",
		"nft -a delete rule inet filter INPUT handle 1", "nft --debug all list ruleset",
		"nft list chain inet filter", "pct exec 203 -- nft flush ruleset",
		"docker exec db psql -c 'select 1'",
	} {
		if ReadOnly(cmd) {
			t.Errorf("写入或未知参数被放行：%s", cmd)
		}
	}
}

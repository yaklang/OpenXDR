package commandgate

import "testing"

// 硬拒绝只认命令位置上的写法：切断平台、毁证据的拦下，查询里出现同样的词不受影响
func TestHardDenied(t *testing.T) {
	denied := []string{
		"systemctl stop openxdr-agent",
		"sudo systemctl disable --now openxdr-agent.service",
		"pkill -f openxdr-agent",
		"rm -f /usr/local/bin/openxdr-agent",
		"Stop-Service OpenXDRAgent",
		"reboot",
		"echo bye; /usr/sbin/shutdown -h now",
		"sudo -n poweroff",
		"systemctl reboot",
		"Restart-Computer -Force",
		"journalctl --vacuum-time=1s",
		"truncate -s0 /var/log/auth.log",
		"cat /dev/null > /var/log/syslog",
		"history -c",
		"auditctl -D",
		"wevtutil cl Security",
		"iptables -F",
		"nft flush ruleset",
		"ufw disable",
		"mkfs.ext4 /dev/sdb1",
		"dd if=/dev/zero of=/dev/sda bs=1M",
		"rm -rf /",
		"rm -rf --no-preserve-root /",
	}
	for _, cmd := range denied {
		if hardDenied(cmd) == "" {
			t.Errorf("应硬拒绝: %q", cmd)
		}
	}
	allowed := []string{
		"last reboot | head",
		"systemctl status openxdr-agent",
		"journalctl -u openxdr-agent --since -1h",
		"grep -i shutdown /var/log/syslog | tail",
		"ls -la /var/log",
		"iptables -S",
		"nft list ruleset",
		"ufw status",
		"cat /etc/sudoers.d/90-cloud-init-users",
		"cp /etc/sudoers.d/90-cloud /root/backup/ && visudo -cf /etc/sudoers.d/90-cloud",
		"rm -rf /tmp/openxdr-test-xyz",
		"df -h /",
		"Get-Service OpenXDRAgent",
	}
	for _, cmd := range allowed {
		if why := hardDenied(cmd); why != "" {
			t.Errorf("不应硬拒绝 %q（%s）", cmd, why)
		}
	}
}

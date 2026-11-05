package triage

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/commandgate"
)

func TestParseStrictAgentContainerAndReadOnlyTemplates(t *testing.T) {
	rt, uid, err := parseStrictAgentContainer(json.RawMessage(`{"container":{"runtime":"docker","uid":"978b4e7c6f53","name":"ctf0-web"}}`))
	if err != nil || rt != "docker" || uid != "978b4e7c6f53" {
		t.Fatalf("合法 12 位 docker 容器解析失败: rt=%q uid=%q err=%v", rt, uid, err)
	}
	fullHex := strings.Repeat("a1b2c3d4", 8)
	rt, uid, err = parseStrictAgentContainer(json.RawMessage(`{"container":{"runtime":"docker","uid":"` + fullHex + `"}}`))
	if err != nil || rt != "docker" || uid != fullHex {
		t.Fatalf("合法 64 位 docker 容器解析失败: rt=%q uid=%q err=%v", rt, uid, err)
	}
	rt, uid, err = parseStrictAgentContainer(json.RawMessage(`{"container":{"runtime":"lxc","uid":"203","name":"gateway"}}`))
	if err != nil || rt != "lxc" || uid != "203" {
		t.Fatalf("合法 lxc 容器解析失败: rt=%q uid=%q err=%v", rt, uid, err)
	}

	for _, bad := range []string{
		`{}`,
		`{"container":null}`,
		`{"container":{"runtime":"lxc","name":"gateway"}}`,
		`{"container":{"runtime":"lxc","uid":"gateway"}}`,
		`{"container":{"runtime":"lxc","uid":"0203"}}`,
		`{"container":{"runtime":"lxc","uid":"203; id"}}`,
		`{"container":{"runtime":"lxc","uid":"-203"}}`,
		`{"container":{"runtime":"docker","uid":"ctf0-web"}}`,
		`{"container":{"runtime":"docker","uid":"978B4E7C6F53"}}`,
		`{"container":{"runtime":"docker","uid":"978b4e7c"}}`,
		`{"container":{"runtime":"docker","uid":"978b4e7c6f53a"}}`,
		`{"container":{"runtime":"docker","uid":"978b4e7c6f53 --privileged"}}`,
		`{"container":{"runtime":"qemu","uid":"108"}}`,
	} {
		if _, _, err := parseStrictAgentContainer(json.RawMessage(bad)); err == nil {
			t.Fatalf("非法或不安全容器元数据必须被拒绝: %s", bad)
		}
	}

	for _, cmd := range []string{
		"journalctl --no-pager --utc -n 40 --since '2026-11-01 09:59:27 UTC' --until '2026-11-01 11:44:31 UTC' -u ssh -u sshd -t sshd -t sudo -t su",
		"pct exec 203 -- journalctl --no-pager --utc -n 40 --since '2026-11-01 09:59:27 UTC' --until '2026-11-01 10:29:27 UTC' -u ssh -u sshd",
		"journalctl --no-pager --utc -n 25 --since '2026-11-05 05:45:00 UTC' --until '2026-11-05 06:15:00 UTC' -u apt-daily.service -u apt-daily-upgrade.service -u unattended-upgrades.service -u packagekit.service && tail -n 30 /var/log/dpkg.log /var/log/apt/history.log",
		"docker logs --timestamps --since '2026-11-05T05:45:00Z' --until '2026-11-05T06:15:00Z' --tail 40 978b4e7c6f53",
		"pct exec 203 -- journalctl --no-pager --utc -n 40 --since '2026-11-01 09:59:27 UTC' --until '2026-11-01 11:44:31 UTC' -u caddy -u nginx -u apache2 -u httpd",
	} {
		if !commandgate.ReadOnly(cmd) {
			t.Fatalf("受控模板命令必须通过 commandgate.ReadOnly: %s", cmd)
		}
		if strings.Contains(cmd, "2>/dev/null") || strings.Contains(cmd, "|| true") {
			t.Fatalf("受控模板不得吞掉错误流或退出码: %s", cmd)
		}
	}

	incID := uuid.New()
	assetID := uuid.New()
	idPkg := EndpointEvidenceCommandID(incID, "100", 1, assetID, TemplateLinuxPackageHistory)
	idWeb := EndpointEvidenceCommandID(incID, "100", 1, assetID, TemplateLinuxContainerWebLogs)
	if idPkg == idWeb {
		t.Fatal("不同模板的确定性 CommandID 必须互不冲突")
	}

	// 验证 journal 模板派生 @utc-v2 新 ID，而 ps 快照与 Docker RFC3339Z 保持原 legacy ID
	for _, tpl := range []string{TemplateLinuxAuthJournal, TemplateLinuxPackageHistory, TemplateLinuxContainerWebLogs} {
		leg := LegacyEndpointEvidenceCommandID(incID, "100", 1, assetID, tpl)
		cur := EndpointEvidenceCommandID(incID, "100", 1, assetID, tpl, "pct exec 203 -- journalctl --no-pager")
		if leg == cur {
			t.Fatalf("journal 模板 %s 必须派生区别于旧错窗指令的 @utc-v2 ID", tpl)
		}
	}
	legPS := LegacyEndpointEvidenceCommandID(incID, "100", 1, assetID, TemplateLinuxProcessSnapshot)
	curPS := EndpointEvidenceCommandID(incID, "100", 1, assetID, TemplateLinuxProcessSnapshot, "ps -eo pid,ppid,user,lstart,args --no-headers")
	if legPS != curPS {
		t.Fatal("ps 进程快照无时区窗口问题，CommandID 应保持不变")
	}
	legDocker := LegacyEndpointEvidenceCommandID(incID, "100", 1, assetID, TemplateLinuxContainerWebLogs)
	curDocker := EndpointEvidenceCommandID(incID, "100", 1, assetID, TemplateLinuxContainerWebLogs, "docker logs --timestamps --since '2026-11-05T05:45:00Z' --until '2026-11-05T06:15:00Z' --tail 40 978b4e7c6f53")
	if legDocker != curDocker {
		t.Fatal("Docker logs 使用 RFC3339Z，CommandID 应保持不变")
	}

	hostAuthID := EndpointEvidenceCommandID(incID, "100", 1, assetID, TemplateLinuxAuthJournal, "journalctl --no-pager --utc -n 40")
	lxcAuthID := EndpointEvidenceCommandID(incID, "100", 1, assetID, TemplateLinuxAuthJournal, "pct exec 203 -- journalctl --no-pager --utc -n 40")
	if hostAuthID == lxcAuthID {
		t.Fatal("LXC 容器认证日志模板必须与宿主机认证日志模板派生不同 CommandID")
	}
	evID1, evID2 := uuid.New(), uuid.New()
	anchored1 := EndpointEvidenceCommandIDWithAnchor(incID, "100", 1, assetID, TemplateLinuxAuthJournal, &evID1, "journalctl --no-pager --utc -n 40")
	anchored2 := EndpointEvidenceCommandIDWithAnchor(incID, "100", 1, assetID, TemplateLinuxAuthJournal, &evID2, "journalctl --no-pager --utc -n 40")
	if anchored1 == hostAuthID || anchored1 == anchored2 {
		t.Fatal("带 event_id 锚点的取证指令必须与无锚点及不同 event_id 的指令 ID 区分")
	}

	hasC, _, _, err := parseOptionalStrictAgentContainer(json.RawMessage(`{"process":{"name":"sshd"}}`))
	if err != nil || hasC {
		t.Fatalf("宿主机事件（无 container 字段）应解析为 hasContainer=false, err=nil，实得 hasC=%v err=%v", hasC, err)
	}
	hasC, rt, uid, err = parseOptionalStrictAgentContainer(json.RawMessage(`{"container":{"runtime":"lxc","uid":"203"}}`))
	if err != nil || !hasC || rt != "lxc" || uid != "203" {
		t.Fatalf("LXC 容器事件解析异常: hasC=%v rt=%q uid=%q err=%v", hasC, rt, uid, err)
	}
	if _, _, _, err := parseOptionalStrictAgentContainer(json.RawMessage(`{"container":{"runtime":"lxc","uid":"203; id"}}`)); err == nil {
		t.Fatal("包含非法 container 字段的事件必须 fail-closed 报错")
	}
}

func TestJournalUTCTimeLayoutParsedAsUTCInAsiaShanghai(t *testing.T) {
	ts := time.Date(2026, 11, 1, 9, 59, 27, 0, time.UTC)
	formatted := ts.UTC().Format(journalUTCTimeLayout)
	if formatted != "2026-11-01 09:59:27 UTC" {
		t.Fatalf("journalUTCTimeLayout 格式化错误: got=%q", formatted)
	}
	if _, err := exec.LookPath("systemd-analyze"); err != nil {
		t.Skip("systemd-analyze 不可用")
	}
	cmd := exec.Command("systemd-analyze", "timestamp", formatted)
	cmd.Env = append(os.Environ(), "TZ=Asia/Shanghai")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("systemd-analyze 解析失败: %v\n%s", err, string(out))
	}
	wantEpoch := fmt.Sprintf("UNIX seconds: @%d", ts.Unix())
	if !strings.Contains(string(out), wantEpoch) || !strings.Contains(string(out), "(in UTC): Sun 2026-11-01 09:59:27 UTC") {
		t.Fatalf("TZ=Asia/Shanghai 下未按 UTC 解析 journal 时间戳:\nwant: %s\ngot:\n%s", wantEpoch, string(out))
	}
}

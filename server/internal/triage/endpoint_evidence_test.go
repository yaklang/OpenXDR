package triage

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"openxdr/server/internal/commandgate"
)

func TestParseStrictAgentContainerAndReadOnlyTemplates(t *testing.T) {
	rt, uid, err := parseStrictAgentContainer(json.RawMessage(`{"container":{"runtime":"docker","uid":"978b4e7c6f53","name":"ctf0-web"}}`))
	if err != nil || rt != "docker" || uid != "978b4e7c6f53" {
		t.Fatalf("合法 docker 容器解析失败: rt=%q uid=%q err=%v", rt, uid, err)
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
		`{"container":{"runtime":"docker","uid":"978b4e7c6f53 --privileged"}}`,
		`{"container":{"runtime":"qemu","uid":"108"}}`,
	} {
		if _, _, err := parseStrictAgentContainer(json.RawMessage(bad)); err == nil {
			t.Fatalf("非法或不安全容器元数据必须被拒绝: %s", bad)
		}
	}

	for _, cmd := range []string{
		"journalctl --no-pager --utc -n 25 --since '2026-11-05 05:45:00' --until '2026-11-05 06:15:00' -u apt-daily.service -u apt-daily-upgrade.service -u unattended-upgrades.service -u packagekit.service && tail -n 30 /var/log/dpkg.log /var/log/apt/history.log",
		"docker logs --timestamps --since '2026-11-05T05:45:00Z' --until '2026-11-05T06:15:00Z' --tail 40 978b4e7c6f53",
		"pct exec 203 -- journalctl --no-pager --utc -n 40 --since '2026-11-05 05:45:00' --until '2026-11-05 06:15:00' -u caddy -u nginx -u apache2 -u httpd",
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
}

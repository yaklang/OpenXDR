package questions

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/schema"
)

func TestPlatformIndexEndpointsAndComponentRoles(t *testing.T) {
	idx := newPlatformIndex()
	idx.addEndpoint("10.1.1.199:8081", "采集接入端点 / VIP")
	idx.addEndpoint("https://xdr.internal.yuzhian.com.cn", "控制台入口")
	idx.addEndpoint("10.1.1.199/32,10.1.1.0/24,127.0.0.1:8080,localhost:8080,http://sandbox:8090", "服务端接入端点 / VIP")
	idx.addEndpoint("nats://10.1.1.198:4222,nats://10.1.1.201:4222", "NATS 事件队列 / 见证节点")

	if !slices.Contains(idx.ips["10.1.1.199"], "采集接入端点 / VIP") || !slices.Contains(idx.ips["10.1.1.199"], "服务端接入端点 / VIP") {
		t.Fatalf("VIP 地址与 /32 单机掩码应被识别：%v", idx.ips["10.1.1.199"])
	}
	for _, excluded := range []string{"10.1.1.0", "127.0.0.1"} {
		if len(idx.ips[excluded]) > 0 {
			t.Fatalf("网段与回环地址不应误判为平台自身地址：%s -> %v", excluded, idx.ips[excluded])
		}
	}
	if !slices.Contains(idx.domains["xdr.internal.yuzhian.com.cn"], "控制台入口") {
		t.Fatalf("控制台域名应被识别：%v", idx.domains)
	}
	if len(idx.domains["localhost"]) > 0 || len(idx.domains["sandbox"]) > 0 {
		t.Fatalf("本机与单标签容器名不应进入公有域名索引：%v", idx.domains)
	}

	serverNode := &ent.Asset{
		ID:        uuid.New(),
		Hostname:  "openxdr-node1",
		IPAddrs:   []string{"10.1.1.198", "10.1.1.199"},
		Listening: json.RawMessage(`[{"port":8080,"proto":"tcp","process":"openxdr-server"}]`),
	}
	roles, _ := assetComponentRoles(serverNode)
	if !slices.Equal(roles, []string{"OpenXDR Server 节点"}) {
		t.Fatalf("openxdr-server 监听进程应识别为 Server 节点：%v", roles)
	}

	witness := &ent.Asset{
		ID:         uuid.New(),
		Hostname:   "openxdr-sandbox",
		IPAddrs:    []string{"10.1.1.201"},
		Listening:  json.RawMessage(`[{"port":8090,"proto":"tcp","process":"sandboxd"}]`),
		Containers: json.RawMessage(`[{"name":"openxdr-witness","addrs":["172.18.0.2"]}]`),
	}
	wRoles, cAddrs := assetComponentRoles(witness)
	if !slices.Contains(wRoles, "OpenXDR Pi 沙箱节点（sandboxd）") || !slices.Contains(wRoles, "OpenXDR NATS/etcd 见证节点") {
		t.Fatalf("沙箱与见证容器均应识别：%v", wRoles)
	}
	if !slices.Equal(cAddrs, []string{"172.18.0.2"}) {
		t.Fatalf("见证容器地址应提取：%v", cAddrs)
	}
}

func TestMergeEvidenceKeepsPinnedFactAcrossWindowOverflow(t *testing.T) {
	now := time.Now()
	pinned := []schema.QuestionEvidence{{
		At:     now,
		Source: "fact",
		Ref:    "F-12345678",
		Note:   "已登记钥匙归属：持有人 Foghaven 凯伊，用途：常驻树莓派运维",
	}}
	var cur []schema.QuestionEvidence
	for i := 0; i < 25; i++ {
		tail := schema.QuestionEvidence{At: now.Add(time.Duration(i) * time.Minute), Source: "ask_controller", Note: fmt.Sprintf("ask-%d", i)}
		cur, _ = mergeEvidence(cur, pinned, &tail)
	}
	if len(cur) != maxEvidence {
		t.Fatalf("证据总数应保持在上限 %d：%d", maxEvidence, len(cur))
	}
	if cur[0].Source != "fact" || cur[0].Ref != "F-12345678" {
		t.Fatalf("钥匙归属事实证据应固定在首位且不被滑窗挤掉：%+v", cur[0])
	}
	factCount := 0
	for _, e := range cur {
		if e.Source == "fact" {
			factCount++
		}
	}
	if factCount != 1 {
		t.Fatalf("同一条事实证据不应重复追加：%d", factCount)
	}
}

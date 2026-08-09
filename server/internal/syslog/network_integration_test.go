//go:build integration

package syslog

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"openxdr/server/internal/ingest"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

// freeUDPPort 找一个空闲 UDP 端口：先占用再释放后交给 Server 监听。
func freeUDPPort(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().String()
}

// 端到端：UDP 接入真实打开监听 → 报文解析 → 命中规则 → 事件与告警落库。
func TestSyslogUDPEndToEnd(t *testing.T) {
	ctx, client := testdb.New(t)
	if _, err := client.Asset.Create().SetHostname("web01").SetOs("linux").Save(ctx); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssh.yml"), []byte(sshRule), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		DB:       client,
		Rules:    sigma.LoadDir(dir),
		Addr:     freeUDPPort(t),
		Suppress: suppress.New(client, time.Hour),
		Intel:    intel.New(client, time.Hour),
	}

	ctxRun, cancel := context.WithCancel(ctx)
	go func() { defer cancel(); s.Run(ctxRun) }()
	time.Sleep(300 * time.Millisecond) // 等监听真正建立，UDP 早发即丢

	conn, err := net.Dial("udp", s.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	line := `<34>Oct 11 22:14:15 web01 sshd[123]: Failed password for root from 1.2.3.4`
	if _, err := conn.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		evCount, _ := client.Event.Query().Count(ctx)
		alCount, _ := client.Alert.Query().Count(ctx)
		if evCount >= 1 && alCount >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n, _ := client.Event.Query().Count(ctx); n != 1 {
		t.Fatalf("应落库 1 条事件，实际 %d", n)
	}
	if n, _ := client.Alert.Query().Count(ctx); n != 1 {
		t.Fatalf("应落库 1 条告警，实际 %d", n)
	}
}

// recordBus 记录发布到总线的 Envelope，用于验证 enqueue 的字段组装。
type recordBus struct{ envs []ingest.Envelope }

func (r *recordBus) Publish(_ context.Context, e ingest.Envelope) error {
	r.envs = append(r.envs, e)
	return nil
}
func (r *recordBus) Ready() bool  { return true }
func (r *recordBus) Close() error { return nil }

func TestSyslogEnqueue(t *testing.T) {
	ctx, client := testdb.New(t)
	asset, err := client.Asset.Create().SetHostname("web01").SetOs("linux").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bus := &recordBus{}
	s := &Server{DB: client, Events: bus}

	line := `<13>Oct 11 22:14:15 web01 sshd[123]: Test message`
	if err := s.enqueue(ctx, incoming{line: line, from: net.ParseIP("10.0.0.1")}); err != nil {
		t.Fatal(err)
	}
	if len(bus.envs) != 1 {
		t.Fatalf("应发布 1 条事件，实际 %d", len(bus.envs))
	}
	env := bus.envs[0]
	if env.Source != "syslog" || env.ClassUID != ClassApplicationActivity || env.AssetID == nil || *env.AssetID != asset.ID {
		t.Errorf("事件字段错误: source=%s class=%d asset=%v (want %v)", env.Source, env.ClassUID, env.AssetID, asset.ID)
	}
	if env.PartitionKey != asset.ID.String() {
		t.Errorf("partition_key = %q, want %q", env.PartitionKey, asset.ID)
	}
}

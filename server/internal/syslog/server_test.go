package syslog

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
)

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitTCPReady(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Status().TCPListening {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Syslog TCP 监听未在预期时间内就绪")
}

func TestTCPMaxConnsAndGracefulShutdown(t *testing.T) {
	s := &Server{
		Addr:        freeTCPAddr(t),
		maxConns:    2,
		idleTimeout: 5 * time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	queue := make(chan incoming, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.listenTCP(ctx, queue)
	}()
	waitTCPReady(t, s)

	// 占满 2 个并发连接槽位并确认消息能正常接收
	c1, err := net.Dial("tcp", s.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := net.Dial("tcp", s.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	if _, err := c1.Write([]byte("<13>Oct 11 22:14:15 h1 app: m1\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Write([]byte("<13>Oct 11 22:14:15 h2 app: m2\n")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-queue:
		case <-time.After(time.Second):
			t.Fatal("前两条合法 TCP 连接的消息未被接收")
		}
	}

	// 第 3 条连接超出上限：服务端立即关闭，客户端读应返回 EOF/错误
	c3, err := net.Dial("tcp", s.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	_ = c3.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := c3.Read(buf); err == nil {
		t.Fatal("超过并发连接上限的新连接应被立即关闭")
	}

	// 停机取消 context：活跃连接 c1/c2 应被关闭，listenTCP 必须尽快返回不泄漏 goroutine
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("停机后 listenTCP 未能关闭活跃连接并退出")
	}
	_ = c1.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c1.Read(buf); err != io.EOF && err == nil {
		t.Fatalf("停机后活跃连接应已关闭，err=%v", err)
	}
}

func TestTCPIdleTimeoutClosesConn(t *testing.T) {
	s := &Server{
		Addr:        freeTCPAddr(t),
		maxConns:    4,
		idleTimeout: 100 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := make(chan incoming, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.listenTCP(ctx, queue)
	}()
	waitTCPReady(t, s)

	c, err := net.Dial("tcp", s.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// 不发任何数据，等待超过 idleTimeout 后服务端主动断开
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("空闲超时的 TCP 连接应被服务端关闭")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("listenTCP 退出超时")
	}
}

func TestResolveAssetPrefersSourceIPOverSpoofedHostname(t *testing.T) {
	webID := uuid.New()
	attackerID := uuid.New()
	relayID := uuid.New()

	s := &Server{
		TrustedRelays: []string{"10.0.0.250"},
	}
	s.assets.at = time.Now()
	s.assets.byHost = map[string]assetRef{
		"web01":    {id: webID, os: "linux"},
		"attacker": {id: attackerID, os: "linux"},
		"relay01":  {id: relayID, os: "linux"},
	}
	s.assets.byIP = map[string]assetRef{
		"10.0.0.10":  {id: webID, os: "linux"},
		"10.0.0.99":  {id: attackerID, os: "linux"},
		"10.0.0.250": {id: relayID, os: "linux"},
	}

	// 已纳管主机 attacker 伪造 hostname=web01：源 IP 优先，仍归属 attacker
	id, _ := s.resolveAsset(context.Background(), "web01", net.ParseIP("10.0.0.99"))
	if id == nil || *id != attackerID {
		t.Fatalf("已知主机伪造 hostname 应按源 IP 归属 attacker(%s)，实际 %v", attackerID, id)
	}

	// 受信转发器 10.0.0.250 转发 web01 日志：允许按报文 hostname 归属 web01
	id, _ = s.resolveAsset(context.Background(), "web01", net.ParseIP("10.0.0.250"))
	if id == nil || *id != webID {
		t.Fatalf("受信转发器应按 hostname 归属 web01(%s)，实际 %v", webID, id)
	}

	// 未在资产表登记的来源 IP：回退按 hostname 归属
	id, _ = s.resolveAsset(context.Background(), "web01", net.ParseIP("10.0.0.200"))
	if id == nil || *id != webID {
		t.Fatalf("未登记源 IP 应回退按 hostname 归属 web01(%s)，实际 %v", webID, id)
	}
}

//go:build integration

package syslog

import (
	"net"
	"openxdr/server/internal/authfields"
	"openxdr/server/internal/testdb"
	"testing"
)

func TestSSHSourceSurvivesEnqueue(t *testing.T) {
	ctx, client := testdb.New(t)
	client.Asset.Create().SetHostname("source-test").SetOs("linux").SaveX(ctx)
	bus := &recordBus{}
	s := &Server{DB: client, Events: bus}
	line := `<34>Oct 11 22:14:15 source-test sshd[7]: Failed password for lab from 192.0.2.8 port 2345 ssh2`
	if err := s.enqueue(ctx, incoming{line: line, from: net.ParseIP("198.51.100.99")}); err != nil {
		t.Fatal(err)
	}
	if len(bus.envs) != 1 || authfields.SourceIP(bus.envs[0].Raw) != "192.0.2.8" {
		t.Fatal("攻击源丢失或被传输对端覆盖")
	}
}

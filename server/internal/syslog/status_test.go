package syslog

import (
	"errors"
	"testing"
)

func TestStatus(t *testing.T) {
	s := &Server{Addr: ":514"}
	queue := make(chan incoming, 1)
	s.receive(queue, incoming{line: "one"})
	s.receive(queue, incoming{line: "two"})
	s.published(nil)
	s.published(errors.New("unavailable"))
	s.unassigned()
	s.listening(true, false, errors.New("bind failed"))
	s.listening(false, true, nil)
	got := s.Status()
	if got.Received != 2 || got.Dropped != 1 || got.Published != 1 || got.Failed != 1 || got.Unassigned != 1 || got.LastReceived == nil {
		t.Fatalf("计数不符: %+v", got)
	}
	if got.TCPListening || got.TCPError != "bind failed" || !got.UDPListening || got.Address != ":514" {
		t.Fatalf("监听状态不符: %+v", got)
	}
	s.listening(true, true, nil)
	if got := s.Status(); !got.TCPListening || got.TCPError != "" {
		t.Fatalf("恢复监听后应清除旧错误: %+v", got)
	}
}

package syslog

import (
	"sync"
	"time"
)

// Status 是当前节点自启动以来的接收状态；收到报文与成功入队分别计数。
type Status struct {
	Address      string     `json:"address"`
	UDPListening bool       `json:"udpListening"`
	TCPListening bool       `json:"tcpListening"`
	UDPError     string     `json:"udpError,omitempty"`
	TCPError     string     `json:"tcpError,omitempty"`
	Received     uint64     `json:"received"`
	Dropped      uint64     `json:"dropped"`
	Published    uint64     `json:"published"`
	Failed       uint64     `json:"failed"`
	Unassigned   uint64     `json:"unassigned"`
	LastReceived *time.Time `json:"lastReceived"`
}

type monitor struct {
	mu     sync.Mutex
	status Status
}

func (s *Server) Status() Status {
	s.monitor.mu.Lock()
	defer s.monitor.mu.Unlock()
	snapshot := s.monitor.status
	snapshot.Address = s.Addr
	return snapshot
}

func (s *Server) listening(tcp, active bool, err error) {
	s.monitor.mu.Lock()
	defer s.monitor.mu.Unlock()
	message := ""
	if err != nil {
		message = err.Error()
	}
	if tcp {
		s.monitor.status.TCPListening, s.monitor.status.TCPError = active, message
	} else {
		s.monitor.status.UDPListening, s.monitor.status.UDPError = active, message
	}
}

func (s *Server) receive(queue chan<- incoming, in incoming) {
	now := time.Now().UTC()
	s.monitor.mu.Lock()
	s.monitor.status.Received++
	s.monitor.status.LastReceived = &now
	select {
	case queue <- in:
	default:
		s.monitor.status.Dropped++
	}
	s.monitor.mu.Unlock()
}

func (s *Server) published(err error) {
	s.monitor.mu.Lock()
	defer s.monitor.mu.Unlock()
	if err != nil {
		s.monitor.status.Failed++
	} else {
		s.monitor.status.Published++
	}
}

func (s *Server) unassigned() {
	s.monitor.mu.Lock()
	defer s.monitor.mu.Unlock()
	s.monitor.status.Unassigned++
}

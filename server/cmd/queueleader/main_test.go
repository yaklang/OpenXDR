package main

import (
	"github.com/nats-io/nats.go"
	"testing"
)

func TestTargetRequiresSyncedOnlineReplica(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cluster *nats.ClusterInfo
		valid   bool
	}{
		{"无Leader", nil, false},
		{"无目标", &nats.ClusterInfo{Leader: "remote"}, false},
		{"掉队", &nats.ClusterInfo{Leader: "remote", Replicas: []*nats.PeerInfo{{Name: "local"}}}, false},
		{"离线", &nats.ClusterInfo{Leader: "remote", Replicas: []*nats.PeerInfo{{Name: "local", Current: true, Offline: true}}}, false},
		{"已同步", &nats.ClusterInfo{Leader: "remote", Replicas: []*nats.PeerInfo{{Name: "local", Current: true}}}, true},
		{"已在其他节点则不迁移", &nats.ClusterInfo{Leader: "other"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateTarget(tc.cluster, "remote", "local"); (err == nil) != tc.valid {
				t.Fatalf("got %v, valid=%v", err, tc.valid)
			}
		})
	}
}

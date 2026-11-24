package main

import (
	"os"
	"strings"
	"testing"
)

// 默认连接池按租约数留余量：leaderLeases 要和 main.go 里实际的 cluster.RunLeader 调用数一致
func TestLeaderLeasesMatchMain(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(src), "cluster.RunLeader("); n != leaderLeases {
		t.Fatalf("main.go 有 %d 处 cluster.RunLeader，leaderLeases 是 %d，增删单活任务后同步改", n, leaderLeases)
	}
}

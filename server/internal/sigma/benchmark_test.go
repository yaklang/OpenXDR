package sigma

import "testing"

// 真实规则集覆盖全小写 Linux、大小写混合 Linux 与 Windows 事件。
func BenchmarkEvaluateRepoRules(b *testing.B) {
	engine, report := LoadDirReport("../../../rules")
	if report.Loaded == 0 || report.Loaded != report.Total {
		b.Fatalf("规则集加载不完整: loaded=%d total=%d", report.Loaded, report.Total)
	}
	for _, tc := range []struct{ name, os, path, command, user string }{
		{"LinuxLower", "linux", "/usr/bin/python3", "python3 /opt/app/worker.py --queue default", "root"},
		{"LinuxMixed", "linux", "/usr/bin/python3", "python3 /opt/App/Worker.py --queue Default", "root"},
		{"WindowsMixed", "windows", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "PowerShell.EXE -NoProfile -EncodedCommand ZWNobyBoaQ==", "Administrator"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			raw := map[string]any{
				"activity_id": 1,
				"process":     map[string]any{"file": map[string]any{"path": tc.path}, "cmd_line": tc.command, "pid": 4242},
				"actor":       map[string]any{"user": map[string]any{"name": tc.user}},
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				engine.Evaluate(1007, tc.os, raw)
			}
		})
	}
}

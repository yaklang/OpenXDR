// sigmacheck 统计一个 Sigma 规则目录的兼容情况：能加载多少条、失败原因分布。
// 用法: go run ./cmd/sigmacheck <规则目录> [失败原因的样例条数]
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"

	"openxdr/server/internal/sigma"
)

// 一条典型的进程创建事件，用于测量单事件过全量规则的成本
const sampleEvent = `{
  "activity_id": 1,
  "process": {
    "pid": 4242,
    "name": "curl",
    "file": {"path": "/usr/bin/curl"},
    "cmd_line": "curl -s https://example.com/payload.sh",
    "parent_process": {"pid": 4200, "cmd_line": "/bin/bash"}
  }
}`

func benchmark(engine *sigma.Engine, rounds int) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(sampleEvent), &raw); err != nil {
		panic(err)
	}
	// 预热，避免首轮的正则惰性初始化混进计时
	engine.Evaluate(1007, "linux", raw)

	start := time.Now()
	hits := 0
	for range rounds {
		hits += len(engine.Evaluate(1007, "linux", raw))
	}
	elapsed := time.Since(start)

	perEvent := elapsed / time.Duration(rounds)
	fmt.Printf("吞吐测量：%d 次匹配耗时 %v，单事件 %v，约 %.0f 事件/秒（命中 %d 次）\n\n",
		rounds, elapsed.Round(time.Millisecond), perEvent.Round(time.Microsecond),
		float64(rounds)/elapsed.Seconds(), hits/rounds)
}

func main() {
	args := os.Args[1:]
	// --strict：有任何规则加载失败就非零退出，用于 CI 守住自带规则
	strict := false
	for i, a := range args {
		if a == "--strict" {
			strict = true
			args = append(args[:i:i], args[i+1:]...)
			break
		}
	}
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "用法: sigmacheck [--strict] <规则目录> [样例条数]")
		os.Exit(2)
	}
	samples := 3
	if len(args) > 1 {
		if n, err := strconv.Atoi(args[1]); err == nil {
			samples = n
		}
	}

	engine, report := sigma.LoadDirReport(args[0])
	rate := 0.0
	if report.Total > 0 {
		rate = float64(report.Loaded) / float64(report.Total) * 100
	}
	fmt.Printf("规则总数 %d，成功加载 %d，兼容率 %.1f%%\n\n", report.Total, report.Loaded, rate)
	benchmark(engine, 2000)

	type row struct {
		reason string
		files  []string
	}
	rows := make([]row, 0, len(report.Skipped))
	for reason, files := range report.Skipped {
		rows = append(rows, row{reason, files})
	}
	sort.Slice(rows, func(i, j int) bool { return len(rows[i].files) > len(rows[j].files) })

	// 能加载 ≠ 能命中：没有对应遥测的规则加载了也只是待命
	classes := make([]int, 0, len(report.ByClass))
	for uid := range report.ByClass {
		classes = append(classes, uid)
	}
	sort.Ints(classes)
	live := 0
	fmt.Println("已加载规则按 OCSF class 分布：")
	for _, uid := range classes {
		count := report.ByClass[uid]
		switch name, ok := sigma.IngestedClass(uid); {
		case uid == 0:
			fmt.Printf("%6d  不限 class（按字段匹配）\n", count)
		case ok:
			live += count
			fmt.Printf("%6d  %d %s\n", count, uid, name)
		default:
			fmt.Printf("%6d  %d 待接入该类遥测\n", count, uid)
		}
	}
	fmt.Printf("\n其中 %d 条有现成数据源可命中\n\n", live)

	fmt.Println("失败原因分布：")
	for _, r := range rows {
		fmt.Printf("%6d  %s\n", len(r.files), r.reason)
		for i, f := range r.files {
			if i >= samples {
				break
			}
			fmt.Printf("          %s\n", f)
		}
	}

	if strict && report.Loaded != report.Total {
		fmt.Fprintf(os.Stderr, "\nstrict: %d 条规则未能加载\n", report.Total-report.Loaded)
		os.Exit(1)
	}
}

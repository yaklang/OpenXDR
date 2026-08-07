// sigmacheck 统计一个 Sigma 规则目录的兼容情况：能加载多少条、失败原因分布。
// 用法: go run ./cmd/sigmacheck <规则目录> [失败原因的样例条数]
package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"

	"openxdr/server/internal/sigma"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "用法: sigmacheck <规则目录> [样例条数]")
		os.Exit(2)
	}
	samples := 3
	if len(os.Args) > 2 {
		if n, err := strconv.Atoi(os.Args[2]); err == nil {
			samples = n
		}
	}

	_, report := sigma.LoadDirReport(os.Args[1])
	rate := 0.0
	if report.Total > 0 {
		rate = float64(report.Loaded) / float64(report.Total) * 100
	}
	fmt.Printf("规则总数 %d，成功加载 %d，兼容率 %.1f%%\n\n", report.Total, report.Loaded, rate)

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
}

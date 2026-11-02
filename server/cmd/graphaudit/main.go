// graphaudit 只读核对指定时间窗的网络事件与资产图谱，不重放、不修改计数。
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"openxdr/server/internal/assetmap"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	sinceFlag := flag.String("since", "", "窗口起点 RFC3339（必填）")
	untilFlag := flag.String("until", "", "窗口终点 RFC3339（必填，不包含）")
	maxEvents := flag.Int("max-events", 100000, "最多核对的事件数，超限失败")
	timeout := flag.Duration("timeout", 2*time.Minute, "整体查询超时")
	replicaOnly := flag.Bool("replica-only", false, "必须连接备库，否则拒绝扫描")
	flag.Parse()
	since, err := time.Parse(time.RFC3339, *sinceFlag)
	if err != nil {
		return fmt.Errorf("需要有效的 -since")
	}
	until, err := time.Parse(time.RFC3339, *untilFlag)
	if err != nil {
		return fmt.Errorf("需要有效的 -until")
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("必须配置 DATABASE_URL")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("无法初始化数据库连接")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	report, err := assetmap.AuditGraph(ctx, db, since, until, *maxEvents, *replicaOnly)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

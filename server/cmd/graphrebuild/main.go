// graphrebuild 从保留的原始网络事件重建图谱，原图随事务备份。
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
	apply := flag.Bool("apply", false, "确认所有工作者已升级维护锁，并按保留窗口重建图谱计数")
	maxEvents := flag.Int("max-events", 100000, "最多扫描的事件数，超限失败")
	timeout := flag.Duration("timeout", 10*time.Minute, "整体查询超时")

	flag.Parse()
	if !*apply {
		return fmt.Errorf("必须显式指定 -apply；先升级全部工作者并完成 graphaudit 核对")
	}
	since, err := time.Parse(time.RFC3339, *sinceFlag)
	if err != nil {
		return fmt.Errorf("需要有效的 -since")
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
	report, err := assetmap.RebuildGraph(ctx, db, since, *maxEvents)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

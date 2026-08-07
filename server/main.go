package main

import (
	"context"
	"database/sql"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"google.golang.org/grpc"

	"openxdr/server/ent"
	"openxdr/server/internal/api"
	"openxdr/server/internal/correlate"
	"openxdr/server/internal/grpcsvc"
	"openxdr/server/internal/janitor"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/syslog"
	"openxdr/server/internal/triage"
	"openxdr/server/pb"
)

func main() {
	ctx := context.Background()

	db, err := sql.Open("pgx", getenv("DATABASE_URL",
		"postgres://openxdr:openxdr@localhost:5432/openxdr?sslmode=disable"))
	if err != nil {
		slog.Error("数据库连接失败", "err", err)
		os.Exit(1)
	}
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	defer client.Close()
	if err := client.Schema.Create(ctx); err != nil {
		slog.Error("schema 迁移失败", "err", err)
		os.Exit(1)
	}

	rules := sigma.LoadDir(getenv("RULES_PATH", "../rules"))

	go (&correlate.Engine{
		DB:            client,
		Rules:         rules,
		Window:        time.Duration(getenvInt("CORRELATE_WINDOW_MINUTES", 30)) * time.Minute,
		Interval:      time.Duration(getenvInt("CORRELATE_INTERVAL_SECONDS", 10)) * time.Second,
		MaxGraphNodes: getenvInt("CORRELATE_MAX_GRAPH_NODES", 500),
	}).Run(ctx)

	go (&janitor.Janitor{
		DB:        client,
		Retention: time.Duration(getenvInt("RETENTION_DAYS", 30)) * 24 * time.Hour,
		Interval:  time.Duration(getenvInt("RETENTION_INTERVAL_MINUTES", 60)) * time.Minute,
	}).Run(ctx)

	go (&triage.Engine{
		DB: client,
		LLM: triage.NewLLM(
			getenv("AI_BASE_URL", "http://localhost:11434/v1"),
			os.Getenv("AI_MODEL"),
			os.Getenv("AI_API_KEY"),
			time.Duration(getenvInt("AI_TIMEOUT_SECONDS", 120))*time.Second,
		),
		Interval: time.Duration(getenvInt("AI_INTERVAL_SECONDS", 30)) * time.Second,
	}).Run(ctx)

	dedupWindow := time.Duration(getenvInt("ALERT_DEDUP_WINDOW_MINUTES", 5)) * time.Minute

	go (&syslog.Server{
		DB:          client,
		Rules:       rules,
		Addr:        os.Getenv("SYSLOG_ADDR"),
		DedupWindow: dedupWindow,
	}).Run(ctx)

	grpcAddr := getenv("GRPC_ADDR", ":8081")
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		slog.Error("gRPC 监听失败", "err", err)
		os.Exit(1)
	}
	tlsOpts, mtls, err := grpcsvc.ServerOptions()
	if err != nil {
		slog.Error("TLS 配置无效", "err", err)
		os.Exit(1)
	}
	if !mtls {
		slog.Warn("gRPC 未启用 mTLS，采集端通信为明文，仅适合本机调试")
	}
	grpcServer := grpc.NewServer(tlsOpts...)
	pb.RegisterAgentServiceServer(grpcServer, &grpcsvc.Server{
		DB:          client,
		Rules:       rules,
		DedupWindow: dedupWindow,
	})
	pb.RegisterSensorServiceServer(grpcServer, &grpcsvc.SensorServer{
		DB:          client,
		Rules:       rules,
		DedupWindow: dedupWindow,
	})
	go func() {
		slog.Info("gRPC 启动", "addr", grpcAddr)
		if err := grpcServer.Serve(lis); err != nil {
			slog.Error("gRPC 退出", "err", err)
			os.Exit(1)
		}
	}()

	httpAddr := getenv("HTTP_ADDR", ":8080")
	slog.Info("HTTP 启动", "addr", httpAddr)
	if err := http.ListenAndServe(httpAddr, api.Handler(client, rules)); err != nil {
		slog.Error("HTTP 退出", "err", err)
		os.Exit(1)
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

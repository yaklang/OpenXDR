package main

import (
	"context"
	"database/sql"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"google.golang.org/grpc"

	"openxdr/server/ent"
	"openxdr/server/internal/api"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/correlate"
	"openxdr/server/internal/grpcsvc"
	"openxdr/server/internal/janitor"
	"openxdr/server/internal/notify"
	"openxdr/server/internal/response"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
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

	suppressions := suppress.New(client, time.Duration(getenvInt("SUPPRESSION_RELOAD_SECONDS", 30))*time.Second)
	go suppressions.Run(ctx)

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

	go (&notify.Notifier{
		DB:         client,
		URL:        os.Getenv("WEBHOOK_URL"),
		Format:     getenv("WEBHOOK_FORMAT", "generic"),
		Interval:   time.Duration(getenvInt("WEBHOOK_INTERVAL_SECONDS", 30)) * time.Second,
		WaitTriage: os.Getenv("AI_MODEL") != "",
		LinkBase:   os.Getenv("WEBHOOK_LINK_BASE"),
	}).Run(ctx)

	dedupWindow := time.Duration(getenvInt("ALERT_DEDUP_WINDOW_MINUTES", 5)) * time.Minute

	go (&syslog.Server{
		DB:          client,
		Rules:       rules,
		Addr:        os.Getenv("SYSLOG_ADDR"),
		DedupWindow: dedupWindow,
		Suppress:    suppressions,
	}).Run(ctx)

	grpcAddr := getenv("GRPC_ADDR", ":8081")
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		slog.Error("gRPC 监听失败", "err", err)
		os.Exit(1)
	}
	hub := response.NewHub(client, os.Getenv("RESPONSE_ENABLED") == "true")

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
		Hub:         hub,
		Suppress:    suppressions,
	})
	pb.RegisterSensorServiceServer(grpcServer, &grpcsvc.SensorServer{
		DB:          client,
		Rules:       rules,
		DedupWindow: dedupWindow,
		Suppress:    suppressions,
	})
	go func() {
		slog.Info("gRPC 启动", "addr", grpcAddr)
		if err := grpcServer.Serve(lis); err != nil {
			slog.Error("gRPC 退出", "err", err)
			os.Exit(1)
		}
	}()

	if err := auth.Bootstrap(ctx, client); err != nil {
		slog.Error("初始化 admin 账号失败", "err", err)
		os.Exit(1)
	}

	httpAddr := getenv("HTTP_ADDR", ":8080")
	slog.Info("HTTP 启动", "addr", httpAddr)
	handler := auth.Middleware(client, api.Handler(client, rules, hub, suppressions, isolationAllowlist()))
	if err := http.ListenAndServe(httpAddr, handler); err != nil {
		slog.Error("HTTP 退出", "err", err)
		os.Exit(1)
	}
}

// isolationAllowlist 隔离主机时必须放行的地址。默认放行 server 的 gRPC 端点，
// 否则 agent 隔离后收不到解除指令，只能人工上机处理。
func isolationAllowlist() []string {
	if v := os.Getenv("ISOLATION_ALLOW"); v != "" {
		return strings.Split(v, ",")
	}
	slog.Warn("未配置 ISOLATION_ALLOW，主机隔离将被 agent 拒绝执行")
	return nil
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

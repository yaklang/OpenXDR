package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"

	"openxdr/server/ent"
	"openxdr/server/internal/api"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/cluster"
	"openxdr/server/internal/correlate"
	"openxdr/server/internal/eventbus"
	"openxdr/server/internal/grpcsvc"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/janitor"
	"openxdr/server/internal/notify"
	"openxdr/server/internal/response"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/syslog"
	"openxdr/server/internal/telemetry"
	"openxdr/server/internal/triage"
	"openxdr/server/internal/ueba"
	"openxdr/server/pb"
)

func main() {
	configureLogging()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := sql.Open("pgx", getenv("DATABASE_URL",
		"postgres://openxdr:openxdr@localhost:5432/openxdr?sslmode=disable"))
	if err != nil {
		slog.Error("数据库连接失败", "err", err)
		os.Exit(1)
	}
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	defer client.Close()
	if err := cluster.WithLock(ctx, db, "schema", func() error {
		if err := client.Schema.Create(ctx); err != nil {
			return err
		}
		ensureSearchIndex(ctx, db)
		return ingest.EnsureSchema(ctx, db)
	}); err != nil {
		slog.Error("集群处理状态初始化失败", "err", err)
		os.Exit(1)
	}

	suppressions := suppress.New(client, time.Duration(getenvInt("SUPPRESSION_RELOAD_SECONDS", 30))*time.Second)
	go suppressions.Run(ctx)

	intelStore := intel.New(client, time.Duration(getenvInt("INTEL_RELOAD_SECONDS", 30))*time.Second)
	go intelStore.Run(ctx)

	rulesPath := getenv("RULES_PATH", "../rules")
	rules := sigma.LoadDir(rulesPath)
	if sec := getenvInt("RULES_RELOAD_SECONDS", 30); sec > 0 {
		go rules.Watch(ctx, rulesPath, time.Duration(sec)*time.Second)
	}

	correlator := &correlate.Engine{
		DB:            client,
		Rules:         rules,
		Window:        time.Duration(getenvInt("CORRELATE_WINDOW_MINUTES", 30)) * time.Minute,
		Interval:      time.Duration(getenvInt("CORRELATE_INTERVAL_SECONDS", 10)) * time.Second,
		MaxGraphNodes: getenvInt("CORRELATE_MAX_GRAPH_NODES", 500),
	}
	go cluster.RunLeader(ctx, db, "correlate", correlator.Run)

	// UEBA 首次出现：先学习后告警，学习期按资产从首次观测起算
	uebaEngine := &ueba.Engine{
		DB:             client,
		Suppress:       suppressions,
		LearningPeriod: time.Duration(getenvInt("UEBA_LEARNING_DAYS", 7)) * 24 * time.Hour,
		Interval:       time.Duration(getenvInt("UEBA_INTERVAL_SECONDS", 30)) * time.Second,
	}
	go cluster.RunLeader(ctx, db, "ueba", uebaEngine.Run)

	janitorEngine := &janitor.Janitor{
		DB:        client,
		Retention: time.Duration(getenvInt("RETENTION_DAYS", 30)) * 24 * time.Hour,
		Interval:  time.Duration(getenvInt("RETENTION_INTERVAL_MINUTES", 60)) * time.Minute,
	}
	go cluster.RunLeader(ctx, db, "janitor", janitorEngine.Run)

	hub := response.NewHub(client, os.Getenv("RESPONSE_ENABLED") == "true")
	allowlist := isolationAllowlist()

	// 研判引擎同时是狩猎的执行者：共用同一套调查工具与模型配置
	triageEngine := &triage.Engine{
		DB:    client,
		Rules: rules,
		LLM: triage.NewLLM(
			getenv("AI_BASE_URL", "http://localhost:11434/v1"),
			os.Getenv("AI_MODEL"),
			os.Getenv("AI_API_KEY"),
			time.Duration(getenvInt("AI_TIMEOUT_SECONDS", 120))*time.Second,
		),
		Interval: time.Duration(getenvInt("AI_INTERVAL_SECONDS", 30)) * time.Second,
	}
	// 自动响应：显式开启才挂钩子，默认 dry-run，白名单主机绝不自动隔离
	if os.Getenv("AUTO_RESPONSE_ENABLED") == "true" {
		triageEngine.OnVerdict = (&response.Auto{
			Hub:            hub,
			MinConfidence:  getenvInt("AUTO_RESPONSE_MIN_CONFIDENCE", 90),
			Live:           os.Getenv("AUTO_RESPONSE_LIVE") == "true",
			Exempt:         hostSet(os.Getenv("AUTO_RESPONSE_EXEMPT")),
			AllowEndpoints: allowlist,
		}).React
	}
	if triageEngine.LLM.Enabled() {
		go cluster.RunLeader(ctx, db, "triage", triageEngine.Run)
	}

	notifier := &notify.Notifier{
		DB:          client,
		URL:         os.Getenv("WEBHOOK_URL"),
		Format:      getenv("WEBHOOK_FORMAT", "generic"),
		Interval:    time.Duration(getenvInt("WEBHOOK_INTERVAL_SECONDS", 30)) * time.Second,
		WaitTriage:  os.Getenv("AI_MODEL") != "",
		LinkBase:    os.Getenv("WEBHOOK_LINK_BASE"),
		MinSeverity: int16(getenvInt("WEBHOOK_MIN_SEVERITY", 0)),
	}
	if notifier.URL != "" {
		go cluster.RunLeader(ctx, db, "notify", notifier.Run)
	}

	dedupWindow := time.Duration(getenvInt("ALERT_DEDUP_WINDOW_MINUTES", 5)) * time.Minute
	registry := prometheus.NewRegistry()
	registry.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	metrics := telemetry.New(registry)
	processor := &ingest.Processor{
		DB: db, Rules: rules, Suppress: suppressions, Intel: intelStore,
		DedupWindow: dedupWindow, Metrics: metrics,
	}
	var events eventbus.Bus = eventbus.NewDirect(processor, metrics)
	hostname, _ := os.Hostname()
	instance := eventbus.InstanceName(hostname, os.Getpid())
	if natsURL := os.Getenv("NATS_URL"); natsURL != "" {
		queued, err := eventbus.NewJetStream(natsURL,
			instance, getenvInt("QUEUE_SHARDS", 32), getenvInt("QUEUE_REPLICAS", 1),
			int64(getenvInt("QUEUE_MAX_BYTES_GB", 20))*1024*1024*1024,
			time.Duration(getenvInt("QUEUE_MAX_AGE_HOURS", 168))*time.Hour, processor, metrics)
		if err != nil {
			slog.Error("JetStream 初始化失败", "err", err)
			os.Exit(1)
		}
		events = queued
		router, routeErr := response.NewNATSRouter(natsURL, instance)
		if routeErr != nil {
			slog.Error("跨节点指令路由初始化失败", "err", routeErr)
			os.Exit(1)
		}
		hub.Router = router
		defer router.Close()
		slog.Info("事件队列已启用", "url", natsURL, "shards", getenvInt("QUEUE_SHARDS", 32))
	} else {
		slog.Warn("NATS_URL 未配置，事件使用单机直连模式")
	}
	defer events.Close()

	go (&syslog.Server{
		DB:          client,
		Rules:       rules,
		Addr:        os.Getenv("SYSLOG_ADDR"),
		DedupWindow: dedupWindow,
		Suppress:    suppressions,
		Intel:       intelStore,
		Events:      events,
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
		Hub:         hub,
		Suppress:    suppressions,
		Intel:       intelStore,
		Events:      events,
	})
	pb.RegisterSensorServiceServer(grpcServer, &grpcsvc.SensorServer{
		DB:          client,
		Rules:       rules,
		DedupWindow: dedupWindow,
		Suppress:    suppressions,
		Intel:       intelStore,
		Events:      events,
	})
	go func() {
		slog.Info("gRPC 启动", "addr", grpcAddr)
		if err := grpcServer.Serve(lis); err != nil {
			slog.Error("gRPC 退出", "err", err)
			os.Exit(1)
		}
	}()

	if err := cluster.WithLock(ctx, db, "bootstrap", func() error { return auth.Bootstrap(ctx, client) }); err != nil {
		slog.Error("初始化 admin 账号失败", "err", err)
		os.Exit(1)
	}

	httpAddr := getenv("HTTP_ADDR", ":8080")
	slog.Info("HTTP 启动", "addr", httpAddr)
	app := auth.Middleware(client, api.Handler(client, rules, rulesPath, hub, suppressions, intelStore, triageEngine, allowlist))
	mux := http.NewServeMux()
	mux.Handle("/metrics", telemetry.Handler(registry))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := db.PingContext(r.Context()); err != nil || !events.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.Handle("/", app)
	httpServer := &http.Server{Addr: httpAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	httpErr := make(chan error, 1)
	go func() { httpErr <- httpServer.ListenAndServe() }()
	select {
	case err := <-httpErr:
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP 退出", "err", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		slog.Info("收到退出信号，开始排空连接")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
	grpcDone := make(chan struct{})
	go func() { grpcServer.GracefulStop(); close(grpcDone) }()
	select {
	case <-grpcDone:
	case <-shutdownCtx.Done():
		grpcServer.Stop()
	}
}

func configureLogging() {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if os.Getenv("LOG_FORMAT") == "json" {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, opts)))
		return
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, opts)))
}

// ensureSearchIndex 事件全文检索的 trgm 索引。没有它，关键词检索在大表上
// 是全表扫。CREATE EXTENSION 需要数据库权限，失败只降级警告——检索仍然可用，
// 只是慢，比起启动失败这是正确的取舍。
func ensureSearchIndex(ctx context.Context, db *sql.DB) {
	stmts := []string{
		"CREATE EXTENSION IF NOT EXISTS pg_trgm",
		"CREATE INDEX IF NOT EXISTS events_raw_trgm ON events USING gin ((raw::text) gin_trgm_ops)",
	}
	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			slog.Warn("检索索引未启用，大数据量下关键词搜索会退化为全表扫描", "err", err)
			return
		}
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

// hostSet 逗号分隔的主机名清单转集合。
func hostSet(v string) map[string]bool {
	set := map[string]bool{}
	for _, h := range strings.Split(v, ",") {
		if h = strings.TrimSpace(h); h != "" {
			set[h] = true
		}
	}
	return set
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

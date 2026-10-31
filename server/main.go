package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
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
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"google.golang.org/grpc"

	"openxdr/server/ent"
	"openxdr/server/internal/agentchat"
	"openxdr/server/internal/aiconf"
	"openxdr/server/internal/aijob"
	"openxdr/server/internal/api"
	"openxdr/server/internal/assetmap"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/automation"
	"openxdr/server/internal/beacon"
	"openxdr/server/internal/cluster"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/correlate"
	"openxdr/server/internal/enroll"
	"openxdr/server/internal/eventarchive"
	"openxdr/server/internal/eventbus"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/eventsearch"
	"openxdr/server/internal/fpstats"
	"openxdr/server/internal/grpcsvc"
	"openxdr/server/internal/hostimport"
	"openxdr/server/internal/identity"
	"openxdr/server/internal/identity/directory"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/integration"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/ipdb"
	"openxdr/server/internal/janitor"
	"openxdr/server/internal/liveness"
	"openxdr/server/internal/notify"
	"openxdr/server/internal/piruntime"
	"openxdr/server/internal/queryrole"
	"openxdr/server/internal/realip"
	"openxdr/server/internal/report"
	"openxdr/server/internal/response"
	"openxdr/server/internal/schedule"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/suricata"
	"openxdr/server/internal/syslog"
	"openxdr/server/internal/telemetry"
	"openxdr/server/internal/temporal"
	"openxdr/server/internal/triage"
	"openxdr/server/internal/ueba"
	"openxdr/server/internal/vuln"
	"openxdr/server/pb"
)

func main() {
	configureLogging()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dsn := getenv("DATABASE_URL", "postgres://openxdr:openxdr@localhost:5432/openxdr?sslmode=disable")
	db, client := openStore(ctx, dsn)
	defer client.Close()
	startDirectorySync(ctx, db)

	suppressions := suppress.New(client, time.Duration(getenvInt("SUPPRESSION_RELOAD_SECONDS", 30))*time.Second)
	go suppressions.Run(ctx)
	credentialVault := loadCredentialVault()
	aiConf := newAIConf(client, credentialVault)
	conf := func() aiconf.Config { return aiConf.Get(ctx) }
	intelStore, intelFeeds := startIntel(ctx, db, client, func(ctx context.Context) string { return aiConf.Get(ctx).AbuseCHKey })

	rulesPath := getenv("RULES_PATH", "../rules")
	rules, temporalRules, err := loadDetectionRules(ctx, rulesPath, os.Getenv("TEMPORAL_RULES_PATH"), time.Duration(getenvInt("RULES_RELOAD_SECONDS", 30))*time.Second)
	if err != nil {
		slog.Error("检测规则快照加载失败", "err", err)
		os.Exit(1)
	}
	if temporalRules != nil {
		// 过期候选清理与 RETENTION_DAYS 无关：它决定候选表规模，不删原始事件或证据
		go cluster.RunLeader(ctx, db, "temporal-candidates", func(ctx context.Context) {
			temporalRules.PruneLoop(ctx, db, 5*time.Minute)
		})
	}
	startAnalytics(ctx, db, client, rules, suppressions)

	// 研判与资产标注共用一个端点与模型，每次调用按当时的配置，用量按用途分开记
	llmFor := func(feature string) *triage.LLM { return newLLM(client, conf, feature) }
	assetEngine := startAssetMap(ctx, db, client, llmFor, conf)

	hub := response.NewHub(client, os.Getenv("RESPONSE_ENABLED") == "true")
	allowlist := isolationAllowlist()
	triageEngine := startTriage(ctx, db, client, rules, llmFor, hub, allowlist)
	notifySettings, webhook := startNotify(ctx, db, client, rules, triageEngine.LLM.Enabled)
	silentAfter := time.Duration(getenvInt("AGENT_SILENT_MINUTES", 10)) * time.Minute
	startLiveness(ctx, db, client, webhook, silentAfter)
	startAutomation(ctx, db, client, webhook)

	dedupWindow := time.Duration(getenvInt("ALERT_DEDUP_WINDOW_MINUTES", 5)) * time.Minute
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		telemetry.NewCollectorHealth(db), telemetry.NewIntegrationQueue(db), integration.RateLimitedRequests)
	events, router := startEventBus(ctx, db, rules, temporalRules, suppressions, intelStore, dedupWindow, hub, registry)
	if router != nil {
		defer router.Close()
	}
	defer events.Close()
	startSyslog(ctx, client, rules, dedupWindow, suppressions, intelStore, events)
	grpcServer, dists := startGRPC(db, client, rules, dedupWindow, hub, suppressions, intelStore, events)

	if err := cluster.WithLock(ctx, db, "bootstrap", func() error { return auth.Bootstrap(ctx, client) }); err != nil {
		slog.Error("初始化 admin 账号失败", "err", err)
		os.Exit(1)
	}

	httpAddr := getenv("HTTP_ADDR", ":8080")
	slog.Info("HTTP 启动", "addr", httpAddr)
	queryRoles := startQueryRoles(ctx, db, client, dsn)
	chat := startChat(ctx, client, rules, hub, webhook, conf, queryRoles)
	scheduler := startScheduler(ctx, db, client, chat, conf, webhook)
	enrollSvc := loadEnroll(client, silentAfter)
	routes := http.NewServeMux()
	registerSQLRoutes(routes, db)
	routes.Handle("GET /api/trusted-sources/candidates", api.TrustedCandidates(client, db))
	registerHostRoutes(ctx, routes, db, client, rules, credentialVault, enrollSvc, conf)
	registerSettingsRoutes(routes, db, client, credentialVault, notifySettings, webhook, aiConf, intelFeeds, enrollSvc, dists)
	// 冷归档读取默认关闭：EVENT_ARCHIVE_READ=1 才把连接交给 /api/events 与问 AI 入口，关着时行为与改动前一致
	archiveRead := archiveConn(ctx, db)
	registerAIRoutes(routes, client, archiveRead, llmFor, assetEngine)
	outboundAllow := &integration.OutboundAllow{DB: client, Locked: os.Getenv("INTEGRATION_WEBHOOK_ALLOW")}
	integrations := api.Integrations(client, credentialVault, outboundAllow)
	routes.Handle("/api/system-integrations", integrations)
	routes.Handle("/api/system-integrations/", integrations)
	startIntegrationDelivery(ctx, client, credentialVault, outboundAllow)
	routes.Handle("/", api.Handler(client, archiveRead, rules, hub, suppressions, intelStore, allowlist, chat))
	mux := publicMux(auth.Middleware(client, routes), db, client, registry, enrollSvc, dists, events)
	// 经反向代理时还原客户端地址，登录退避与审计才按真人计
	trustedProxies, err := realip.Parse(os.Getenv("TRUSTED_PROXIES"))
	if err != nil {
		slog.Error("TRUSTED_PROXIES 配置无效", "err", err)
		os.Exit(1)
	}
	httpServer := &http.Server{Addr: httpAddr, Handler: realip.Middleware(trustedProxies, mux), ReadHeaderTimeout: 10 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	if err := api.StartDeceptionHost(ctx, client, os.Getenv("DYGK_CONTROL_SOCKET")); err != nil {
		slog.Error("欺骗引擎控制通道启动失败", "err", err)
		os.Exit(1)
	}
	serveUntilDone(ctx, httpServer, chat, scheduler, grpcServer)
}

// openStore 连接数据库，在 schema 锁里建表并完成各模块的库结构迁移。
func openStore(ctx context.Context, dsn string) (*sql.DB, *ent.Client) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		slog.Error("数据库连接失败", "err", err)
		os.Exit(1)
	}
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	if err := cluster.WithLock(ctx, db, "schema", func() error { return migrateSchema(ctx, db, client) }); err != nil {
		slog.Error("集群处理状态初始化失败", "err", err)
		os.Exit(1)
	}
	return db, client
}

// migrateSchema 建表与各模块的库结构迁移，调用方须持有 schema 锁。
func migrateSchema(ctx context.Context, db *sql.DB, client *ent.Client) error {
	if err := eventpart.Migrate(ctx, client, db); err != nil {
		return err
	}
	eventsearch.Ensure(ctx, db)
	// 旧版 AI 免审批名单换成高风险名单；放在 schema 锁里，多节点同时启动只迁一次
	if err := commandgate.MigrateAllowToDeny(ctx, client); err != nil {
		return err
	}
	if err := commandgate.UpgradeDefaults(ctx, client); err != nil {
		return err
	}
	if err := aijob.EnsureSchema(ctx, db); err != nil {
		return err
	}
	if err := response.EnsureVerificationSchema(ctx, db); err != nil {
		return err
	}
	return ingest.EnsureSchema(ctx, db)
}

// startDirectorySync 目录来源登记、单活同步、运行记录清理与身份图增量更新。
func startDirectorySync(ctx context.Context, db *sql.DB) {
	directoryJobs, err := directory.LoadConfig(os.Getenv("IDENTITY_SOURCES_JSON"), os.Getenv)
	if err != nil {
		slog.Error("目录同步配置无效", "err", err)
		os.Exit(1)
	}
	if err := directory.RegisterJobs(ctx, db, directoryJobs); err != nil {
		slog.Error("目录来源登记失败", "err", err)
		os.Exit(1)
	}
	if len(directoryJobs) > 0 {
		go cluster.RunLeader(ctx, db, "identity-directories", func(ctx context.Context) {
			directory.RunWorker(ctx, db, directoryJobs)
		})
	}
	directoryRetention := getenvInt("IDENTITY_RUN_RETENTION_DAYS", 30)
	if directoryRetention < 0 || directoryRetention > 3650 {
		slog.Error("IDENTITY_RUN_RETENTION_DAYS 必须为 0 到 3650")
		os.Exit(1)
	}
	go cluster.RunLeader(ctx, db, "identity-maintenance", func(ctx context.Context) {
		directory.RunMaintenance(ctx, db, time.Duration(directoryRetention)*24*time.Hour)
	})
	// 身份图不依赖目录配置：本地账号与登录观察也要建图
	go cluster.RunLeader(ctx, db, "identity-graph", func(ctx context.Context) { identity.RunGraph(ctx, db) })
}

// startIntel 情报库定时重载与情报订阅。
func startIntel(ctx context.Context, db *sql.DB, client *ent.Client, authKey func(context.Context) string) (*intel.Store, *intel.Feeds) {
	intelStore := intel.New(client, time.Duration(getenvInt("INTEL_RELOAD_SECONDS", 30))*time.Second)
	go intelStore.Run(ctx)
	// 情报订阅：内置公开源，控制台开关，单活定时拉取；落库后由 intelStore 下个重载周期生效
	intelFeeds := &intel.Feeds{DB: db, Client: client, HTTP: &http.Client{}, AuthKey: authKey,
		Interval: time.Duration(getenvInt("INTEL_FEED_INTERVAL_HOURS", 6)) * time.Hour}
	go cluster.RunLeader(ctx, db, "intel-feeds", intelFeeds.Run)
	return intelStore, intelFeeds
}

// startAnalytics 关联、UEBA、外联心跳、保留期清理与自动结案等单活后台任务。
func startAnalytics(ctx context.Context, db *sql.DB, client *ent.Client, rules sigma.Catalog, suppressions *suppress.Store) {
	correlator := &correlate.Engine{
		DB:            client,
		Rules:         rules,
		Window:        time.Duration(getenvInt("CORRELATE_WINDOW_MINUTES", 30)) * time.Minute,
		Interval:      time.Duration(getenvInt("CORRELATE_INTERVAL_SECONDS", 10)) * time.Second,
		MaxGraphNodes: getenvInt("CORRELATE_MAX_GRAPH_NODES", 500),
		RecurSpan:     time.Duration(getenvInt("CORRELATE_RECUR_HOURS", 24)) * time.Hour,
		RecurCoarse:   getenvInt("CORRELATE_RECUR_COARSE", 1) == 1,
	}
	go cluster.RunLeader(ctx, db, "correlate", correlator.Run)

	// UEBA 首次出现：先学习后告警，学习期按资产从首次观测起算
	uebaEngine := &ueba.Engine{
		DB:             client,
		SQL:            db,
		Suppress:       suppressions,
		LearningPeriod: time.Duration(getenvInt("UEBA_LEARNING_DAYS", 7)) * 24 * time.Hour,
		Interval:       time.Duration(getenvInt("UEBA_INTERVAL_SECONDS", 30)) * time.Second,
	}
	go cluster.RunLeader(ctx, db, "ueba", uebaEngine.Run)

	// 外联心跳：新出现的规律公网外联。首次上线回放学习期内的历史只学不报
	if getenvInt("BEACON_ENABLED", 1) == 1 {
		beaconEngine := &beacon.Engine{
			DB: client, SQL: db, Suppress: suppressions,
			LearningPeriod: time.Duration(getenvInt("BEACON_LEARNING_DAYS", 7)) * 24 * time.Hour,
			Window:         time.Duration(getenvInt("BEACON_WINDOW_HOURS", 12)) * time.Hour,
			Interval:       time.Duration(getenvInt("BEACON_INTERVAL_SECONDS", 300)) * time.Second,
		}
		go cluster.RunLeader(ctx, db, "beacon", beaconEngine.Run)
	}

	janitorEngine := &janitor.Janitor{
		SQL:          db,
		DB:           client,
		Retention:    time.Duration(getenvInt("RETENTION_DAYS", 30)) * 24 * time.Hour,
		Interval:     time.Duration(getenvInt("RETENTION_INTERVAL_MINUTES", 60)) * time.Minute,
		GapRetention: time.Duration(getenvInt("TEMPORAL_GAP_RETENTION_DAYS", 30)) * 24 * time.Hour,
	}
	go cluster.RunLeader(ctx, db, "janitor", janitorEngine.Run)
	// 事件日分区预建与保留期退役无关：RETENTION_DAYS=0 也要按天建分区
	partitions := &eventpart.Maintainer{DB: db, Interval: time.Hour}
	go cluster.RunLeader(ctx, db, "event-partitions", partitions.Run)
	// 低危良性事件放久了自动按误报结案；0 关闭。Run 返回会被租约循环立刻重拉，关闭时干脆不启动
	if days := getenvInt("AUTO_CLOSE_BENIGN_DAYS", 7); days > 0 {
		autoClose := &janitor.AutoClose{DB: client, Days: days, Interval: time.Hour}
		go cluster.RunLeader(ctx, db, "auto-close-benign", autoClose.Run)
	}
	// 同一规则在同一主机上被人反复判误报，生成待组管理员批准的抑制草案；0 关闭
	if minCount := getenvInt("FP_SUPPRESS_MIN_COUNT", 5); minCount > 0 {
		stats := &fpstats.Stats{
			DB: client, MinCount: minCount, MinRatio: getenvInt("FP_SUPPRESS_MIN_RATIO", 90),
			Window:   time.Duration(getenvInt("FP_SUPPRESS_WINDOW_DAYS", 30)) * 24 * time.Hour,
			Days:     min(max(getenvInt("FP_SUPPRESS_DAYS", 30), 1), 90),
			Cooldown: time.Duration(getenvInt("FP_SUPPRESS_COOLDOWN_DAYS", 30)) * 24 * time.Hour,
			Interval: time.Duration(max(getenvInt("FP_SUPPRESS_INTERVAL_HOURS", 6), 1)) * time.Hour,
		}
		go cluster.RunLeader(ctx, db, "fp-stats", stats.Run)
	}
}

// loadCredentialVault 主机凭据加密钥匙，未配置 HOST_CREDENTIAL_KEY 时为 nil。
func loadCredentialVault() *hostimport.Vault {
	key := os.Getenv("HOST_CREDENTIAL_KEY")
	if key == "" {
		return nil
	}
	credentialVault, err := hostimport.NewVault(key)
	if err != nil {
		slog.Error("凭据加密配置无效")
		os.Exit(1)
	}
	return credentialVault
}

// newAIConf AI 与外部情报查询配置：控制台保存的为准，环境变量是首次部署的默认值；密钥用主机凭据同一把钥匙加密落库
func newAIConf(client *ent.Client, credentialVault *hostimport.Vault) *aiconf.Store {
	return &aiconf.Store{DB: client, Vault: credentialVault, Default: aiconf.Config{
		BaseURL: getenv("AI_BASE_URL", "http://localhost:11434/v1"), APIKey: os.Getenv("AI_API_KEY"),
		Model: os.Getenv("AI_MODEL"), PiModel: os.Getenv("PI_MODEL"),
		AbuseCHKey: os.Getenv("ABUSE_CH_AUTH_KEY"),
		PTR:        getenv("IPINFO_PTR", "true") == "true", VTKey: os.Getenv("VT_API_KEY"), VTAlertMin: getenvInt("VT_ALERT_MIN_ENGINES", 3),
	}}
}

// newLLM 端点与模型按调用当时的控制台配置取，用量记在 feature 名下。
func newLLM(client *ent.Client, conf func() aiconf.Config, feature string) *triage.LLM {
	l := triage.NewLLM("", "", "", time.Duration(getenvInt("AI_TIMEOUT_SECONDS", 120))*time.Second)
	l.Endpoint = func() (string, string, string) { c := conf(); return c.BaseURL, c.Model, c.APIKey }
	l.OnUsage = aiconf.Recorder(client, feature)
	return l
}

// startAssetMap 资产图谱与攻击面，以及公网目的地址的背景信息补全。
func startAssetMap(ctx context.Context, db *sql.DB, client *ent.Client, llmFor func(string) *triage.LLM, conf func() aiconf.Config) *assetmap.Engine {
	// 资产图谱与攻击面：物化清单与依赖边始终运行；配置了研判与标注模型才做 AI 标注
	assetEngine := &assetmap.Engine{
		DB: client, SQL: db,
		LLM:      llmFor("annotate"),
		Interval: time.Minute,
		Refresh:  time.Duration(getenvInt("ASSET_ANNOTATE_REFRESH_HOURS", 24)) * time.Hour,
	}
	// 标注是后台批量调用：关掉 GLM 隐式思考、限住输出，耗时才稳定（实测 pve1 默认模式波动到 120 秒超时）
	assetEngine.LLM.NoThinking, assetEngine.LLM.MaxTokens = true, 2048
	go cluster.RunLeader(ctx, db, "assetmap", assetEngine.Run)
	// 公网目的地址的背景信息：离线归属库（IPDB_DIR，本地查）放了库就查；反向解析默认开；
	// 配了 VirusTotal key 才查（会把外联的公网地址发给它）。开关与 key 每轮取。启动时先打开一次离线库，库缺失在日志里说明
	ipDB := &ipdb.DB{Dir: os.Getenv("IPDB_DIR")}
	ipDB.Refresh()
	ipEnricher := &assetmap.Enricher{
		DB: client, IPDB: ipDB, Settings: func() (bool, string, int) { c := conf(); return c.PTR, c.VTKey, c.VTAlertMin },
		VTPerMin: getenvInt("VT_PER_MINUTE", 4), VTPerDay: getenvInt("VT_PER_DAY", 500),
		TTL: time.Duration(getenvInt("IPINFO_TTL_DAYS", 7)) * 24 * time.Hour, Interval: time.Minute,
		HTTP: &http.Client{Timeout: 15 * time.Second},
	}
	go cluster.RunLeader(ctx, db, "ipinfo", ipEnricher.Run)
	return assetEngine
}

// startTriage 研判引擎：AI 带只读调查工具逐个研判 incident
func startTriage(ctx context.Context, db *sql.DB, client *ent.Client, rules sigma.Catalog, llmFor func(string) *triage.LLM, hub *response.Hub, allowlist []string) *triage.Engine {
	triageEngine := &triage.Engine{
		DB:       client,
		Rules:    rules,
		LLM:      llmFor("triage"),
		Interval: time.Duration(getenvInt("AI_INTERVAL_SECONDS", 30)) * time.Second,
		Cooldown: time.Duration(getenvInt("AI_RETRIAGE_COOLDOWN_MINUTES", 30)) * time.Minute,
	}
	// 自动响应：显式开启才挂钩子，隔离真执行（仍受 RESPONSE_ENABLED 约束），白名单主机绝不自动隔离
	if os.Getenv("AUTO_RESPONSE_ENABLED") == "true" {
		triageEngine.OnVerdict = (&response.Auto{
			Hub:            hub,
			MinConfidence:  getenvInt("AUTO_RESPONSE_MIN_CONFIDENCE", 90),
			Exempt:         hostSet(os.Getenv("AUTO_RESPONSE_EXEMPT")),
			AllowEndpoints: allowlist,
		}).React
	}
	// 常驻：模型在控制台配上就开始研判，撤掉就停
	go cluster.RunLeader(ctx, db, "triage", triageEngine.Run)
	return triageEngine
}

// startNotify 推送目标以控制台保存的为准，环境变量只是首次部署的默认值
func startNotify(ctx context.Context, db *sql.DB, client *ent.Client, rules sigma.Catalog, waitTriage func() bool) (*notify.Settings, *notify.Webhook) {
	notifySettings := &notify.Settings{DB: client, Default: notify.Target{
		URL:         os.Getenv("WEBHOOK_URL"),
		Format:      getenv("WEBHOOK_FORMAT", "generic"),
		LinkBase:    os.Getenv("WEBHOOK_LINK_BASE"),
		MinSeverity: int16(getenvInt("WEBHOOK_MIN_SEVERITY", 0)),
	}}
	webhook := &notify.Webhook{Settings: notifySettings}
	notifier := &notify.Notifier{
		DB:         client,
		Settings:   notifySettings,
		Interval:   time.Duration(getenvInt("WEBHOOK_INTERVAL_SECONDS", 30)) * time.Second,
		WaitTriage: waitTriage,
		Rules:      rules,
	}
	go cluster.RunLeader(ctx, db, "notify", notifier.Run)
	return notifySettings, webhook
}

// startLiveness 采集端静默与丢事件告警。
func startLiveness(ctx context.Context, db *sql.DB, client *ent.Client, webhook *notify.Webhook, silentAfter time.Duration) {
	watcher := &liveness.Watcher{
		DB: client, Notify: webhook.Send,
		SilentAfter: silentAfter,
		Interval:    time.Minute,
		DropAlert:   getenvInt("COLLECTOR_DROP_ALERT", 1000),
	}
	go cluster.RunLeader(ctx, db, "liveness", watcher.Run)
}

// startAutomation 运维自动化的自动识别。参数不合理（非正数、有效期超上限）的退回默认值；
// 总开关关掉时仍收集登录、按结论停用已识别的条目并通知
func startAutomation(ctx context.Context, db *sql.DB, client *ent.Client, webhook *notify.Webhook) {
	def := automation.DefaultConfig()
	positive := func(key string, d int) int {
		if v := getenvInt(key, d); v > 0 {
			return v
		}
		return d
	}
	conf := automation.Config{
		Enabled:    getenv("AUTOMATION_AUTO_ENABLED", "true") != "false",
		WindowDays: positive("AUTOMATION_AUTO_WINDOW_DAYS", def.WindowDays),
		MinDays:    positive("AUTOMATION_AUTO_MIN_DAYS", def.MinDays),
		MinLogins:  positive("AUTOMATION_AUTO_MIN_LOGINS", def.MinLogins),
		AIBenign:   positive("AUTOMATION_AUTO_AI_BENIGN", def.AIBenign),
		TTLDays:    positive("AUTOMATION_AUTO_TTL_DAYS", def.TTLDays),
	}
	if conf.TTLDays > automation.MaxDays {
		conf.TTLDays = def.TTLDays
	}
	if conf.MinDays > conf.WindowDays {
		conf.MinDays = conf.WindowDays
	}
	automation.Configure(conf)
	auto := &automation.Auto{
		DB: client, SQL: db, Notify: webhook.Send, Config: conf,
		Interval: time.Duration(positive("AUTOMATION_AUTO_INTERVAL_SECONDS", 300)) * time.Second,
	}
	go cluster.RunLeader(ctx, db, "automation", auto.Run)
}

// startEventBus 事件处理管道：配了 NATS_URL 走 JetStream 持久队列并挂上跨节点指令路由，
// 否则单机直连，返回的 router 为 nil。
func startEventBus(ctx context.Context, db *sql.DB, rules sigma.Catalog, temporalRules *temporal.Store, suppressions *suppress.Store, intelStore *intel.Store, dedupWindow time.Duration, hub *response.Hub, registry *prometheus.Registry) (eventbus.Bus, *response.NATSRouter) {
	metrics := telemetry.New(registry)
	// ingest 用可选接口记整批耗时，漏实现只会静默失效，在接线处钉死
	var _ interface{ Batch(int, time.Duration) } = metrics
	processor := &ingest.Processor{
		DB: db, Rules: rules, Temporal: temporalRules, Suppress: suppressions, Intel: intelStore,
		DedupWindow: dedupWindow, Metrics: metrics,
	}
	// 冷归档重传判重默认关闭：EVENT_ARCHIVE_DEDUP=1 才接上，不设时 Processor.Archive 为 nil，
	// 接入路径一行代码都不多跑。与 EVENT_ARCHIVE_READ 相互独立（一个管读接口、一个管接入），
	// 但只要用 eventarchive swap 切走过分区，这里就必须为 1，否则重放的老事件会重新入库、
	// 重复告警——见 docs/event-archive.md。
	if getenv("EVENT_ARCHIVE_DEDUP", "") == "1" {
		archive := ingest.NewCachedArchive(archiveDedup{db: db})
		processor.Archive = archive
		// ingest 用可选接口探测计数器，漏实现不会报错、只会静默失效，所以在接线的位置钉死它。
		var _ interface{ ArchiveFailOpen(string) } = (*telemetry.Metrics)(nil)
		// 启动时探一次边界：把边界写进启动日志，也让第一个事件就吃到缓存。
		// 冷层不可用不影响 server 起来，按 fail-open（没有归档）运行并如实告警。
		last, ok, err := archive.ArchiveBoundary(ctx)
		switch {
		case err != nil:
			slog.Warn("冷归档重传判重已启用，但读不到归档边界，本次按没有归档运行（fail-open）", "err", err)
		case ok:
			slog.Info("冷归档重传判重已启用", "boundary", last, "cache_ttl", ingest.DefaultArchiveBoundaryTTL)
		default:
			slog.Info("冷归档重传判重已启用，当前冷归档为空")
		}
	}
	var events eventbus.Bus = eventbus.NewDirect(processor, metrics)
	hostname, _ := os.Hostname()
	instance := eventbus.InstanceName(hostname, os.Getpid())
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		slog.Warn("NATS_URL 未配置，事件使用单机直连模式")
		return events, nil
	}
	queued, err := eventbus.NewJetStream(natsURL,
		instance, getenvInt("QUEUE_SHARDS", 32), getenvInt("QUEUE_REPLICAS", 1),
		int64(getenvInt("QUEUE_MAX_BYTES_GB", 20))*1024*1024*1024,
		time.Duration(getenvInt("QUEUE_MAX_AGE_HOURS", 0))*time.Hour, processor, metrics, getenvInt("QUEUE_BATCH_SIZE", 1))
	if err != nil {
		slog.Error("JetStream 初始化失败", "err", err)
		os.Exit(1)
	}
	router, routeErr := response.NewNATSRouter(natsURL, instance)
	if routeErr != nil {
		slog.Error("跨节点指令路由初始化失败", "err", routeErr)
		os.Exit(1)
	}
	hub.Router = router
	slog.Info("事件队列已启用", "url", natsURL, "shards", getenvInt("QUEUE_SHARDS", 32), "batch_size", queued.BatchSize())
	return queued, router
}

// startSyslog syslog 接入，与采集端共用同一事件管道。
func startSyslog(ctx context.Context, client *ent.Client, rules sigma.Catalog, dedupWindow time.Duration, suppressions *suppress.Store, intelStore *intel.Store, events eventbus.Bus) {
	go (&syslog.Server{
		DB:          client,
		Rules:       rules,
		Addr:        os.Getenv("SYSLOG_ADDR"),
		DedupWindow: dedupWindow,
		Suppress:    suppressions,
		Intel:       intelStore,
		Events:      events,
	}).Run(ctx)
}

// startGRPC 监听 agent 与 sensor 接入，返回 gRPC 服务与采集端安装包目录。
func startGRPC(db *sql.DB, client *ent.Client, rules sigma.Catalog, dedupWindow time.Duration, hub *response.Hub, suppressions *suppress.Store, intelStore *intel.Store, events eventbus.Bus) (*grpc.Server, enroll.Dists) {
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
	// 证书用途核对在所有 RPC 之前：探针证书进不了 agent 通道，反之亦然
	grpcServer := grpc.NewServer(append(tlsOpts, grpcsvc.Interceptors()...)...)
	// 采集端安装包：一键接入从这里下载，在线 agent / sensor 也按这里的版本自动升级（AGENT_AUTO_UPGRADE=false 都关闭）
	dists := enroll.NewDists(os.Getenv("AGENT_DIST_DIR"))
	autoUpgrade := os.Getenv("AGENT_AUTO_UPGRADE") != "false"
	pb.RegisterAgentServiceServer(grpcServer, &grpcsvc.Server{
		DB:          client,
		SQL:         db,
		Rules:       rules,
		DedupWindow: dedupWindow,
		Hub:         hub,
		Suppress:    suppressions,
		Intel:       intelStore,
		Events:      events,
		Dist:        dists.Agent,
		AutoUpgrade: autoUpgrade,
	})
	pb.RegisterSensorServiceServer(grpcServer, &grpcsvc.SensorServer{
		DB:          client,
		Rules:       rules,
		DedupWindow: dedupWindow,
		Suppress:    suppressions,
		Intel:       intelStore,
		Events:      events,
		Dist:        dists.Sensor,
		AutoUpgrade: autoUpgrade,
	})
	go func() {
		slog.Info("gRPC 启动", "addr", grpcAddr)
		if err := grpcServer.Serve(lis); err != nil {
			slog.Error("gRPC 退出", "err", err)
			os.Exit(1)
		}
	}()
	return grpcServer, dists
}

// startQueryRoles 组查询身份：手工配置的优先，其余由平台账号自动开通（需 CREATEROLE）
func startQueryRoles(ctx context.Context, db *sql.DB, client *ent.Client, dsn string) *queryrole.Provisioner {
	queryURLs := map[uuid.UUID]string{}
	if raw := os.Getenv("PI_QUERY_DATABASE_URLS"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &queryURLs); err != nil {
			slog.Error("PI_QUERY_DATABASE_URLS 必须是组 UUID 到只读 DSN 的 JSON 对象")
			os.Exit(1)
		}
	}
	queryRoles := &queryrole.Provisioner{DB: db, Client: client, BaseDSN: dsn, Static: queryURLs}
	go func() {
		queryRoles.Reconcile(ctx)
		if err := queryrole.DropDryRun(ctx, db); err != nil {
			slog.Error("删除遗留 dry_run 列失败，多半是仍有视图引用 commands.dry_run：手工开通的组视图需按新版 deploy/pi-query/group-views.sql 重建，其他手工视图需去掉该列，然后重启 server；在此之前该列只是不再被读取", "err", err)
		}
	}()
	return queryRoles
}

// newPiRuntime 配了沙箱就让 Pi 在远端隔离容器里用默认工具干活；没配退回本机 runner 与平台自定义工具
func newPiRuntime() piruntime.Runtime {
	piRuntime := piruntime.Runtime{Runner: getenv("PI_RUNNER_PATH", "/app/pi-runtime/runner.mjs"), Timeout: time.Duration(getenvInt("PI_TIMEOUT_SECONDS", 1800)) * time.Second}
	url := os.Getenv("SANDBOX_URL")
	if url == "" {
		return piRuntime
	}
	remote, err := piruntime.NewRemote(url, os.Getenv("SANDBOX_KEY"), os.Getenv("SANDBOX_CA_FILE"))
	if err != nil {
		slog.Error("沙箱配置无效", "err", err)
		os.Exit(1)
	}
	if strings.HasPrefix(url, "http://") {
		slog.Warn("平台与沙箱之间为明文，仅适合受信网络调试")
	}
	piRuntime.Remote = remote
	slog.Info("Pi 在沙箱中运行", "url", url)
	return piRuntime
}

// startChat Pi 会话服务，并恢复上次退出时未完成的会话。
func startChat(ctx context.Context, client *ent.Client, rules sigma.Catalog, hub *response.Hub, webhook *notify.Webhook, conf func() aiconf.Config, queryRoles *queryrole.Provisioner) *agentchat.Service {
	piRuntime := newPiRuntime()
	chat := &agentchat.Service{Base: ctx, Rules: rules, Timeout: time.Duration(getenvInt("PI_TIMEOUT_SECONDS", 1800)) * time.Second, DB: client, Gate: &commandgate.Gate{DB: client, Hub: hub, ApprovalTimeout: time.Duration(getenvInt("PI_APPROVAL_TIMEOUT_SECONDS", 600)) * time.Second, Notify: webhook.Send},
		Runtime: piRuntime, Sandboxed: piRuntime.Sandboxed(),
		AI: func() (string, string, string) { c := conf(); return c.BaseURL, c.APIKey, c.PiModel }, Query: queryRoles,
		GroupDailyTokens: getenvInt("PI_GROUP_DAILY_TOKENS", 0),
		// 长会话折叠较早的工具结果与思考过程再发给模型，库里与界面仍是原文
		FoldAbove: getenvInt("PI_HISTORY_FOLD_KB", 64) * 1024}
	go chat.Recover(ctx)
	return chat
}

// startScheduler 预设任务：Pi 启用才调度，集群单活；报告与失败通知走与 incident 相同的 webhook
// 返回的通道在调度器完全退出后关闭：停机时要等它把被打断的运行记成 interrupted，
// 否则进程先退出，运行记录停在 running，只能等执行期限过了按失败清理，接手的 leader 也不会重跑
func startScheduler(ctx context.Context, db *sql.DB, client *ent.Client, chat *agentchat.Service, conf func() aiconf.Config, webhook *notify.Webhook) <-chan struct{} {
	report.Chromium = getenv("CHROMIUM_PATH", "chromium")
	// 错峰窗口调度器与任务页共用，必须在 HTTP 服务起来之前设好
	schedule.Spread = time.Duration(max(0, getenvInt("SCHEDULE_SPREAD_MINUTES", 15))) * time.Minute
	scheduler := &schedule.Scheduler{
		DB: client, Runner: chat,
		Dir:          getenv("TASKS_PATH", "../tasks"),
		Interval:     time.Duration(getenvInt("SCHEDULE_INTERVAL_SECONDS", 30)) * time.Second,
		DefaultModel: func() string { return conf().PiModel },
		Notify:       webhook.Send,
		Timeout:      time.Duration(getenvInt("PI_TIMEOUT_SECONDS", 1800)) * time.Second,
		MaxRunning:   getenvInt("SCHEDULE_MAX_RUNNING", schedule.DefaultMaxRunning),
	}
	// 常驻：任务定义照常同步到库里，Pi 模型配上才运行
	done := make(chan struct{})
	go func() {
		defer close(done)
		cluster.RunLeader(ctx, db, "schedule", scheduler.Run)
	}()
	return done
}

// loadEnroll 主机在线接入配置。
func loadEnroll(client *ent.Client, silentAfter time.Duration) *enroll.Service {
	enrollSvc, err := enroll.FromEnv(client, silentAfter)
	if err != nil {
		slog.Error("主机接入配置无效", "err", err)
		os.Exit(1)
	}
	if reason := enrollSvc.Disabled(); reason != "" {
		slog.Warn("主机在线接入未启用", "reason", reason)
	}
	return enrollSvc
}

// newImportLLM 运维文档导入：AI 解析主机清单，截图与扫描件走视觉模型（AI_VISION_MODEL，不配就用研判模型）。
// 端点与密钥按控制台当时的配置取；文档大，超时放宽到 180 秒、关掉隐式思考
func newImportLLM(conf func() aiconf.Config, model string) *triage.LLM {
	l := triage.NewLLM("", "", "", 180*time.Second)
	l.NoThinking, l.MaxTokens = true, 16384
	l.Endpoint = func() (string, string, string) {
		c := conf()
		return c.BaseURL, cmp.Or(model, c.Model, c.PiModel), c.APIKey
	}
	return l
}

// archiveConn 冷归档读取用的连接：只有 EVENT_ARCHIVE_READ=1 才接上，默认关闭。
// 开启时先确保冷归档表存在；建表失败只记日志并降级为「没有冷层」——事件页不能因为
// 冷归档起不来就整页报错，server 更不该因此起不来。阶段 B1 只读，归档写入仍然走 CLI。
func archiveConn(ctx context.Context, db *sql.DB) *sql.DB {
	if getenv("EVENT_ARCHIVE_READ", "") != "1" {
		// 关着时检索与改动前一致、不报冷层缺口；库里已经有冷块却没开读，是部署配置错了，
		// 在启动日志里如实告警，而不是让每次检索都弹提示
		if ext, err := eventarchive.ArchiveExtent(ctx, db); err == nil && ext.Has {
			slog.Warn("库里有冷归档数据，但 EVENT_ARCHIVE_READ 未开启：事件检索与调查不会覆盖已归档的历史",
				"first", ext.First, "last", ext.Last)
		}
		return nil
	}
	if err := eventarchive.EnsureSchema(ctx, db); err != nil {
		slog.Warn("冷归档读取已开启，但初始化冷归档表失败，本次按没有冷层运行", "err", err)
		return nil
	}
	return db
}

// archiveDedup 把冷归档的两个只读函数接到接入路径的最小接口（ingest.ArchiveDedup）上：
// 依赖方向仍是 main → 两个包，ingest 不 import eventarchive，eventarchive 也不知道自己在被谁调用。
type archiveDedup struct{ db *sql.DB }

// Archived 只在事件时间不晚于归档边界时被调用（罕见的重传路径）。
func (a archiveDedup) Archived(ctx context.Context, id uuid.UUID) (bool, error) {
	return eventarchive.Exists(ctx, a.db, id)
}

// ArchiveBoundary 由 ingest 侧的 CachedArchive 缓存 60 秒，不会逐条事件查库。
func (a archiveDedup) ArchiveBoundary(ctx context.Context) (time.Time, bool, error) {
	return eventarchive.Boundary(ctx, a.db)
}

// registerSQLRoutes 直接查库的接口：时序缺口、指令核验与身份观测。
func registerSQLRoutes(routes *http.ServeMux, db *sql.DB) {
	routes.Handle("/api/temporal-gaps", api.TemporalGaps(db))
	routes.Handle("/api/temporal-rule-snapshots", api.TemporalRuleSnapshots(db))
	routes.Handle("/api/temporal-rule-snapshots/", api.TemporalRuleSnapshots(db))
	verifications := api.CommandVerifications(db)
	routes.Handle("/api/commands/{id}/verifications", verifications)
	routes.Handle("/api/commands/{id}/verifications/{verificationId}", verifications)
	routes.Handle("/api/identity-observations", api.IdentityObservations(db))
	routes.Handle("/api/local-account-snapshots", api.LocalAccountSnapshots(db))
	routes.Handle("/api/local-account-snapshots/", api.LocalAccountSnapshots(db))
	routes.Handle("/api/identity-observations/", api.IdentityCandidates(db))
	identities := api.Identities(db)
	routes.Handle("/api/identities", identities)
	routes.Handle("/api/identities/", identities)
	routes.Handle("/api/identity-links/", identities)
	routes.Handle("/api/identity-rejections/", identities)
	routes.Handle("/api/assets/{id}/identity-accounts", identities)
	directoryAPI := api.IdentityDirectories(db)
	routes.Handle("/api/identity-directories", directoryAPI)
	routes.Handle("/api/identity-directories/", directoryAPI)
}

// registerHostRoutes 主机导入、初始化向导、研判准确率与软件漏洞接口，并启动漏洞库同步。
func registerHostRoutes(ctx context.Context, routes *http.ServeMux, db *sql.DB, client *ent.Client, rules sigma.Catalog, credentialVault *hostimport.Vault, enrollSvc *enroll.Service, conf func() aiconf.Config) {
	routes.Handle("/api/host-import/", api.HostImports(&hostimport.Service{DB: client, Vault: credentialVault, LLM: newImportLLM(conf, ""), VisionLLM: newImportLLM(conf, os.Getenv("AI_VISION_MODEL"))}, enrollSvc, os.Getenv("ENROLL_PUBLIC_URL"), getenv("ENROLL_SSH_ENABLED", "false") == "true"))
	setup := api.Setup(client)
	routes.Handle("/api/setup", setup)
	routes.Handle("/api/setup/", setup)
	// 比 /api/settings/ 更具体，ServeMux 优先匹配；门槛同样是 admin
	routes.Handle("/api/settings/ai/accuracy", api.AIAccuracy(db, rules))
	// 软件漏洞：资产详情与攻击面；漏洞库每天从 OSV 同步（VULN_DIR 指向离线目录时不联网）
	vulnAPI := api.Vulns(client, db)
	routes.Handle("/api/assets/{id}/vulns", vulnAPI)
	routes.Handle("/api/vulns/summary", vulnAPI)
	if getenvInt("VULN_SYNC_HOURS", 24) > 0 {
		syncer := &vuln.Syncer{DB: client, SQL: db, BaseURL: getenv("VULN_OSV_URL", vuln.DefaultBaseURL), Dir: os.Getenv("VULN_DIR"),
			Interval: time.Duration(getenvInt("VULN_SYNC_HOURS", 24)) * time.Hour}
		go cluster.RunLeader(ctx, db, "vuln-sync", syncer.Run)
	}
}

// registerSettingsRoutes 诱饵部署、系统设置、情报订阅与接入令牌接口。
func registerSettingsRoutes(routes *http.ServeMux, db *sql.DB, client *ent.Client, credentialVault *hostimport.Vault, notifySettings *notify.Settings, webhook *notify.Webhook, aiConf *aiconf.Store, intelFeeds *intel.Feeds, enrollSvc *enroll.Service, dists enroll.Dists) {
	routes.Handle("/api/decoy-install/", api.DecoyInstalls(&hostimport.Service{DB: client, Vault: credentialVault}, api.DecoyInstallConfig{Enabled: getenv("DECOY_SSH_ENABLED", "false") == "true", PublicURL: os.Getenv("ENROLL_PUBLIC_URL"), DistDir: os.Getenv("DECOY_DIST_DIR")}))
	routes.Handle("/api/settings/", api.Settings(client, notifySettings, webhook, aiConf, db))
	routes.Handle("/api/intel/feeds", api.IntelFeeds(client, intelFeeds))
	routes.Handle("/api/intel/feeds/", api.IntelFeeds(client, intelFeeds))
	enrollTokens := api.EnrollTokens(client, enrollSvc, dists)
	routes.Handle("/api/enroll-tokens", enrollTokens)
	routes.Handle("/api/enroll-tokens/", enrollTokens)
}

// registerAIRoutes 日志检索「问 AI」与资产图谱接口。conn 是冷归档读取连接（受
// EVENT_ARCHIVE_READ 闸门控制，由调用方传入）：热表查不到的日志按 id 定位冷事件，
// 与 /api/events 共用同一个受控连接。
func registerAIRoutes(routes *http.ServeMux, client *ent.Client, conn *sql.DB, llmFor func(string) *triage.LLM, assetEngine *assetmap.Engine) {
	// 日志检索里的「问 AI」：交互式调用，同样关掉隐式思考、限住输出，等得起
	explainLLM := llmFor("explain")
	explainLLM.NoThinking, explainLLM.MaxTokens = true, 1500
	eventAI := api.EventAI(client, conn, explainLLM)
	for _, path := range api.EventAIPaths {
		routes.Handle(path, eventAI)
	}
	assetMap := api.AssetMap(client, assetEngine.LLM.Enabled)
	for _, path := range api.AssetMapPaths {
		routes.Handle(path, assetMap)
	}
}

// publicMux 外层路由：指标、健康检查与免登录的接入端点，其余交给需登录的 app。
func publicMux(app http.Handler, db *sql.DB, client *ent.Client, registry *prometheus.Registry, enrollSvc *enroll.Service, dists enroll.Dists, events eventbus.Bus) *http.ServeMux {
	mux := http.NewServeMux()
	// 集成 API 的闸门是控制台里由全局管理员启用的集成与签发的 Token，不再另设全局开关；
	// 游标密钥由 HOST_CREDENTIAL_KEY 派生，没配主密钥时集成 API 返回 503
	var cursorKey []byte
	if key := os.Getenv("HOST_CREDENTIAL_KEY"); key != "" {
		var err error
		if cursorKey, err = hostimport.DeriveKey(key, "openxdr/integration-cursor/v1"); err != nil {
			slog.Error("凭据加密配置无效")
			os.Exit(1)
		}
	}
	integrationAPI := &integration.Service{DB: client, CursorKey: cursorKey,
		Suricata: func(ctx context.Context, origin suricata.Origin, event suricata.Event) error {
			return events.Publish(ctx, ingest.SuricataEnvelope(origin, event))
		}}
	mux.Handle("/api/integration/v1/", integrationAPI.Handler())
	mux.Handle("/metrics", telemetry.Handler(registry))
	// 接入端点免登录：安装脚本与二进制公开，注册靠令牌
	mux.Handle("/api/enroll/", enrollSvc.Public(dists))
	mux.Handle("/api/decoy-runtime/", api.DecoyRuntime(client))
	mux.Handle("/api/deception-runtime/", api.DeceptionRuntime(client))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := db.PingContext(r.Context()); err != nil || !events.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.Handle("/", app)
	return mux
}

// serveUntilDone 服务 HTTP 直到出错或收到退出信号，然后依次排空 HTTP、Pi 会话与 gRPC。
func serveUntilDone(ctx context.Context, httpServer *http.Server, chat *agentchat.Service, scheduler <-chan struct{}, grpcServer *grpc.Server) {
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
	chat.Wait(shutdownCtx)
	select {
	case <-scheduler:
	case <-shutdownCtx.Done():
		slog.Warn("等待定时任务收尾超时")
	}
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

// startIntegrationDelivery 有 HOST_CREDENTIAL_KEY 才能解开签名密钥、投递出站消息；
// 订阅本身要全局管理员显式创建，不再另设全局开关。没有主密钥时只维护本地队列与保留期。
func startIntegrationDelivery(ctx context.Context, client *ent.Client, vault *hostimport.Vault, allow *integration.OutboundAllow) {
	worker := &integration.Worker{DB: client, Vault: vault, Allow: allow}
	if vault == nil {
		go worker.RunMaintenance(ctx)
		return
	}
	if allow.Locked != "" {
		if _, err := integration.CleanAllow(strings.Split(allow.Locked, ",")); err != nil {
			slog.Error("INTEGRATION_WEBHOOK_ALLOW 无效", "err", err)
			os.Exit(1)
		}
	}
	go worker.Run(ctx)
}

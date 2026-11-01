package intel

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/setting"
	"openxdr/server/internal/cluster"
)

// 情报订阅：内置几个免费、稳定、格式简单的公开源，在控制台开关，集群单活定时拉取。
//
// 订阅条目以 source=feed:<id> 落库，每次同步刷新有效期：源里撤下的条目到期自然失效，
// 拉取暂时失败也不会马上丢情报；关掉的源立即清掉。手工录入的同值情报优先，订阅不覆盖。
// 外部数据不可信：内网与保留地址剔除，域名、哈希逐条校验，下载大小与条目数都有上限。

// Feed 一个内置情报源。
type Feed struct {
	ID       string
	Name     string
	URL      string
	Severity int16
	// 带密钥的下载地址仅在请求时拼接，接口仍返回公开说明页。
	authURL  string
	authFile string
	parse    func(io.Reader) ([]Entry, error)
}

// Entry 源里解析出的一条 IOC。
type Entry struct {
	Kind, Value, Note string
}

// Catalog 内置情报源。只收能直接撞上本平台事件字段的 IOC：IP、域名、文件哈希。
var Catalog = []Feed{
	{ID: "feodo", Name: "abuse.ch Feodo Tracker：僵尸网络 C2 服务器 IP",
		URL: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", Severity: 5, parse: parseList},
	{ID: "threatfox", Name: "abuse.ch ThreatFox：近期恶意软件 IOC（IP、域名、哈希）",
		URL: "https://threatfox.abuse.ch/export/", Severity: 4, authURL: "https://threatfox-api.abuse.ch/v2/files/exports/", authFile: "full.csv.zip", parse: parseThreatFoxZIP},
	{ID: "urlhaus", Name: "abuse.ch URLhaus：恶意软件分发域名",
		URL: "https://urlhaus.abuse.ch/api/", Severity: 4, authURL: "https://urlhaus-api.abuse.ch/v2/files/exports/", authFile: "hostfile.txt", parse: parseHostsFile},
	{ID: "et-compromised", Name: "Emerging Threats：已知失陷主机 IP",
		URL: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", Severity: 3, parse: parseList},
}

const (
	feedSettingsKey = "intel_feeds"
	feedStatusKey   = "intel_feed_status"
	// 单个源的下载与条目上限：超限拒绝本次更新，保留原有情报。
	maxFeedBytes   = 50 << 20
	maxFeedEntries = 100_000
)

var errFeedEntryLimit = errors.New("情报源超过 10 万条上限")

// FeedSettings 控制台保存的开关。从没保存过时内置源全部开启——没有情报等于没开碰撞。
type FeedSettings struct {
	Enabled []string `json:"enabled"`
}

// FeedStatus 每个源最近一次同步的结果。
type FeedStatus struct {
	SyncedAt    *time.Time `json:"syncedAt"`
	AttemptedAt *time.Time `json:"attemptedAt"`
	Count       int        `json:"count"`
	Error       string     `json:"error,omitempty"`
}

type Feeds struct {
	DB      *sql.DB
	Client  *ent.Client
	HTTP    *http.Client
	AuthKey func(context.Context) string
	// 同步周期；条目有效期取它的 8 倍，连续几次拉不到也不会断情报
	Interval time.Duration
}

func (f *Feeds) ttl() time.Duration { return 8 * f.Interval }

// Run 集群单活：启动即同步一次，之后按周期同步。
func (f *Feeds) Run(ctx context.Context) {
	ticker := time.NewTicker(f.Interval)
	defer ticker.Stop()
	for {
		if err := f.Sync(ctx); err != nil {
			slog.Error("情报订阅同步失败", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (f *Feeds) Settings(ctx context.Context) (FeedSettings, error) {
	var s FeedSettings
	err := f.getSetting(ctx, feedSettingsKey, &s)
	if ent.IsNotFound(err) {
		for _, feed := range Catalog {
			s.Enabled = append(s.Enabled, feed.ID)
		}
		return s, nil
	}
	if err != nil {
		return s, err
	}
	return s, s.validate()
}

// SaveSettings 保存开关，只认内置源 ID。
func (f *Feeds) SaveSettings(ctx context.Context, s FeedSettings) error {
	if err := s.validate(); err != nil {
		return err
	}
	return f.putSetting(ctx, feedSettingsKey, s)
}

func (s FeedSettings) validate() error {
	if s.Enabled == nil {
		return errors.New("情报订阅配置缺少 enabled 数组")
	}
	for _, id := range s.Enabled {
		if !slices.ContainsFunc(Catalog, func(feed Feed) bool { return feed.ID == id }) {
			return fmt.Errorf("未知情报源：%s", id)
		}
	}
	return nil
}

func (f *Feeds) Status(ctx context.Context) (map[string]FeedStatus, error) {
	status := map[string]FeedStatus{}
	if err := f.getSetting(ctx, feedStatusKey, &status); err != nil && !ent.IsNotFound(err) {
		return nil, err
	}
	// 旧版本把失败时间也写入 syncedAt；无法还原成功时间时明确留空。
	for id, st := range status {
		if st.AttemptedAt == nil {
			st.AttemptedAt = st.SyncedAt
			if st.Error != "" {
				st.SyncedAt = nil
			}
			status[id] = st
		}
	}
	return status, nil
}

// Sync 拉取开启的源并落库，清掉关闭的源与过期条目。集群内串行，控制台「立即同步」与定时任务不会撞车。
func (f *Feeds) Sync(ctx context.Context) error {
	return cluster.WithLock(ctx, f.DB, "intel-feeds-sync", func() error {
		settings, err := f.Settings(ctx)
		if err != nil {
			return err
		}
		enabled := settings.Enabled
		status, err := f.Status(ctx)
		if err != nil {
			return err
		}
		for _, feed := range Catalog {
			if !slices.Contains(enabled, feed.ID) {
				if _, err := f.DB.ExecContext(ctx, `DELETE FROM intels WHERE source = $1`, "feed:"+feed.ID); err != nil {
					return err
				}
				delete(status, feed.ID)
				continue
			}
			now := time.Now()
			st := status[feed.ID]
			st.AttemptedAt = &now
			entries, err := f.fetch(ctx, feed)
			if err == nil {
				err = f.store(ctx, feed, entries, now.Add(f.ttl()))
			}
			if err != nil {
				// 失败保留上次的条目数，旧条目在有效期内照常生效
				st.Error = err.Error()
				slog.Warn("情报源同步失败", "feed", feed.ID, "err", err)
			} else {
				st.Count, st.Error, st.SyncedAt = len(entries), "", &now
				slog.Info("情报源已同步", "feed", feed.ID, "count", len(entries))
			}
			status[feed.ID] = st
		}
		if _, err := f.DB.ExecContext(ctx, `DELETE FROM intels WHERE source LIKE 'feed:%' AND expires_at < now()`); err != nil {
			return err
		}
		return f.putSetting(ctx, feedStatusKey, status)
	})
}

func (f *Feeds) fetch(ctx context.Context, feed Feed) ([]Entry, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	address := feed.URL
	if feed.authURL != "" {
		key := ""
		if f.AuthKey != nil {
			key = f.AuthKey(ctx)
		}
		if key == "" {
			return nil, errors.New("请在系统设置 → 外部情报查询中配置 abuse.ch Auth-Key")
		}
		address = feed.authURL + url.PathEscape(key) + "/" + feed.authFile
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, errors.New("情报源请求地址无效")
	}
	req.Header.Set("User-Agent", "OpenXDR-intel-feeds")
	client := f.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	if feed.authURL != "" {
		copy := *client
		copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &copy
	}
	resp, err := client.Do(req)
	if err != nil {
		// url.Error 包含请求地址，认证导出的密钥在路径中，不能直接写日志或回显。
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("情报源连接失败，请检查网络或代理配置")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("情报源返回 %d", resp.StatusCode)
	}
	limited := &io.LimitedReader{R: resp.Body, N: maxFeedBytes + 1}
	entries, err := feed.parse(limited)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, errFeedEntryLimit) {
			return nil, errFeedEntryLimit
		}
		return nil, errors.New("情报源解析失败：数据不完整或格式错误")
	}
	if limited.N == 0 {
		return nil, errors.New("情报源超过 50 MiB 下载上限")
	}
	if len(entries) == 0 {
		// 空源多半是格式变了或被限流，不能当成"情报全部撤销"
		return nil, errors.New("情报源没有解析出任何条目")
	}
	if len(entries) > maxFeedEntries {
		return nil, errFeedEntryLimit
	}
	return entries, nil
}

// store 一条 SQL 批量写入：已有的订阅条目刷新有效期，手工情报不碰。
func (f *Feeds) store(ctx context.Context, feed Feed, entries []Entry, expires time.Time) error {
	ids, kinds, values, notes := make([]string, len(entries)), make([]string, len(entries)), make([]string, len(entries)), make([]string, len(entries))
	for i, e := range entries {
		ids[i], kinds[i], values[i], notes[i] = uuid.Must(uuid.NewV7()).String(), e.Kind, e.Value, e.Note
	}
	_, err := f.DB.ExecContext(ctx, `
INSERT INTO intels (id, created_at, kind, value, source, severity, note, expires_at, matched_count)
SELECT i, now(), k, v, $5, $6, NULLIF(n, ''), $7, 0
FROM unnest($1::uuid[], $2::text[], $3::text[], $4::text[]) AS t(i, k, v, n)
ON CONFLICT (kind, value) DO UPDATE
SET source = EXCLUDED.source, severity = EXCLUDED.severity, note = EXCLUDED.note, expires_at = EXCLUDED.expires_at
WHERE intels.source LIKE 'feed:%'`,
		ids, kinds, values, notes, "feed:"+feed.ID, feed.Severity, expires)
	return err
}

func (f *Feeds) getSetting(ctx context.Context, key string, v any) error {
	row, err := f.Client.Setting.Get(ctx, key)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(row.Value)) == "null" {
		return fmt.Errorf("情报订阅配置 %s 不能为 null", key)
	}
	if err := json.Unmarshal(row.Value, v); err != nil {
		return fmt.Errorf("情报订阅配置 %s 格式错误", key)
	}
	return nil
}

func (f *Feeds) putSetting(ctx context.Context, key string, v any) error {
	value, err := json.Marshal(v)
	if err != nil {
		return err
	}
	n, err := f.Client.Setting.Update().Where(setting.IDEQ(key)).SetValue(value).Save(ctx)
	if err != nil || n > 0 {
		return err
	}
	return f.Client.Setting.Create().SetID(key).SetValue(value).Exec(ctx)
}

// --- 解析与校验 ---

var (
	domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$`)
	hashRe   = regexp.MustCompile(`^([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$`)
	// RFC 6598 共享地址不属于 IsPrivate 覆盖的 RFC 1918 私网。
	cgnat = netip.MustParsePrefix("100.64.0.0/10")
)

// normalize 校验并规范化一条 IOC，不合格返回 false。
func normalize(kind, value string) (Entry, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch kind {
	case "ip":
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return Entry{}, false
		}
		addr = addr.Unmap()
		// 内网与保留地址出现在公开情报里只会误伤自己人
		if !addr.IsGlobalUnicast() || addr.IsPrivate() || cgnat.Contains(addr) {
			return Entry{}, false
		}
		return Entry{Kind: "ip", Value: addr.String()}, true
	case "domain":
		value = strings.TrimSuffix(value, ".")
		if len(value) > 253 || !domainRe.MatchString(value) {
			return Entry{}, false
		}
		return Entry{Kind: "domain", Value: value}, true
	case "hash":
		if !hashRe.MatchString(value) {
			return Entry{}, false
		}
		return Entry{Kind: "hash", Value: value}, true
	}
	return Entry{}, false
}

// 解析时去重并限制唯一条目数，避免先积累整份重复数据再分配去重表。
type feedEntries struct {
	entries []Entry
	seen    map[[2]string]bool
}

func (out *feedEntries) add(e Entry) error {
	key := [2]string{e.Kind, e.Value}
	if out.seen[key] {
		return nil
	}
	if len(out.entries) >= maxFeedEntries {
		return errFeedEntryLimit
	}
	if out.seen == nil {
		out.seen = make(map[[2]string]bool)
	}
	out.seen[key] = true
	out.entries = append(out.entries, e)
	return nil
}

func lines(r io.Reader, each func(string) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			if err := each(line); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

// parseList 每行一个 IP。
func parseList(r io.Reader) ([]Entry, error) {
	var out feedEntries
	err := lines(r, func(line string) error {
		if e, ok := normalize("ip", strings.Fields(line)[0]); ok {
			return out.add(e)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out.entries, nil
}

// parseHostsFile hosts 格式：127.0.0.1<空白>域名。
func parseHostsFile(r io.Reader) ([]Entry, error) {
	var out feedEntries
	err := lines(r, func(line string) error {
		if fields := strings.Fields(line); len(fields) >= 2 {
			if e, ok := normalize("domain", fields[1]); ok {
				return out.add(e)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out.entries, nil
}

// parseThreatFox ThreatFox CSV 导出。URL 只取主机为 IP 的：挂在公共平台上的恶意 URL
// 若按主机名入库，访问正常的 GitHub、Google 也会报警。
func parseThreatFox(r io.Reader) ([]Entry, error) {
	var body strings.Builder
	err := lines(r, func(line string) error {
		body.WriteString(line + "\n")
		return nil
	})
	if err != nil {
		return nil, err
	}
	rd := csv.NewReader(strings.NewReader(body.String()))
	rd.TrimLeadingSpace = true
	rd.FieldsPerRecord = -1
	var out feedEntries
	for {
		rec, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("ThreatFox CSV 格式损坏")
		}
		if len(rec) < 8 {
			return nil, errors.New("ThreatFox CSV 字段不足")
		}
		value, typ, malware := rec[2], rec[3], rec[7]
		var e Entry
		var ok bool
		switch {
		case typ == "ip:port":
			host, _, _ := strings.Cut(value, ":")
			e, ok = normalize("ip", host)
		case typ == "domain":
			e, ok = normalize("domain", value)
		case strings.HasSuffix(typ, "_hash"):
			e, ok = normalize("hash", value)
		case typ == "url":
			if u, err := url.Parse(value); err == nil {
				e, ok = normalize("ip", u.Hostname())
			}
		}
		if ok {
			if malware != "" && malware != "None" {
				e.Note = "ThreatFox：" + malware
			}
			if err := out.add(e); err != nil {
				return nil, err
			}
		}
	}
	return out.entries, nil
}

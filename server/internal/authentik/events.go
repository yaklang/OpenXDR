// Package authentik 对接 Authentik（SSO）：把登录成功与失败转成认证事件进检测管线，
// 爆破得手、横向喷洒、研判就能看到 SSO 上的攻击；处置侧可停用被攻破的账号（见 account.go）。
//
// 只用一个最小权限的服务账号令牌：查看事件、查看用户、修改用户。事件只取用户名、来源地址、时间与地理位置，
// 失败事件 context 里的口令字段（Authentik 自己打码）一律不取。
package authentik

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/internal/eventbus"
	"openxdr/server/internal/ingest"
)

// Client Authentik API 客户端：固定实例根地址（HTTPS），Bearer 令牌，不跟随跳转
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = strings.NewReader(string(b))
	} else {
		reader = strings.NewReader("")
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.BaseURL, "/")+"/api/v3/"+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return errors.New("连接 Authentik 失败")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("Authentik 返回 HTTP %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out); err != nil {
		return errors.New("Authentik 响应格式无效")
	}
	return nil
}

// event Authentik 事件里用得到的字段
type event struct {
	PK     string `json:"pk"`
	Action string `json:"action"`
	User   struct {
		Username string `json:"username"`
	} `json:"user"`
	ClientIP string    `json:"client_ip"`
	Created  time.Time `json:"created"`
	Context  struct {
		Username string `json:"username"`
		Geo      struct {
			Country string `json:"country"`
			City    string `json:"city"`
		} `json:"geo"`
	} `json:"context"`
}

// 登录成功与失败；OCSF Authentication 的 status_id：1 成功、2 失败
var actions = map[string]int{"login": 1, "login_failed": 2}

// 每轮每种事件最多翻这么多页（每页 100 条），积压再多也分几轮补
const maxPages = 20

const cursorKey = "authentik.events.cursor"

// 首次启动只回看这么久：更早的登录失败早已过了爆破判定窗口，补进来只会造出过期的告警
const firstLookback = time.Hour

// Poller 定时拉 Authentik 的登录事件，挂到运行 Authentik 的资产上发进事件总线
type Poller struct {
	API      *Client
	DB       *ent.Client
	SQL      *sql.DB
	Events   eventbus.Bus
	Host     string // 运行 Authentik 的资产主机名
	Interval time.Duration
}

func (p *Poller) Run(ctx context.Context) {
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	for {
		if n, err := p.Poll(ctx); err != nil && ctx.Err() == nil {
			slog.Error("拉取 Authentik 登录事件失败", "err", err)
		} else if n > 0 {
			slog.Info("Authentik 登录事件", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Poll 拉一轮：按时间倒序翻页，翻到不晚于游标的就停；按时间正序发出，游标推进到最新一条。
// 同一时刻的事件靠事件 pk 生成的稳定 ID 去重，游标取「不早于」不会漏
func (p *Poller) Poll(ctx context.Context) (int, error) {
	a, err := p.DB.Asset.Query().Where(asset.HostnameEQ(p.Host), asset.RetiredAtIsNil()).Only(ctx)
	if err != nil {
		return 0, fmt.Errorf("找不到运行 Authentik 的资产 %s：%w", p.Host, err)
	}
	since, err := p.cursor(ctx)
	if err != nil {
		return 0, err
	}
	var batch []event
	for action := range actions {
		got, err := p.fetch(ctx, action, since)
		if err != nil {
			return 0, err
		}
		batch = append(batch, got...)
	}
	sort.Slice(batch, func(i, j int) bool { return batch[i].Created.Before(batch[j].Created) })
	os := ""
	if a.Os != nil {
		os = *a.Os
	}
	for _, ev := range batch {
		env, ok := envelope(ev, a.ID, os)
		if !ok {
			continue
		}
		if err := p.Events.Publish(ctx, env); err != nil {
			return 0, err
		}
	}
	if len(batch) > 0 {
		if err := p.save(ctx, batch[len(batch)-1].Created); err != nil {
			return 0, err
		}
	}
	return len(batch), nil
}

func (p *Poller) fetch(ctx context.Context, action string, since time.Time) ([]event, error) {
	var out []event
	for page := 1; page <= maxPages; page++ {
		var resp struct {
			Pagination struct {
				Next int `json:"next"`
			} `json:"pagination"`
			Results []event `json:"results"`
		}
		q := url.Values{"action": {action}, "ordering": {"-created"}, "page_size": {"100"}, "page": {fmt.Sprint(page)}}
		if err := p.API.do(ctx, http.MethodGet, "events/events/?"+q.Encode(), nil, &resp); err != nil {
			return nil, err
		}
		for _, ev := range resp.Results {
			if ev.Created.Before(since) {
				return out, nil
			}
			out = append(out, ev)
		}
		if resp.Pagination.Next == 0 {
			break
		}
	}
	return out, nil
}

// envelope 一条 Authentik 登录事件转成认证事件（OCSF 3002）。拿不到用户名的不发：爆破判定按用户名关联
func envelope(ev event, assetID uuid.UUID, assetOS string) (ingest.Envelope, bool) {
	status, ok := actions[ev.Action]
	if !ok || ev.PK == "" {
		return ingest.Envelope{}, false
	}
	user := ev.User.Username
	if status == 2 && ev.Context.Username != "" {
		user = ev.Context.Username // 失败时 user 是 AnonymousUser，尝试的用户名在 context 里
	}
	if user == "" || user == "AnonymousUser" || len(user) > 150 {
		return ingest.Envelope{}, false
	}
	src := map[string]any{}
	if ip, err := netip.ParseAddr(ev.ClientIP); err == nil {
		src["ip"] = ip.String()
	}
	if ev.Context.Geo.Country != "" {
		src["location"] = map[string]any{"country": ev.Context.Geo.Country, "city": ev.Context.Geo.City}
	}
	statusName := map[int]string{1: "Success", 2: "Failure"}[status]
	raw, _ := json.Marshal(map[string]any{
		"activity_id": 1, "status_id": status, "status": statusName,
		"user":          map[string]any{"name": user},
		"src_endpoint":  src,
		"service":       map[string]any{"name": "authentik"},
		"auth_protocol": "SSO",
		"metadata":      map[string]any{"product": map[string]any{"name": "Authentik"}, "uid": ev.PK},
	})
	return ingest.Envelope{
		Version: ingest.EnvelopeVersion, ID: ingest.StableID("authentik", ev.PK), PartitionKey: assetID.String(),
		Timestamp: ev.Created, ClassUID: 3002, Source: "authentik",
		AssetID: &assetID, AssetOS: assetOS, Username: user, Raw: raw,
	}, true
}

func (p *Poller) cursor(ctx context.Context) (time.Time, error) {
	var raw []byte
	err := p.SQL.QueryRowContext(ctx, `SELECT value FROM settings WHERE id=$1`, cursorKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Now().Add(-firstLookback), nil
	}
	if err != nil {
		return time.Time{}, err
	}
	var t time.Time
	if err := json.Unmarshal(raw, &t); err != nil {
		return time.Now().Add(-firstLookback), nil
	}
	return t, nil
}

func (p *Poller) save(ctx context.Context, t time.Time) error {
	b, _ := json.Marshal(t)
	_, err := p.SQL.ExecContext(ctx, `INSERT INTO settings (id, value, updated_at) VALUES ($1, $2::jsonb, now())
ON CONFLICT (id) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, cursorKey, string(b))
	return err
}

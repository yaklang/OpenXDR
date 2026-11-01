package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var VersionPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,95}$`)
var SessionPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type EngineConfig struct {
	Hosted         bool     `json:"hosted,omitempty"`
	Attachment     string   `json:"attachment"`
	Mode           string   `json:"mode"`
	Origin         string   `json:"origin"`
	Upstream       string   `json:"upstream,omitempty"`
	Prefix         string   `json:"prefix"`
	TrustedProxies []string `json:"trustedProxies,omitempty"`
	Entries        int      `json:"entries"`
	Branches       int      `json:"branches"`
	Depth          int      `json:"depth"`
	MaxNodes       int      `json:"maxNodes"`
	RequestLimit   int      `json:"requestLimit"`
}

func DefaultConfig() EngineConfig {
	return EngineConfig{Attachment: "standalone", Mode: "observe", Prefix: "/_dygk", Entries: 3, Branches: 4, Depth: 4, MaxNodes: 256, RequestLimit: 120}
}

func DecodeConfig(raw []byte) (EngineConfig, error) {
	c := DefaultConfig()
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	if d.Decode(new(any)) != io.EOF {
		return c, fmt.Errorf("配置包含多余内容")
	}
	if c.Attachment != "standalone" && c.Attachment != "gateway" {
		return c, fmt.Errorf("不支持的接入方式")
	}
	if c.Mode != "observe" && c.Mode != "block" && c.Mode != "quarantine" {
		return c, fmt.Errorf("不支持的动作模式")
	}
	if !regexp.MustCompile(`^/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*$`).MatchString(c.Prefix) {
		return c, fmt.Errorf("诱饵前缀无效")
	}
	if c.Origin != "" {
		u, e := url.Parse(c.Origin)
		if e != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
			return c, fmt.Errorf("公开 origin 无效")
		}
	}
	if c.Attachment == "gateway" {
		u, e := url.Parse(c.Upstream)
		if e != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return c, fmt.Errorf("业务 upstream 无效")
		}
	} else if c.Upstream != "" {
		return c, fmt.Errorf("独立模式不接受业务 upstream")
	}
	if len(c.TrustedProxies) > 16 {
		return c, fmt.Errorf("可信代理过多")
	}
	for _, ip := range c.TrustedProxies {
		if net.ParseIP(ip) == nil {
			return c, fmt.Errorf("可信代理须为明确 IP")
		}
	}
	if c.Entries < 1 || c.Entries > 8 || c.Branches < 1 || c.Branches > 64 || c.Depth < 1 || c.Depth > 8 || c.MaxNodes < 1 || c.MaxNodes > 4096 || c.RequestLimit < 4 || c.RequestLimit > 1000 {
		return c, fmt.Errorf("资源参数超出边界")
	}
	return c, nil
}

type Release struct {
	Engine      string `json:"engine"`
	Version     string `json:"version"`
	Digest      string `json:"digest"`
	Protocol    int    `json:"protocol"`
	StateSchema string `json:"stateSchema"`
}

func (r Release) Validate() error {
	if (r.Engine != "native" && r.Engine != "dygk") || !VersionPattern.MatchString(r.Version) || !DigestPattern.MatchString(r.Digest) || r.Protocol != ProtocolVersion || !VersionPattern.MatchString(r.StateSchema) {
		return fmt.Errorf("引擎发布信息不受支持")
	}
	return nil
}

type RuntimeConfig struct {
	Manifest
	Revision      string       `json:"revision"`
	Release       Release      `json:"release"`
	Config        EngineConfig `json:"config"`
	StopRequested bool         `json:"stopRequested"`
}
type Handshake struct {
	Instance string  `json:"instance"`
	Revision string  `json:"revision"`
	Release  Release `json:"release"`
}
type Fact struct {
	ID       string    `json:"eventId"`
	Epoch    string    `json:"streamEpoch"`
	Sequence int64     `json:"sequence"`
	Time     time.Time `json:"occurredAt"`
	Session  string    `json:"session"`
	Kind     string    `json:"kind"`
	Count    int       `json:"count,omitempty"`
}

var FactKinds = map[string]string{"entry": "http_session", "archive": "http_archive", "verify_view": "http_verify", "honeypot_triggered": "dygk_triggered", "honeypot_completed": "http_completed", "ip_banned": "web_source_blocked", "blocked_request": "web_request_blocked", "quarantine_started": "web_source_quarantined", "quarantine_request": "web_quarantine_request", "export_gap": "engine_export_gap"}

func (f Fact) Validate() error {
	if _, e := uuid.Parse(f.ID); e != nil || f.ID == uuid.Nil.String() {
		return fmt.Errorf("事件 ID 无效")
	}
	if _, e := uuid.Parse(f.Epoch); e != nil || f.Epoch == uuid.Nil.String() {
		return fmt.Errorf("事件流代次无效")
	}
	if f.Sequence < 1 || f.Time.IsZero() || f.Time.After(time.Now().Add(5*time.Minute)) || f.Count < 0 || f.Count > 1000000 {
		return fmt.Errorf("事件字段无效")
	}
	if _, ok := FactKinds[f.Kind]; !ok && !nativeFact(f.Kind) {
		return fmt.Errorf("未知事实类型")
	}
	if f.Session != "" && !SessionPattern.MatchString(f.Session) {
		return fmt.Errorf("会话标识无效")
	}
	if f.Kind == "honeypot_triggered" && strings.TrimSpace(f.Session) == "" {
		return fmt.Errorf("验证触发缺少会话")
	}
	return nil
}

func nativeFact(kind string) bool {
	for _, carrier := range []string{"ssh", "http", "file", "shell"} {
		if ValidEvent(carrier, kind) {
			return true
		}
	}
	return false
}

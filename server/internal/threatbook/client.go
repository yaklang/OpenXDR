// Package threatbook 查询微步 IP 分析情报；不把单一供应商标签直接变成自动处置。
package threatbook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var ErrQuota = errors.New("微步查询达到本地额度上限，请稍后重试")
var ErrDisabled = errors.New("尚未配置微步 API Key")

// PublicIP 不向外部供应商发送内网、回环、链路本地、文档或共享地址。
func PublicIP(value string) (string, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || ip.Zone() != "" {
		return "", errors.New("需要有效的公网 IP")
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsUnspecified() {
		return "", errors.New("仅支持查询公网 IP")
	}
	for _, prefix := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32"} {
		if netip.MustParsePrefix(prefix).Contains(ip) {
			return "", errors.New("保留地址不能查询外部情报")
		}
	}
	return ip.String(), nil
}

type Result struct {
	Provider  string          `json:"provider"`
	IP        string          `json:"ip"`
	QueriedAt time.Time       `json:"queriedAt"`
	ExpiresAt time.Time       `json:"expiresAt"`
	Cached    bool            `json:"cached"`
	Judgments []string        `json:"judgments"`
	Data      json.RawMessage `json:"data"`
}

// Query 只调用官方 IP 分析接口，不使用仅适合入站流量的 IP 信誉接口。
func Query(ctx context.Context, client *http.Client, key, ip string) (Result, error) {
	result := Result{Provider: "threatbook", IP: ip}
	if key == "" {
		return result, ErrDisabled
	}
	ip, err := PublicIP(ip)
	if err != nil {
		return result, err
	}
	form := url.Values{"apikey": {key}, "resource": {ip}, "lang": {"zh"}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.threatbook.cn/v3/ip/query", strings.NewReader(form.Encode()))
	if err != nil {
		return result, errors.New("无法构造微步请求")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	// 无论调用方如何配置，都禁止重定向携带密钥。
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := copyClient.Do(request)
	if err != nil {
		return result, errors.New("连接微步失败，请检查网络与代理配置")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, fmt.Errorf("微步返回 HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (256<<10)+1))
	if err != nil || len(data) > 256<<10 {
		return result, errors.New("微步响应读取失败或超过 256 KiB")
	}
	var body struct {
		Code *int                       `json:"response_code"`
		IPs  map[string]json.RawMessage `json:"ips"`
	}
	if json.Unmarshal(data, &body) != nil || body.Code == nil {
		return result, errors.New("微步返回无效响应")
	}
	if *body.Code != 0 {
		return result, fmt.Errorf("微步业务错误 %d，请检查接口授权、出口 IP 绑定与配额", *body.Code)
	}
	raw := body.IPs[ip]
	var details struct {
		Judgments []string `json:"judgments"`
	}
	if len(raw) == 0 || string(raw) == "null" || json.Unmarshal(raw, &details) != nil {
		return result, errors.New("微步响应缺少所查询 IP 的结果")
	}
	result.IP = ip
	result.Data = raw
	result.Judgments = details.Judgments
	if result.Judgments == nil {
		result.Judgments = []string{}
	}
	result.QueriedAt = time.Now().UTC()
	result.ExpiresAt = result.QueriedAt.Add(24 * time.Hour)
	return result, nil
}

package aiconf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Models 仅从管理员指定的同一 API 获取模型标识，不推断工具或图像能力。
func Models(ctx context.Context, c Config) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+"/models", nil)
	if err != nil {
		return nil, errors.New("模型服务地址无效")
	}
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("连接模型列表接口失败")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("模型列表接口返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
	if err != nil || len(body) > 1024*1024 {
		return nil, errors.New("模型列表响应过大或读取失败")
	}
	var out struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &out) != nil {
		return nil, errors.New("模型列表不是兼容的 JSON 格式")
	}
	ids := []string{}
	seen := map[string]bool{}
	for _, row := range out.Data {
		if row.ID == "" || len(row.ID) > 128 || strings.ContainsAny(row.ID, ", \t\r\n") || seen[row.ID] {
			continue
		}
		seen[row.ID] = true
		ids = append(ids, row.ID)
		if len(ids) >= 1000 {
			break
		}
	}
	slices.Sort(ids)
	return ids, nil
}

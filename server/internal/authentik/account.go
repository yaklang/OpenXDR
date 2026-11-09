package authentik

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
)

// Accounts 停用与恢复 SSO 账号，供自主响应在爆破得手时锁住被攻破的账号。
//
// 永远不碰超级管理员、服务账号和 Protected 里的账号：自动处置被人利用来刷停用的话，
// 最坏是普通用户暂时登不上，不会把管理员和平台自己锁在门外
type Accounts struct {
	API       *Client
	Protected map[string]bool
}

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9@._+-]{1,150}$`)

type user struct {
	PK          int    `json:"pk"`
	Username    string `json:"username"`
	IsActive    bool   `json:"is_active"`
	IsSuperuser bool   `json:"is_superuser"`
	Type        string `json:"type"`
}

func (a *Accounts) find(ctx context.Context, username string) (*user, error) {
	if !usernameRe.MatchString(username) {
		return nil, errors.New("用户名格式无效")
	}
	var resp struct {
		Results []user `json:"results"`
	}
	if err := a.API.do(ctx, http.MethodGet, "core/users/?"+url.Values{"username": {username}}.Encode(), nil, &resp); err != nil {
		return nil, err
	}
	for _, u := range resp.Results {
		if u.Username == username {
			return &u, nil
		}
	}
	return nil, fmt.Errorf("Authentik 里没有账号 %s", username)
}

// refuse 不能自动停用的账号：返回原因
func (a *Accounts) refuse(u *user) string {
	switch {
	case u.IsSuperuser:
		return "是超级管理员，不自动停用"
	case u.Type != "internal" && u.Type != "external":
		return "是服务账号，不自动停用"
	case a.Protected[u.Username]:
		return "在保护名单里，不自动停用"
	}
	return ""
}

func (a *Accounts) set(ctx context.Context, u *user, active bool) error {
	return a.API.do(ctx, http.MethodPatch, fmt.Sprintf("core/users/%d/", u.PK), map[string]bool{"is_active": active}, nil)
}

// Disable 停用账号。已经停用的算达成
func (a *Accounts) Disable(ctx context.Context, username string) (string, error) {
	u, err := a.find(ctx, username)
	if err != nil {
		return "", err
	}
	if why := a.refuse(u); why != "" {
		return "", fmt.Errorf("SSO 账号 %s %s", username, why)
	}
	if !u.IsActive {
		return "SSO 账号 " + username + " 原本就是停用状态", nil
	}
	if err := a.set(ctx, u, false); err != nil {
		return "", err
	}
	return "已在 Authentik 停用 SSO 账号 " + username + "（改密后人工恢复）", nil
}

// Enable 恢复账号
func (a *Accounts) Enable(ctx context.Context, username string) (string, error) {
	u, err := a.find(ctx, username)
	if err != nil {
		return "", err
	}
	if u.IsActive {
		return "SSO 账号 " + username + " 已经是启用状态", nil
	}
	if err := a.set(ctx, u, true); err != nil {
		return "", err
	}
	return "已在 Authentik 恢复 SSO 账号 " + username, nil
}

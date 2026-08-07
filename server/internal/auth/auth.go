// Package auth 登录会话与 RBAC，包在业务 API 外层：认证不过的请求到不了业务代码。
//
// 会话是不透明 token：客户端拿随机值，库里只存 SHA-256，删行即吊销。
// 权限是一张"路径 + 方法 → 最低角色"的表，不在 handler 里撒 if。
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"openxdr/server/ent"
	"openxdr/server/ent/session"
	"openxdr/server/ent/user"
	"openxdr/server/internal/audit"
)

const (
	CookieName = "openxdr_session"
	sessionTTL = 7 * 24 * time.Hour
	// "wrong-password" 的 bcrypt 哈希，用户不存在时陪跑用
	dummyHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
)

// 角色等级。数值只用于比较，不落库。
var roleRank = map[string]int{"viewer": 1, "analyst": 2, "admin": 3}

// ValidRole 供用户管理 API 校验输入。
func ValidRole(role string) bool { _, ok := roleRank[role]; return ok }

// minRole 请求要过的最低角色门槛。
func minRole(method, path string) string {
	switch {
	case strings.HasPrefix(path, "/api/users"), strings.HasPrefix(path, "/api/audit"):
		return "admin"
	case method == http.MethodGet:
		return "viewer"
	default:
		return "analyst"
	}
}

type userKey struct{}

// From 取当前登录用户，认证中间件保证业务代码里一定拿得到。
func From(ctx context.Context) *ent.User {
	u, _ := ctx.Value(userKey{}).(*ent.User)
	return u
}

// Bootstrap 首次启动时创建 admin。密码取 ADMIN_PASSWORD，
// 未配置则生成随机密码打印一次——绝不留默认口令这种后门。
func Bootstrap(ctx context.Context, db *ent.Client) error {
	n, err := db.User.Query().Count(ctx)
	if err != nil || n > 0 {
		return err
	}
	password := os.Getenv("ADMIN_PASSWORD")
	generated := password == ""
	if generated {
		password = rand.Text()
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := db.User.Create().
		SetUsername("admin").SetPasswordHash(string(hash)).SetRole("admin").
		Exec(ctx); err != nil {
		return err
	}
	if generated {
		slog.Warn("已创建初始 admin 账号，请立即登录改密", "password", password)
	} else {
		slog.Info("已创建初始 admin 账号（密码来自 ADMIN_PASSWORD）")
	}
	return nil
}

// Middleware 处理登录/登出/me，其余请求验会话、查角色后放行到 inner。
func Middleware(db *ent.Client, inner http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) { login(db, w, r) })
	mux.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) { logout(db, w, r) })

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		u := authenticate(db, r)
		if u == nil {
			http.Error(w, "未登录", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api/me" {
			writeJSON(w, map[string]string{"username": u.Username, "role": u.Role})
			return
		}
		if roleRank[u.Role] < roleRank[minRole(r.Method, r.URL.Path)] {
			http.Error(w, "当前角色无此权限", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), userKey{}, u)
		ctx = audit.WithActor(ctx, u.Username)
		inner.ServeHTTP(w, r.WithContext(ctx))
	})
	return mux
}

func authenticate(db *ent.Client, r *http.Request) *ent.User {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return nil
	}
	hash := sha256.Sum256([]byte(cookie.Value))
	s, err := db.Session.Query().
		Where(session.TokenHashEQ(hex.EncodeToString(hash[:]))).
		Only(r.Context())
	if err != nil || time.Now().After(s.ExpiresAt) {
		return nil
	}
	u, err := db.User.Get(r.Context(), s.UserID)
	if err != nil {
		return nil
	}
	return u
}

func login(db *ent.Client, w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		http.Error(w, "请求体不是合法 JSON", http.StatusBadRequest)
		return
	}
	ctx := audit.WithActor(r.Context(), body.Username)

	u, err := db.User.Query().Where(user.UsernameEQ(body.Username)).Only(ctx)
	// 用户不存在也走一次 bcrypt，别让响应时间泄露用户名是否存在
	hash := dummyHash
	if err == nil {
		hash = u.PasswordHash
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)) != nil || err != nil {
		audit.Log(ctx, db, r, "login_failed", "", "")
		http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}

	token := rand.Text()
	tokenHash := sha256.Sum256([]byte(token))
	// 顺手清掉该用户的过期会话，不留垃圾
	_, _ = db.Session.Delete().
		Where(session.UserIDEQ(u.ID), session.ExpiresAtLT(time.Now())).
		Exec(ctx)
	if err := db.Session.Create().
		SetTokenHash(hex.EncodeToString(tokenHash[:])).
		SetUserID(u.ID).
		SetExpiresAt(time.Now().Add(sessionTTL)).
		Exec(ctx); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(sessionTTL / time.Second),
	})
	audit.Log(ctx, db, r, "login", "", "")
	writeJSON(w, map[string]string{"username": u.Username, "role": u.Role})
}

func logout(db *ent.Client, w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(CookieName); err == nil {
		hash := sha256.Sum256([]byte(cookie.Value))
		hexHash := hex.EncodeToString(hash[:])
		if s, err := db.Session.Query().Where(session.TokenHashEQ(hexHash)).Only(r.Context()); err == nil {
			if u, err := db.User.Get(r.Context(), s.UserID); err == nil {
				audit.Log(audit.WithActor(r.Context(), u.Username), db, r, "logout", "", "")
			}
			_ = db.Session.DeleteOne(s).Exec(r.Context())
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", HttpOnly: true, MaxAge: -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

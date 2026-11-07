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

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"openxdr/server/ent"
	"openxdr/server/ent/groupmember"
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
	case path == "/api/assets/export" && method == http.MethodPost:
		return "viewer"
	case strings.HasPrefix(path, "/api/system-integrations"), strings.HasPrefix(path, "/api/users"), strings.HasPrefix(path, "/api/audit"), strings.HasPrefix(path, "/api/settings"):
		return "admin"
	// 同意用户协议、结束首次引导代表整个安装，只有 admin 能做；读取对所有人开放
	case strings.HasPrefix(path, "/api/setup") && method != http.MethodGet:
		return "admin"
	// 自主响应开关影响全部主机
	case path == "/api/containments/config":
		return "admin"
	// 情报订阅影响全局检测
	case strings.HasPrefix(path, "/api/intel/feeds") && method != http.MethodGet:
		return "admin"
	// 任务在某个组上的开关由该组管理员决定，handler 按组检查
	case strings.HasPrefix(path, "/api/tasks/") && strings.Contains(path, "/groups/") && method == http.MethodPut:
		return "viewer"
	// 预设任务跨组运行，全局启停与改周期只有 admin 能动
	case strings.HasPrefix(path, "/api/tasks") && method != http.MethodGet:
		return "admin"
	// 组的增删、成员与资产归属只有 admin 能改；列表按成员身份过滤，viewer 可读
	case strings.HasPrefix(path, "/api/groups") && method != http.MethodGet:
		return "admin"
		// Pi 的写权限由具体 handler 按组检查，不能被全局 viewer 角色提前截断。
	case strings.HasPrefix(path, "/api/agent-sessions"), strings.HasPrefix(path, "/api/command-policies"), strings.HasPrefix(path, "/api/approvals"), strings.HasPrefix(path, "/api/enroll-tokens"), strings.HasPrefix(path, "/api/host-import/"):
		return "viewer"
	case strings.HasPrefix(path, "/api/findings/") && strings.HasSuffix(path, "/decision"):
		return "viewer" // 执行决定由 handler 核对当前组 admin，不能被全局 viewer 角色提前拦下。
	case method == http.MethodGet:
		return "viewer"
	default:
		return "analyst"
	}
}

// Allowed 角色 role 是否达到门槛 min。空角色（非成员）什么都过不了。
func Allowed(role, min string) bool { return role != "" && roleRank[role] >= roleRank[min] }

// GroupRole 用户在组内的有效角色：全局 admin 即组 admin，其余看成员记录，非成员返回空。
func GroupRole(ctx context.Context, db *ent.Client, u *ent.User, groupID uuid.UUID) string {
	if u.Role == "admin" {
		return "admin"
	}
	m, err := db.GroupMember.Query().
		Where(groupmember.GroupIDEQ(groupID), groupmember.UserIDEQ(u.ID)).
		Only(ctx)
	if err != nil {
		return ""
	}
	return m.Role
}

type userKey struct{}

// WithUser 把用户挂进上下文。认证中间件之外，后台身份（定时任务）与测试也走这里。
func WithUser(ctx context.Context, u *ent.User) context.Context {
	return context.WithValue(ctx, userKey{}, u)
}

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
		ctx := WithUser(r.Context(), u)
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

	ip := clientIP(r)
	now := time.Now()
	if loginThrottle.Blocked(ip, now) {
		audit.Log(ctx, db, r, "login_throttled", "", "")
		http.Error(w, "尝试过于频繁，稍后再试", http.StatusTooManyRequests)
		return
	}

	u, err := db.User.Query().Where(user.UsernameEQ(body.Username)).Only(ctx)
	// 用户不存在也走一次 bcrypt，别让响应时间泄露用户名是否存在
	hash := dummyHash
	if err == nil {
		hash = u.PasswordHash
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)) != nil || err != nil {
		loginThrottle.Fail(ip, now)
		audit.Log(ctx, db, r, "login_failed", "", "")
		http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}
	loginThrottle.Clear(ip)

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
		Secure: secureCookie(r),
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
	// 属性与登录时一致，浏览器才认得出是同一条 cookie
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: secureCookie(r),
		MaxAge: -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

// secureCookie 是否给会话 cookie 加 Secure：直连 TLS，或反向代理转发的是 https。
// 代理头的值只影响本机响应的 cookie 属性，伪造它顶多让客户端自己收不到明文 cookie。
func secureCookie(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

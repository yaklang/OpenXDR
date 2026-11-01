package api

import (
	"encoding/json"
	"net/http"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"openxdr/server/ent"
	entauditlog "openxdr/server/ent/auditlog"
	"openxdr/server/ent/groupmember"
	"openxdr/server/ent/integration"
	entsession "openxdr/server/ent/session"
	entuser "openxdr/server/ent/user"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/commandgate"
)

type userRow struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
}

// mapUsers 用户管理与审计查询。RBAC 已把 /api/users 与 /api/audit 拦成 admin 专属，
// 这里不再重复查角色。
func mapUsers(api *http.ServeMux, db *ent.Client) {
	api.HandleFunc("GET /api/users", func(w http.ResponseWriter, r *http.Request) {
		users, err := db.User.Query().Order(ent.Asc(entuser.FieldUsername)).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]userRow, len(users))
		for i, u := range users {
			out[i] = userRow{u.ID, u.CreatedAt, u.Username, u.Role}
		}
		writeJSON(w, out)
	})

	api.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil ||
			body.Username == "" || len(body.Password) < 8 || !auth.ValidRole(body.Role) {
			http.Error(w, "username 必填，密码至少 8 位，role 必须是 admin / analyst / viewer", http.StatusBadRequest)
			return
		}
		// 系统身份不是用户，同名账号会让人分不清审计里是谁动的手
		if body.Username == commandgate.SystemActor || body.Username == commandgate.ReviewerActor {
			http.Error(w, "用户名 "+body.Username+" 保留给平台身份（定时任务、AI 审计员）", http.StatusBadRequest)
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		u, err := db.User.Create().
			SetUsername(body.Username).SetPasswordHash(string(hash)).SetRole(body.Role).
			Save(r.Context())
		if ent.IsConstraintError(err) {
			http.Error(w, "用户名已存在", http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "user_created", body.Username, body.Role)
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, userRow{u.ID, u.CreatedAt, u.Username, u.Role})
	})

	api.HandleFunc("DELETE /api/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "无效的 user id", http.StatusBadRequest)
			return
		}
		// 删自己等于把自己锁在门外，禁止
		if self := auth.From(r.Context()); self != nil && self.ID == id {
			http.Error(w, "不能删除当前登录的账号", http.StatusBadRequest)
			return
		}
		tx, err := db.Tx(r.Context())
		if err != nil {
			http.Error(w, "删除用户事务创建失败", 500)
			return
		}
		defer tx.Rollback()
		u, err := tx.User.Query().Where(entuser.IDEQ(id)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(r.Context())
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		active, err := tx.Integration.Query().Where(integration.OwnerIDEQ(id), integration.EnabledEQ(true)).Exist(r.Context())
		if err != nil {
			http.Error(w, "检查集成负责人失败", 500)
			return
		}
		if active {
			http.Error(w, "请先转交或停用该用户负责的系统集成", 409)
			return
		}
		// 会话与组成员关系一并清掉，删号即离场
		if _, err := tx.Session.Delete().Where(entsession.UserIDEQ(id)).Exec(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := tx.GroupMember.Delete().Where(groupmember.UserIDEQ(id)).Exec(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := tx.User.DeleteOneID(id).Exec(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := audit.Checked(r.Context(), tx.AuditLog.Create(), audit.Actor(r.Context()), audit.RemoteAddr(r), "user_deleted", u.Username, ""); err != nil {
			http.Error(w, "删除审计失败", 500)
			return
		}
		if err := tx.Commit(); err != nil {
			http.Error(w, "删除用户事务提交失败", 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	api.HandleFunc("POST /api/users/{id}/password", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "无效的 user id", http.StatusBadRequest)
			return
		}
		var body struct {
			Password string `json:"password"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Password) < 8 {
			http.Error(w, "密码至少 8 位", http.StatusBadRequest)
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		u, err := db.User.UpdateOneID(id).SetPasswordHash(string(hash)).Save(r.Context())
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// 改密吊销既有会话，持有旧凭证的人立即出局
		if _, err := db.Session.Delete().Where(entsession.UserIDEQ(id)).Exec(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "user_password_reset", u.Username, "")
		w.WriteHeader(http.StatusNoContent)
	})

	api.HandleFunc("GET /api/audit", func(w http.ResponseWriter, r *http.Request) {
		const maxAuditRows = 500
		q := db.AuditLog.Query()
		// 关键词在库里筛，否则只能在最近 500 条里找
		if kw := r.URL.Query().Get("q"); kw != "" {
			q = q.Where(entauditlog.Or(
				entauditlog.UsernameContainsFold(kw),
				entauditlog.ActionContainsFold(kw),
				entauditlog.TargetContainsFold(kw),
				entauditlog.DetailContainsFold(kw),
			))
		}
		rows, err := q.
			Order(ent.Desc(entauditlog.FieldTs)).
			Limit(maxAuditRows).
			All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(rows) == maxAuditRows {
			w.Header().Set("X-Truncated", "1")
		}
		type auditRow struct {
			ID         uuid.UUID `json:"id"`
			Ts         time.Time `json:"ts"`
			Username   string    `json:"username"`
			Action     string    `json:"action"`
			Target     *string   `json:"target"`
			Detail     *string   `json:"detail"`
			RemoteAddr string    `json:"remoteAddr"`
		}
		out := make([]auditRow, len(rows))
		for i, a := range rows {
			out[i] = auditRow{a.ID, a.Ts, a.Username, a.Action, a.Target, a.Detail, a.RemoteAddr}
		}
		writeJSON(w, out)
	})
}

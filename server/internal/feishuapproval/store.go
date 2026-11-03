// Package feishuapproval 通过飞书应用私聊绑定审批人，所有决定复用命令审批闸门。
package feishuapproval

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/hostimport"
)

const configKey = "feishu.approval"

type Config struct {
	Enabled  bool   `json:"enabled"`
	AppID    string `json:"app_id"`
	Sealed   []byte `json:"sealed"`
	Revision string `json:"revision"`
}

type Service struct {
	SQL           *sql.DB
	DB            *ent.Client
	Gate          *commandgate.Gate
	Vault         *hostimport.Vault
	HTTP          *http.Client
	mu            sync.RWMutex
	state         string
	diagnostic    map[string]any
	token         string
	tokenRevision string
	tokenUntil    time.Time
}

func (s *Service) recordDiagnostic(values map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.diagnostic == nil {
		s.diagnostic = map[string]any{}
	}
	for k, v := range values {
		s.diagnostic[k] = v
	}
}
func (s *Service) diagnostics() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := map[string]any{}
	for k, v := range s.diagnostic {
		result[k] = v
	}
	return result
}

func (s *Service) EnsureSchema(ctx context.Context) error {
	_, err := s.SQL.ExecContext(ctx, `
 CREATE TABLE IF NOT EXISTS feishu_approval_bindings (
   app_id text NOT NULL, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
   tenant text NOT NULL, open_id text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
   PRIMARY KEY(app_id,user_id), UNIQUE(app_id,tenant,open_id));
 CREATE TABLE IF NOT EXISTS feishu_approval_codes (
   code_hash text PRIMARY KEY, user_id uuid NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
   app_id text NOT NULL, revision text NOT NULL, expires_at timestamptz NOT NULL);
 CREATE TABLE IF NOT EXISTS feishu_approval_deliveries (
   nonce text PRIMARY KEY, approval_id uuid REFERENCES approvals(id) ON DELETE CASCADE,
   user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
   app_id text NOT NULL, revision text NOT NULL, tenant text NOT NULL, open_id text NOT NULL,
   message_id text NOT NULL DEFAULT '', expires_at timestamptz NOT NULL,
   attempts int NOT NULL DEFAULT 0, next_attempt timestamptz NOT NULL DEFAULT now(),
   created_at timestamptz NOT NULL DEFAULT now(), outcome text NOT NULL DEFAULT '',
   UNIQUE(approval_id,user_id));
 CREATE INDEX IF NOT EXISTS feishu_approval_delivery_expiry ON feishu_approval_deliveries(expires_at);
 `)
	return err
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readConfig(ctx context.Context, q queryer, lock bool) (Config, error) {
	query := `SELECT value FROM settings WHERE id=$1`
	if lock {
		query += " FOR SHARE"
	}
	var raw []byte
	err := q.QueryRowContext(ctx, query, configKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Config{}, nil
	}
	var c Config
	if err == nil {
		err = json.Unmarshal(raw, &c)
	}
	return c, err
}

func validConfig(c Config) bool {
	return c.Enabled && c.AppID != "" && len(c.Sealed) > 0 && c.Revision != ""
}
func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}
func newCode() string { return "OXB-" + rand.Text() }

func sqlAudit(ctx context.Context, tx *sql.Tx, username, action, target string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(id,ts,username,action,target,remote_addr) VALUES($1,now(),$2,$3,$4,'feishu')`, uuid.New(), username, action, target)
	return err
}

func (s *Service) bindingCode(ctx context.Context, u *ent.User) (string, error) {
	tx, err := s.SQL.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	c, err := readConfig(ctx, tx, true)
	if err != nil || !validConfig(c) {
		return "", errors.New("飞书审批尚未启用")
	}
	code := newCode()
	_, err = tx.ExecContext(ctx, `INSERT INTO feishu_approval_codes(code_hash,user_id,app_id,revision,expires_at) VALUES($1,$2,$3,$4,now()+interval '10 minutes') ON CONFLICT(user_id) DO UPDATE SET code_hash=excluded.code_hash,app_id=excluded.app_id,revision=excluded.revision,expires_at=excluded.expires_at`, hashCode(code), u.ID, c.AppID, c.Revision)
	if err == nil {
		err = sqlAudit(ctx, tx, u.Username, "feishu_binding_requested", u.ID.String())
	}
	if err == nil {
		err = tx.Commit()
	}
	return code, err
}

func (s *Service) bind(ctx context.Context, c Config, tenant, openID, code string) error {
	if tenant == "" || openID == "" || len(code) < 20 || len(code) > 100 {
		return errors.New("绑定消息无效")
	}
	tx, err := s.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := readConfig(ctx, tx, true)
	if err != nil || !validConfig(current) || current.Revision != c.Revision {
		return errors.New("配置已变化")
	}
	var id uuid.UUID
	err = tx.QueryRowContext(ctx, `DELETE FROM feishu_approval_codes WHERE code_hash=$1 AND app_id=$2 AND revision=$3 AND expires_at>now() RETURNING user_id`, hashCode(code), c.AppID, c.Revision).Scan(&id)
	if err != nil {
		return errors.New("绑定码已过期或已使用")
	}
	u, err := s.DB.User.Get(ctx, id)
	if err != nil {
		return err
	}
	// 已绑定身份不能靠新码替换；须本人先在控制台解绑，旧卡片随之作废。
	_, err = tx.ExecContext(ctx, `INSERT INTO feishu_approval_bindings(app_id,user_id,tenant,open_id) VALUES($1,$2,$3,$4)`, c.AppID, id, tenant, openID)
	if err == nil {
		err = sqlAudit(ctx, tx, u.Username, "feishu_bound", id.String())
	}
	if err == nil {
		err = tx.Commit()
	}
	return err
}

func (s *Service) unbind(ctx context.Context, u *ent.User) error {
	tx, err := s.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM feishu_approval_bindings WHERE user_id=$1`, u.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM feishu_approval_codes WHERE user_id=$1`, u.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM feishu_approval_deliveries WHERE user_id=$1`, u.ID); err != nil {
		return err
	}
	if err = sqlAudit(ctx, tx, u.Username, "feishu_unbound", u.ID.String()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) setState(state string) { s.mu.Lock(); s.state = state; s.mu.Unlock() }
func (s *Service) getState() string      { s.mu.RLock(); defer s.mu.RUnlock(); return s.state }

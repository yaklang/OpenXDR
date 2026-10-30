package agentchat

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// query 的 DSN 必须属于仅能读取当前组视图的专用登录角色，绝不复用平台连接。
func query(ctx context.Context, dsn, statement string) (string, error) {
	if dsn == "" {
		return "", errors.New("当前组未配置只读查询身份")
	}
	// 结尾的分号是写 SQL 的习惯，原样包进限额外壳就成了语法错；中间的分号（多语句）仍由预解析拒绝
	statement = strings.TrimRight(statement, "; \t\r\n")
	if len(statement) == 0 || len(statement) > 16384 {
		return "", errors.New("SQL 长度须为 1–16384")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return "", errors.New("只读查询连接配置无效")
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", errors.New("无法开启只读查询事务")
	}
	defer tx.Rollback()
	var unsafe bool
	if err := tx.QueryRowContext(ctx, `SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&unsafe); err != nil || unsafe {
		return "", errors.New("查询身份不可具备管理或绕过 RLS 权限")
	}
	// 拒绝能直接读取业务基表的账号，只允许管理员预先授予的组视图。
	var baseAccess bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
 SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'
 AND c.relkind IN ('r','p','m','f') AND (has_table_privilege(current_user,c.oid,'SELECT') OR has_any_column_privilege(current_user,c.oid,'SELECT')))`).Scan(&baseAccess); err != nil || baseAccess {
		return "", errors.New("查询身份不得直接读取业务基表，只能读取授权视图")
	}
	// 先让 PostgreSQL 单独解析原始语句（不执行），避免闭合括号/注释逃出限额包装。
	prepared, err := tx.PrepareContext(ctx, statement)
	if err != nil {
		return "", sqlError("只读 SQL 必须是独立的合法语句", err)
	}
	if err := prepared.Close(); err != nil {
		return "", errors.New("关闭查询预解析失败")
	}
	// 子查询限制只允许一条可查询语句；权限仍以数据库角色/授权视图为边界。
	// 在数据库端拦截大行，避免 Scan 后才限额导致服务器先接收任意大的字段。
	rows, err := tx.QueryContext(ctx, `SELECT CASE WHEN octet_length(row_to_json(xdr_result)::text) <= 8192
 THEN row_to_json(xdr_result)::text ELSE NULL END FROM (
`+statement+`
) AS xdr_result LIMIT 201`)
	if err != nil {
		return "", sqlError("只读 SQL 查询失败，请检查语法与视图权限", err)
	}
	defer rows.Close()
	result := queryResult{Columns: []string{}, Rows: [][]json.RawMessage{}, Coverage: queryScope}
	for rows.Next() {
		if len(result.Rows) == 200 {
			result.Truncated = true
			break
		}
		var raw sql.NullString
		if err := rows.Scan(&raw); err != nil {
			return "", err
		}
		if !raw.Valid {
			result.Truncated = true
			break
		}
		columns, values, err := decodeQueryRow(raw.String)
		if err != nil {
			return "", err
		}
		if len(result.Rows) == 0 {
			result.Columns = columns
		}
		result.Rows = append(result.Rows, values)
		encoded, err := marshal(result)
		if err != nil {
			return "", err
		}
		if len(encoded) > 8192 {
			result.Rows = result.Rows[:len(result.Rows)-1]
			if len(result.Rows) == 0 {
				result.Columns = []string{}
			}
			result.Truncated = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		return "", sqlError("只读查询中断", err)
	}
	return marshal(result)
}

// errQueryTimeout 超时单独说清楚：笼统报「检查语法」会让模型反复改写法，而该做的是收窄范围
var errQueryTimeout = errors.New("查询超过 5 秒被取消（不是语法或权限问题）：events 必须带窄的 ts 范围，尽量再带 asset_id；" +
	"要告警对应的事件用 alert_events 视图，不要自己 JOIN events，也不要用 IN (SELECT event_id ...)")

// sqlError 带上 PostgreSQL 的报错原文，模型才知道是哪个列或语法错了；
// 只取 Message，不带 Position/Where——第二次执行包了一层限额外壳，位置对不上原语句。
// 本地 5 秒期限与角色的 statement_timeout 同时到点，先到的那个报出来的错不同，两种都按超时报。
func sqlError(prefix string, err error) error {
	var pg *pgconn.PgError
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &pg) && pg.Code == "57014") {
		return errQueryTimeout
	}
	if errors.As(err, &pg) {
		return fmt.Errorf("%s：%s", prefix, pg.Message)
	}
	return errors.New(prefix)
}

type queryResult struct {
	Columns   []string            `json:"columns"`
	Rows      [][]json.RawMessage `json:"rows"`
	Truncated bool                `json:"truncated"`
	// Coverage 是静态范围声明，每次结果都带（见 queryScope）。
	Coverage queryCoverage `json:"coverage"`
}

// queryCoverage 声明 query 工具的数据边界，不解析 SQL、不承诺行级覆盖度：
// 这是声明，不是对具体语句的分析。任意 SQL 里到底碰了哪些表（子查询、CTE、
// information_schema 都能绕开字符串匹配）靠解析是说不清的——说不清还硬说，
// 比每次都带同一条真实边界更危险。模型拿到任何结果都知道：查不到 ≠ 没发生。
type queryCoverage struct {
	// Tables 列出只覆盖热表（events 现存行）的事件数据视图
	Tables []string `json:"tables"`
	// HotOnly 为 true 表示上述视图不含已归档冷数据
	HotOnly bool   `json:"hot_only"`
	Note    string `json:"note"`
}

// queryScope 与 queryrole 的视图定义同一口径（见 service.go 的 queryDescription），改视图时一起改。
var queryScope = queryCoverage{
	Tables:  []string{"events", "alert_events"},
	HotOnly: true,
	Note:    "events 与 alert_events 只覆盖仍保留在热表的事件；已归档冷数据（swap/retire 移出热表）不在任何 SQL 可查范围内，组视图同样；查不到不等于没发生",
}

// 按数据库输出顺序解码，不用 map 丢失列序或同名列。
func decodeQueryRow(raw string) ([]string, []json.RawMessage, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, nil, errors.New("查询结果不是行对象")
	}
	columns := []string{}
	values := []json.RawMessage{}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, nil, err
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, nil, err
		}
		columns = append(columns, key.(string))
		values = append(values, value)
	}
	if _, err := decoder.Token(); err != nil {
		return nil, nil, err
	}
	return columns, values, nil
}

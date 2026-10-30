//go:build integration

package agentchat

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"openxdr/server/internal/testdb"
)

func TestQueryDedicatedGroupView(t *testing.T) {
	ctx, _ := testdb.New(t)
	dsn, role := os.Getenv("PI_TEST_QUERY_DSN"), os.Getenv("PI_TEST_QUERY_ROLE")
	if (dsn == "") != (role == "") {
		t.Fatal("PI_TEST_QUERY_DSN 与 PI_TEST_QUERY_ROLE 必须同时配置")
	}
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if dsn == "" {
		config, err := pgx.ParseConfig(os.Getenv("INTEGRATION_DATABASE_URL"))
		if err != nil {
			t.Fatal("测试数据库连接配置无效")
		}
		role = "pi_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
		password := strings.ReplaceAll(uuid.NewString(), "-", "")
		// 名称与密码只由随机十六进制构造，且不输出到测试日志。
		if _, err := db.ExecContext(ctx, `CREATE ROLE `+role+` LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD '`+password+`'`); err != nil {
			t.Fatal("创建隔离测试角色失败")
		}
		defer func() {
			if _, err := db.ExecContext(ctx, `DROP OWNED BY `+role+`; DROP ROLE `+role); err != nil {
				t.Error("清理隔离测试角色失败")
			}
		}()
		if _, err := db.ExecContext(ctx, `GRANT USAGE ON SCHEMA public TO `+role); err != nil {
			t.Fatal(err)
		}
		config.User = role
		config.Password = password
		dsn = stdlib.RegisterConnConfig(config)
		defer stdlib.UnregisterConnConfig(dsn)
	}

	_, err = db.ExecContext(ctx, `CREATE TABLE pi_query_fixture(group_id text,value text);
 INSERT INTO pi_query_fixture VALUES ('allowed','可见'),('other','不可见');
 CREATE VIEW pi_group_view WITH (security_barrier=true) AS SELECT value FROM pi_query_fixture WHERE group_id='allowed';`)
	if err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(ctx, `DROP VIEW pi_group_view; DROP TABLE pi_query_fixture`)
	quoted := `"` + strings.ReplaceAll(role, `"`, `""`) + `"`
	if _, err = db.ExecContext(ctx, `GRANT SELECT ON pi_group_view TO `+quoted); err != nil {
		t.Fatal(err)
	}
	result, err := query(ctx, dsn, `SELECT * FROM pi_group_view`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "可见") || strings.Contains(result, "不可见") {
		t.Fatalf("组视图数据越界: %s", result)
	}
	for _, statement := range []string{`SELECT * FROM pi_query_fixture`, `DELETE FROM pi_query_fixture RETURNING *`, `SELECT 1); DELETE FROM pi_query_fixture; SELECT (1`, `SELECT 1) AS xdr_result UNION ALL SELECT repeat('x',100000) --`} {
		if _, err := query(ctx, dsn, statement); err == nil {
			t.Fatalf("不应执行: %s", statement)
		}
	}
	result, err = query(ctx, dsn, `SELECT generate_series(1,300) AS n`)
	if err != nil {
		t.Fatal(err)
	}
	var truncated struct {
		Truncated bool `json:"truncated"`
	}
	if err = json.Unmarshal([]byte(result), &truncated); err != nil || !truncated.Truncated {
		t.Fatalf("截断未标注: %v", err)
	}
	// P5：静态范围声明每次结果都带——模型不用额外调用就知道 events 只覆盖热表
	var scoped queryResult
	if err := json.Unmarshal([]byte(result), &scoped); err != nil {
		t.Fatal(err)
	}
	if !scoped.Coverage.HotOnly || len(scoped.Coverage.Tables) == 0 || scoped.Coverage.Note == "" {
		t.Fatalf("结果应带静态范围声明: %+v", scoped.Coverage)
	}
	if !slices.Contains(scoped.Coverage.Tables, "events") {
		t.Fatalf("events 视图应在范围声明里: %+v", scoped.Coverage)
	}
	for _, statement := range []string{`SELECT repeat('中',1000000) AS payload`, `SELECT repeat('中',3000) AS payload`, `SELECT repeat('x',40000) AS payload FROM generate_series(1,3)`} {
		result, err = query(ctx, dsn, statement)
		if err != nil {
			t.Fatal(err)
		}
		if len(result) > 8192 {
			t.Fatalf("结果超过字节限制: %d", len(result))
		}
		if err = json.Unmarshal([]byte(result), &truncated); err != nil || !truncated.Truncated {
			t.Fatal("大结果必须标注截断")
		}
	}
	if _, err = query(ctx, dsn, "SELECT 1 -- 合法尾部注释"); err != nil {
		t.Fatal(err)
	}
	if _, err = query(ctx, dsn, "SELECT 1;\n"); err != nil {
		t.Fatalf("结尾分号应容忍：%v", err)
	}
	if _, err = query(ctx, dsn, "SELECT 1; SELECT 2;"); err == nil {
		t.Fatal("多语句仍应拒绝")
	}
	// 超时要说成超时：报成语法错误会让模型反复改写法，而不是收窄范围
	if _, err = query(ctx, dsn, `SELECT pg_sleep(6)`); !errors.Is(err, errQueryTimeout) {
		t.Fatalf("超时应单独报出: %v", err)
	}
	result, err = query(ctx, dsn, `SELECT 1 AS same,2 AS same`)
	if err != nil {
		t.Fatal(err)
	}
	var decoded queryResult
	if err = json.Unmarshal([]byte(result), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Columns) != 2 || string(decoded.Rows[0][0]) != "1" || string(decoded.Rows[0][1]) != "2" {
		t.Fatalf("同名列丢失: %s", result)
	}
	if _, err = db.ExecContext(ctx, `GRANT SELECT(value) ON pi_query_fixture TO `+quoted); err != nil {
		t.Fatal(err)
	}
	if _, err = query(ctx, dsn, `SELECT value FROM pi_query_fixture`); err == nil {
		t.Fatal("列级基表权限也必须拒绝")
	}
	if _, err := query(ctx, os.Getenv("INTEGRATION_DATABASE_URL"), `SELECT 1`); err == nil {
		t.Fatal("平台基表账号应拒绝")
	}
}

package queryrole

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// 平台账号只有 CREATEROLE、不是超级用户：PostgreSQL 16 起这些属性连 NO 的写法都会被拒，整个开通事务回滚。
// 集成测试用超级用户跑，测不出来，这里直接看语句
func TestDDLAvoidsSuperuserOnlyAttributes(t *testing.T) {
	for _, stmt := range ddl(uuid.New(), "p", true) {
		if !strings.HasPrefix(stmt, "ALTER ROLE") && !strings.Contains(stmt, "CREATE ROLE") {
			continue
		}
		for _, attr := range []string{"SUPERUSER", "REPLICATION", "BYPASSRLS", "CREATEDB"} {
			if strings.Contains(stmt, attr) {
				t.Errorf("非超级用户执行不了含 %s 的角色语句：%s", attr, stmt)
			}
		}
	}
}

// queryrole.ddl 与 deploy/pi-query/group-views.sql 必须保持视图定义一致，防止手工开通与自动开通静默漂移。
func TestViewsMatchDeploySQL(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "pi-query", "group-views.sql"))
	if err != nil {
		t.Fatalf("读取 deploy/pi-query/group-views.sql 失败：%v", err)
	}
	gid := uuid.MustParse("01900000-0000-7000-8000-000000000001")
	schema, _ := names(gid)

	// 去掉 -- 注释行再按分号切分，并把 psql 变量替换成与 ddl() 相同的字面量
	var cleaned strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		cleaned.WriteString(line)
		cleaned.WriteByte('\n')
	}
	sqlText := strings.NewReplacer(
		`:"schema".`, schema+".",
		`:'group_id'`, "'"+gid.String()+"'",
	).Replace(cleaned.String())

	extractViews := func(stmts []string) map[string]string {
		views := make(map[string]string)
		prefix := schema + "."
		for _, stmt := range stmts {
			norm := strings.Join(strings.Fields(stmt), " ")
			var rest string
			switch {
			case strings.HasPrefix(norm, "CREATE OR REPLACE VIEW "+prefix):
				rest = strings.TrimPrefix(norm, "CREATE OR REPLACE VIEW "+prefix)
			case strings.HasPrefix(norm, "CREATE VIEW "+prefix):
				rest = strings.TrimPrefix(norm, "CREATE VIEW "+prefix)
			default:
				continue
			}
			name, _, _ := strings.Cut(rest, " ")
			views[name] = norm
		}
		return views
	}

	goViews := extractViews(ddl(gid, "p", true))
	sqlViews := extractViews(strings.Split(sqlText, ";"))
	if len(goViews) == 0 {
		t.Fatal("未从 ddl() 提取到任何视图定义")
	}
	for name, want := range goViews {
		got, ok := sqlViews[name]
		if !ok {
			t.Errorf("deploy/pi-query/group-views.sql 缺少视图 %s", name)
			continue
		}
		if got != want {
			t.Errorf("视图 %s 定义不一致：\nqueryrole.go:    %s\ngroup-views.sql: %s", name, want, got)
		}
	}
	for name := range sqlViews {
		if _, ok := goViews[name]; !ok {
			t.Errorf("queryrole.go 缺少视图 %s", name)
		}
	}
}

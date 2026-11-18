// integrationexec 让集成测试按包并行：作为 go test -exec 的包装程序，按测试二进制所在的包目录
// 给每个包分配独立的测试库（<基础库名>_<目录摘要>，不存在就建），改写 INTEGRATION_DATABASE_URL 后再启动测试二进制。
// 各包互不清对方的表，就不必再 -p 1 串行。未设置 INTEGRATION_DATABASE_URL 时原样启动。
//
// 用法（工作目录 server/）：
//
//	go build -o /tmp/integrationexec ./cmd/integrationexec
//	INTEGRATION_DATABASE_URL=postgres://... go test -tags integration -p 4 -exec /tmp/integrationexec ./...
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "用法：integrationexec <测试二进制> [参数...]")
		os.Exit(2)
	}
	if base := os.Getenv("INTEGRATION_DATABASE_URL"); base != "" {
		dir, err := os.Getwd()
		if err != nil {
			fail(err)
		}
		dsn, err := packageDatabase(base, dir)
		if err != nil {
			fail(err)
		}
		os.Setenv("INTEGRATION_DATABASE_URL", dsn)
	}
	bin, err := exec.LookPath(os.Args[1])
	if err != nil {
		fail(err)
	}
	fail(syscall.Exec(bin, os.Args[1:], os.Environ()))
}

// packageDatabase 返回该包专用库的连接串；库不存在就用基础库的连接建出来（并发建同名库按已存在处理）
func packageDatabase(base, dir string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	baseName := strings.TrimPrefix(u.Path, "/")
	if baseName == "" {
		return "", errors.New("INTEGRATION_DATABASE_URL 缺库名")
	}
	sum := sha256.Sum256([]byte(dir))
	name := baseName + "_" + hex.EncodeToString(sum[:])[:10]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		return "", err
	}
	defer conn.Close(ctx)
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)`, name).Scan(&exists); err != nil {
		return "", err
	}
	if !exists {
		_, err := conn.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{name}.Sanitize())
		var pgErr *pgconn.PgError
		if err != nil && !(errors.As(err, &pgErr) && (pgErr.Code == "42P04" || pgErr.Code == "23505")) {
			return "", err
		}
	}
	u.Path = "/" + name
	return u.String(), nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "integrationexec:", err)
	os.Exit(1)
}

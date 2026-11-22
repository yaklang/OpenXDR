// sandboxd 沙箱守护进程：独占 Docker，按平台请求为每轮 Pi 会话起一个隔离容器，
// 把请求体接到容器 stdin、容器 stdout 接到响应体，组成一条全双工 JSONL 流（协议与平台 runner.mjs 相同）。
// 平台断开、超时或会话结束即删除容器。只认共享密钥；TLS 证书与私钥要么都配、要么都不配。
//
// 它不知道平台的任何凭据，也不解析流里的内容：权限、审批与审计都在平台一侧完成。
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type config struct {
	addr, key, cert, tlsKey   string
	docker, image, network    string
	memory, cpus, pids, tmpfs string
	maxRuns                   int
	maxRun                    time.Duration
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func load() (config, error) {
	c := config{
		addr: getenv("SANDBOXD_ADDR", ":8090"), key: os.Getenv("SANDBOXD_KEY"),
		cert: os.Getenv("SANDBOXD_TLS_CERT"), tlsKey: os.Getenv("SANDBOXD_TLS_KEY"),
		docker: getenv("DOCKER", "docker"), image: getenv("SANDBOX_IMAGE", "openxdr-pi-sandbox:latest"),
		network: getenv("SANDBOX_NETWORK", "openxdr-sandbox"),
		memory:  getenv("SANDBOX_MEMORY", "1g"), cpus: getenv("SANDBOX_CPUS", "1.5"), pids: getenv("SANDBOX_PIDS", "256"),
		tmpfs: getenv("SANDBOX_WORK_SIZE", "512m"),
	}
	if len(c.key) < 32 {
		return c, errors.New("SANDBOXD_KEY 必须配置且不少于 32 个字符")
	}
	if (c.cert == "") != (c.tlsKey == "") {
		return c, errors.New("SANDBOXD_TLS_CERT 与 SANDBOXD_TLS_KEY 必须同时配置")
	}
	var err error
	if c.maxRuns, err = strconv.Atoi(getenv("SANDBOX_MAX_RUNS", "4")); err != nil || c.maxRuns < 1 {
		return c, errors.New("SANDBOX_MAX_RUNS 必须是正整数")
	}
	minutes, err := strconv.Atoi(getenv("SANDBOX_MAX_MINUTES", "60"))
	if err != nil || minutes < 1 {
		return c, errors.New("SANDBOX_MAX_MINUTES 必须是正整数")
	}
	c.maxRun = time.Duration(minutes) * time.Minute
	return c, nil
}

// args 容器限制：只读根文件系统、写目录走 tmpfs、去掉全部能力、禁止提权、限内存 CPU 进程数；
// 网络用专用网桥，出口只放行模型端点由宿主防火墙负责。代理变量清空：Docker 会把宿主代理注入容器
func (c config) args(name string) []string {
	return []string{"run", "-i", "--rm", "--name", name, "--network", c.network,
		"--read-only", "--tmpfs", "/tmp:size=256m,noexec,nosuid,nodev", "--tmpfs", "/home/agent:size=" + c.tmpfs + ",uid=10010,gid=10010,noexec,nosuid,nodev",
		"--memory", c.memory, "--memory-swap", c.memory, "--cpus", c.cpus, "--pids-limit", c.pids,
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "10010:10010",
		"-e", "HTTP_PROXY=", "-e", "HTTPS_PROXY=", "-e", "http_proxy=", "-e", "https_proxy=", "-e", "ALL_PROXY=", "-e", "all_proxy=",
		c.image}
}

// flushWriter 容器每写一段就推给平台，JSONL 事件不能攒在缓冲里
type flushWriter struct {
	w  io.Writer
	rc *http.ResponseController
}

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if err == nil {
		err = f.rc.Flush()
	}
	return n, err
}

func runHandler(c config) http.Handler {
	slots := make(chan struct{}, c.maxRuns)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 一进来就开全双工：否则拒绝时不读请求体，Go 会先等着把请求体读完再回错误，而平台在等回应才开始写，两边卡死
		rc := http.NewResponseController(w)
		_ = rc.EnableFullDuplex() // HTTP/1.1 需要显式开启；HTTP/2 本身就是全双工
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(c.key)) != 1 {
			http.Error(w, "密钥无效", http.StatusUnauthorized)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "沙箱并发已满", http.StatusServiceUnavailable)
			return
		}
		buf := make([]byte, 8)
		_, _ = rand.Read(buf)
		name := "openxdr-sbx-" + hex.EncodeToString(buf)
		ctx, cancel := context.WithTimeout(r.Context(), c.maxRun)
		defer cancel()

		cmd := exec.Command(c.docker, c.args(name)...)
		// 请求体自己拷进 stdin 管道，不交给 exec：卡在读请求体上的拷贝协程连 WaitDelay 都打断不了，
		// 交给 exec 会让 Wait 永远等下去。容器退出后 Wait 关管道，处理函数返回时请求体随之关闭，协程自然退出
		stdin, err := cmd.StdinPipe()
		if err != nil {
			slog.Error("创建沙箱输入管道失败", "err", err)
			return
		}
		go func() {
			_, _ = io.Copy(stdin, r.Body)
			_ = stdin.Close()
		}()
		cmd.Stdout = flushWriter{w, rc}
		var stderr strings.Builder
		cmd.Stderr = &limited{&stderr, 4096}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		_ = rc.Flush()
		started := time.Now()
		if err := cmd.Start(); err != nil {
			slog.Error("启动沙箱失败", "err", err)
			return
		}
		// 平台断开或超时：docker CLI 被杀不会带走容器，必须显式删除
		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = exec.Command(c.docker, "rm", "-f", name).Run()
			case <-done:
			}
		}()
		err = cmd.Wait()
		close(done)
		slog.Info("沙箱结束", "name", name, "seconds", int(time.Since(started).Seconds()), "err", err, "stderr", stderr.String(), "canceled", ctx.Err() != nil)
	})
}

// limited 只留 stderr 开头一段写日志，排障够用，不让异常输出撑爆日志
type limited struct {
	b *strings.Builder
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if room := l.n - l.b.Len(); room > 0 {
		l.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func main() {
	c, err := load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.Handle("POST /run", runHandler(c))
	srv := &http.Server{Addr: c.addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	slog.Info("sandboxd 启动", "addr", c.addr, "image", c.image, "network", c.network, "max_runs", c.maxRuns, "tls", c.cert != "")
	if c.cert == "" {
		slog.Warn("sandboxd 未启用 TLS，平台与沙箱之间为明文，仅适合本机或受信网络调试")
		err = srv.ListenAndServe()
	} else {
		err = srv.ListenAndServeTLS(c.cert, c.tlsKey)
	}
	slog.Error("sandboxd 退出", "err", err)
	os.Exit(1)
}

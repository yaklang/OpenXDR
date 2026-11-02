// decoyhost 显式运行已登记的专用诱饵，不修改业务服务、登录 Shell 或已有文件。
package runner

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"openxdr/server/deception/contract"
	"openxdr/server/deception/native"
	"openxdr/server/deception/sdk"
)

func Run() (runErr error) {
	managed := flag.Bool("managed", false, "使用版本化运行协议")
	printRelease := flag.Bool("print-release", false, "输出本地产物准入信息后退出")
	expectedKind := flag.String("expected-kind", "", "要求平台配置与预期载体一致")
	platform := flag.String("platform", "", "平台 HTTPS origin")
	id := flag.String("deployment", "", "登记 UUID")
	listenHost := flag.String("listen-host", "127.0.0.1", "HTTP / SSH 监听 IP；端口取自登记")
	root := flag.String("file-root", "", "文件诱饵专用父目录，必须预先存在")
	hostKey := flag.String("host-key", "", "SSH 诱饵专用主机私钥路径")
	tokenFile := flag.String("token-file", "", "0600 权限的运行令牌文件，与环境变量互斥")
	flag.Parse()
	if *printRelease {
		release, err := sdk.NativeRelease()
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(release)
	}
	token := os.Getenv("DECOY_RUNTIME_TOKEN")
	if *tokenFile != "" {
		if token != "" {
			return fmt.Errorf("token-file 与 DECOY_RUNTIME_TOKEN 不能同时设置")
		}
		var err error
		token, err = sdk.ReadTokenFile(*tokenFile)
		if err != nil {
			return err
		}
	}
	client, err := sdk.NewClient(*platform, *id, token)
	if *managed && err == nil {
		var release contract.Release
		release, err = sdk.NativeRelease()
		if err == nil {
			client, err = sdk.NewManagedClient(*platform, *id, token, release)
		}
	}
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	manifest, err := client.Manifest(ctx)
	if err != nil {
		return err
	}
	if *expectedKind != "" && manifest.Kind != *expectedKind {
		return fmt.Errorf("平台载体与本地服务配置不一致")
	}
	if err = client.Acquire(ctx); err != nil {
		return err
	}
	defer func() {
		stop()
		finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.Finish(finishCtx, runErr != nil); err != nil && runErr == nil {
			runErr = fmt.Errorf("运行端已退出，但无法确认状态回写: %w", err)
		}
	}()
	var mu sync.Mutex
	var failure error
	fail := func(err error) {
		mu.Lock()
		if failure == nil {
			failure = err
		}
		mu.Unlock()
		stop()
	}
	sampled := map[string]time.Time{}
	record := func(kind string) error {
		if contract.Sampled(kind) {
			mu.Lock()
			last, seen := sampled[kind]
			skip := seen && time.Since(last) < contract.SampleWindow
			if !skip {
				sampled[kind] = time.Now()
			}
			mu.Unlock()
			if skip {
				return nil
			}
		}
		err := client.Ready(ctx)
		if err == nil {
			err = client.Record(ctx, kind)
		}
		// 收到停止信号时在途上报被取消，不算平台失败。
		if err != nil && ctx.Err() == nil {
			fail(err)
		}
		return err
	}
	// 撤销、迁组或令牌轮换后，空闲服务也会停止；最长 30 秒探测周期。
	// 平台明确拒绝立即停止；网络或 5xx 等暂时故障容忍到租约过期前，单次抖动不让诱饵下线。
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		confirmed := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				next, err := client.Manifest(ctx)
				if errors.Is(err, sdk.ErrStopRequested) {
					stop()
					return
				}
				if err == nil {
					err = client.Heartbeat(ctx)
				}
				if err != nil && (!sdk.Transient(err) || time.Since(confirmed) >= contract.LeaseTTL-30*time.Second) {
					fail(err)
					return
				}
				if err != nil {
					continue
				}
				confirmed = time.Now()
				if next != manifest {
					fail(fmt.Errorf("布放配置变化，停止旧实例"))
					return
				}
			}
		}
	}()
	switch manifest.Kind {
	case "ssh":
		if net.ParseIP(*listenHost) == nil || *hostKey == "" {
			return fmt.Errorf("SSH 需要专用 host-key 和监听 IP")
		}
		key, err := os.ReadFile(*hostKey)
		if err != nil {
			return fmt.Errorf("读取 SSH 主机密钥失败")
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return fmt.Errorf("解析 SSH 主机密钥失败")
		}
		listener, err := net.Listen("tcp", net.JoinHostPort(*listenHost, strconv.Itoa(manifest.Port)))
		if err != nil {
			return err
		}
		defer listener.Close()
		if err = client.Ready(ctx); err != nil {
			return err
		}
		if err = native.ServeSSH(ctx, listener, signer, manifest, record); err != nil {
			return err
		}

	case "http":
		if net.ParseIP(*listenHost) == nil {
			return fmt.Errorf("listen-host 必须为监听 IP")
		}
		handler, err := native.HTTPHandler(manifest, record)
		if err != nil {
			return err
		}
		slots := make(chan struct{}, 16)
		bounded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
				handler.ServeHTTP(w, r)
			default:
				http.Error(w, "连接繁忙", 429)
			}
		})
		listener, err := net.Listen("tcp", net.JoinHostPort(*listenHost, strconv.Itoa(manifest.Port)))
		if err != nil {
			return err
		}
		defer listener.Close()
		if err = client.Ready(ctx); err != nil {
			return err
		}
		server := &http.Server{Handler: bounded, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
		go func() { <-ctx.Done(); _ = server.Close() }()
		fmt.Fprintf(os.Stderr, "HTTP 诱饵监听 %s，根路径与 /decoy/%s 均为诱饵页\n", listener.Addr(), manifest.ID)
		err = server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case "file":
		if runtime.GOOS != "linux" {
			return fmt.Errorf("文件打开监视目前只支持 Linux")
		}
		installed, err := native.InstallFile(*root, manifest)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "已创建文件诱饵:", installed.Path)
		watchErr := native.WatchFile(ctx, installed.Path, record)
		// 先停止 watcher，再核验和清理，平台自己清理时不产生打开事件。
		if err = installed.Remove(); err != nil {
			return err
		}
		if watchErr != nil {
			return watchErr
		}
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if err = client.Record(cleanupContext, "file_removed"); err != nil {
			return err
		}
	case "shell":
		shellCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		go func() { <-shellCtx.Done(); _ = os.Stdin.Close() }()
		err = native.Shell(os.Stdin, os.Stdout, manifest, record)
		if err != nil && shellCtx.Err() == nil {
			return err
		}
	default:
		return fmt.Errorf("此运行端不支持该载体")
	}
	mu.Lock()
	defer mu.Unlock()
	return failure
}

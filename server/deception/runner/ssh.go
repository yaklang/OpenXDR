// sshdecoy 是显式启动的靶场服务，不由主服务或安装脚本自动开启。
package runner

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
	"openxdr/server/deception/sshdecoy"
)

func SSHRun() error {
	address := flag.String("listen", "127.0.0.1:2222", "独立诱饵监听地址，默认仅回环")
	key := flag.String("host-key", "", "诱饵专用 SSH 私钥路径")
	output := flag.String("events", "", "新建事件文件路径，已存在则拒绝启动")
	profile := flag.String("profile", "", "运行策略：decoy / pause / padding，未选实验模板时默认 decoy")
	template := flag.String("template", "", "显式选择历史实验模板，与 profile 互斥")
	listProfiles := flag.Bool("list-profiles", false, "输出策略目录并退出，不启动监听")
	deployment := flag.String("deployment", "", "布放 UUID")
	group := flag.String("group", "", "所属组 UUID，仅为本地标签")
	asset := flag.String("asset", "", "诱饵资产 UUID，仅为本地标签")
	flag.Parse()
	if *listProfiles {
		return json.NewEncoder(os.Stdout).Encode(sshdecoy.Profiles())
	}
	if *profile == "" && *template == "" {
		*profile = "decoy"
	}
	if *key == "" || *output == "" {
		return fmt.Errorf("必须提供专用 host-key 与 events 文件路径")
	}
	bytes, err := os.ReadFile(*key)
	if err != nil {
		return fmt.Errorf("读取诱饵主机密钥失败")
	}
	signer, err := ssh.ParsePrivateKey(bytes)
	clear(bytes)
	if err != nil {
		return fmt.Errorf("诱饵主机密钥无效")
	}
	var mu sync.Mutex
	var file *os.File
	var used int
	record := func(event sshdecoy.Event) error {
		mu.Lock()
		defer mu.Unlock()
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if used+len(data) > 16*1024*1024 {
			return fmt.Errorf("事件文件达到 16 MiB 上限")
		}
		n, err := file.Write(data)
		used += n
		if err != nil {
			return err
		}
		return file.Sync()
	}
	server, err := sshdecoy.New(sshdecoy.Config{Signer: signer, DeploymentID: *deployment, GroupID: *group, AssetID: *asset, Template: *template, Profile: *profile, Record: record})
	if err != nil {
		return err
	}
	file, err = os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("无法新建事件文件")
	}
	defer file.Close()
	listener, err := net.Listen("tcp", *address)
	if err != nil {
		return fmt.Errorf("无法绑定独立诱饵监听地址")
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintln(os.Stderr, "独立 SSH 诱饵已启动；所有认证均拒绝，不提供 shell")
	return server.Serve(ctx, listener)
}

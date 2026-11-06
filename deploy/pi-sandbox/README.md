# Pi 沙箱

Pi 在一次性容器里用自己的默认工具（bash / read / edit / write）工作，按 `skills/openxdr/SKILL.md` 工作手册行事；
平台能力只经容器内的 `xdr` 命令行使用。设计与配置见 [Pi 后端 · 沙箱模式](../../docs/pi-backend.md#沙箱模式)。

- `bridge.mjs`：容器入口，与 `server/pi-runtime/runner.mjs` 说同一套 JSONL 协议，用 Pi SDK 驱动会话。
- `xdr`：经 unix socket 把调用交给桥，桥发 `tool_request` 回平台；判权、审批、审计都在平台完成。
  容器里没有任何平台凭据，也不需要访问平台网络。
- `jq`：装在 `/usr/local/bin` 的薄包装。参数里带 `->` 且 jq 报语法错时，在 stderr 补一句「用点路径，不是 SQL 的 `->`」；
  输出与退出码原样交给 `/usr/bin/jq`。
- `server/cmd/sandboxd`：沙箱主机上的守护进程，每轮对话起一个容器，平台断开或超时即删除。

## 部署

沙箱主机应是独立的机器（或 VM），只装 Docker 与 sandboxd，不放任何其他服务。

```bash
# 1. 镜像与二进制（在构建机上）
docker build -t openxdr-pi-sandbox:latest deploy/pi-sandbox
(cd server && CGO_ENABLED=0 go build -o sandboxd ./cmd/sandboxd)

# 2. 沙箱主机：专用网桥，关闭容器互通
docker network create -o com.docker.network.bridge.name=br-sandbox \
  -o com.docker.network.bridge.enable_icc=false openxdr-sandbox

# 3. 防火墙：出口只放行模型端点（其余立刻拒绝），sandboxd 端口只对 server 节点开放
apt-get install -y ipset iptables util-linux
mkdir -p /etc/openxdr
install -D -m 0755 firewall.sh /usr/local/lib/openxdr/firewall.sh
cat > /etc/openxdr/sandbox-firewall.env <<'X'
MODEL_ENDPOINTS="10.0.0.5:8000 api.deepseek.com:443 opencode.ai:443"
PLATFORM_NODES="10.0.0.1 10.0.0.2"
X
install -m 0644 openxdr-sandbox-firewall*.service openxdr-sandbox-firewall-refresh.timer sandboxd.service /etc/systemd/system/

# 4. sandboxd：TLS 证书私钥与密钥只放在本机，sandboxd 用户需能读取
useradd -r -s /usr/sbin/nologin -G docker sandboxd
install -m 0755 sandboxd /usr/local/bin/sandboxd
cat > /etc/openxdr/sandboxd.env <<'X'
SANDBOXD_KEY=<至少 32 个字符>
SANDBOXD_TLS_CERT=/etc/openxdr/sandboxd.crt
SANDBOXD_TLS_KEY=/etc/openxdr/sandboxd.key
X
systemctl daemon-reload && systemctl enable --now openxdr-sandbox-firewall openxdr-sandbox-firewall-refresh.timer sandboxd
```

server 侧配置 `SANDBOX_URL=https://<沙箱主机>:8090`、`SANDBOX_KEY`、`SANDBOX_CA_FILE`（签发 sandboxd 证书的 CA）。

Docker 会把宿主代理变量注入容器，sandboxd 起容器时已全部清空：Node 不认 `NO_PROXY` 里的网段写法，
内网模型请求会被送进代理。

## 防火墙升级

Debian 12 需安装 `ipset`、`iptables`、`util-linux`。覆盖安装 `firewall.sh`、
`openxdr-sandbox-firewall*.service` 与 `openxdr-sandbox-firewall-refresh.timer` 到上述位置，
执行 `systemctl daemon-reload`、`systemctl restart openxdr-sandbox-firewall.service`，
再执行 `systemctl enable --now openxdr-sandbox-firewall-refresh.timer`。

每两分钟按端口重建 IPv4 ipset，再原子 swap；同端口任一域名解析失败则保留旧集合。
首次解析失败保持空集合，出口拒绝。已有连接仍遵循 conntrack 规则。
修改端口或其他防火墙配置后需重启主服务；仅 DNS 变化无需重启。
可用 `systemctl status openxdr-sandbox-firewall-refresh.timer` 和对应 service 日志检查刷新。

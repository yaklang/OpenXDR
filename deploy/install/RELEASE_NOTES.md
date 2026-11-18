## 安装 / Install

一台装了 Docker 的 Linux 服务器（x86_64 或 arm64，建议 2 核 4 GB 以上），一行命令：

```bash
curl -fsSL https://github.com/yaklang/OpenXDR/releases/download/__OPENXDR_VERSION__/install.sh | sudo sh -s -- <控制台域名或 IP>
```

脚本会生成口令与密钥、签发 mTLS 证书、配好 HTTPS（解析到公网的域名自动申请 Let's Encrypt，内网地址用自建 CA），
拉起后打印控制台地址与 admin 口令。装好即可在「资产 → 添加主机」接入被监控主机。已安装的再执行一遍就是升级。

**让你的 AI agent 来装**（Claude Code、Codex、Cursor 等，在目标服务器上运行）：

```text
请在这台服务器上安装 OpenXDR __OPENXDR_VERSION__，严格按照 https://github.com/yaklang/OpenXDR/blob/master/docs/install.md 操作：
先检查环境并问我控制台用哪个域名或 IP，再执行安装，最后把控制台地址、admin 口令，以及被纳管主机信任 CA 的命令告诉我。
```

One-line install on a Linux server with Docker: `curl -fsSL https://github.com/yaklang/OpenXDR/releases/download/__OPENXDR_VERSION__/install.sh | sudo sh -s -- <domain-or-ip>`.
Or ask your AI agent: *"Install OpenXDR __OPENXDR_VERSION__ on this server following https://github.com/yaklang/OpenXDR/blob/master/docs/install.md — check the environment, ask me which domain or IP to use, run the installer, then tell me the console URL, the admin password and how managed hosts should trust the CA."*

| 附件 | 说明 |
|---|---|
| `install.sh` / `docker-compose.yml` | 一行安装脚本与它使用的编排文件 |
| `docker-compose.syslog.yml` / `nats.conf` | 可选的 syslog 接入编排与 NATS 配置 |
| `openxdr-agent-linux-amd64` | 端点 agent，静态链接带 eBPF，新老发行版通用（控制台接入会自动下发，一般不用手动下载） |
| `openxdr-agent-linux-arm64` | 同上，arm64（ARM 云主机、国产 ARM 服务器、树莓派等） |
| `openxdr-agent-windows-amd64.exe` | Windows 端点 agent |
| `openxdr-tray-windows-amd64.exe` | Windows 托盘：显示本机 agent 状态与是否被隔离（只读） |
| `openxdr-sensor-linux-amd64` / `openxdr-sensor-linux-arm64` | 全流量探针 |
| `openxdr-sensor-windows-amd64.exe` | Windows 全流量探针（Windows 11 / Server 2022 及以上，基于系统 Packet Monitor） |
| `SHA256SUMS` | 校验和 |

镜像：`ghcr.io/yaklang/openxdr-server:__OPENXDR_VERSION__`、`ghcr.io/yaklang/openxdr-web:__OPENXDR_VERSION__`（amd64 / arm64），server 镜像已内置默认规则、预设任务与 agent 安装包。

---

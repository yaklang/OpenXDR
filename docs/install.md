# 安装

一台 Linux 服务器、一行命令。本文同时写给人和 AI agent：按顺序做，每一步都有可核对的结果。
从源码构建、高可用部署与全部配置项见 [部署与使用手册](deployment.md)、[高可用部署](../deploy/ha/README.md)。

已有 Suricata 的环境可选用 [EVE 告警接入](suricata.md)：在「系统集成」为探针建一个带 `suricata:write`、只授权一个组的集成，用它的 Token 通过 HTTPS 投递。

## 1. 准备

| 项 | 要求 |
|---|---|
| 系统 | Linux，x86_64 或 arm64 |
| 被纳管主机 | agent：Linux x86_64 / arm64（静态链接，新老发行版通用）、Windows x86_64；流量探针：Linux x86_64 / arm64 |
| 资源 | 2 核 4 GB 内存、20 GB 磁盘起步；主机多、保留期长时加磁盘 |
| Docker | 24 以上，带 Compose v2（`docker compose version` 能输出版本）。没有就 `curl -fsSL https://get.docker.com \| sh` |
| 端口 | 80、443（控制台 HTTPS）、8081（agent / sensor 的 mTLS 接入），本机空闲且防火墙放行 |
| 地址 | 一个被纳管主机能访问到的域名或 IP，控制台与接入都用它 |

地址决定证书怎么来：

- **解析到公网 IP 的域名**：自动申请 Let's Encrypt 证书，浏览器与主机直接信任。要求公网能访问到这台机器的 80 与 443。
- **内网 IP 或内网域名**：用安装时生成的自建 CA。浏览器首次访问会提示不受信任；被纳管主机要先信任这张 CA（安装结束会打印命令与指纹）。

## 2. 安装

```bash
curl -fsSL https://github.com/yaklang/OpenXDR/releases/latest/download/install.sh | sudo sh -s -- <域名或 IP>
```

脚本依次：检查 Docker 与端口 → 下载编排文件到 `/opt/openxdr` → 生成数据库口令、admin 口令与凭据加密密钥（写进 `.env`，权限 600）→
签发 mTLS 证书（`certs/`）→ 写 Caddyfile → 拉镜像并启动 → 等 server 就绪 → 打印控制台地址、admin 口令与后续步骤。

可选环境变量（放在 `sudo` 后面，如 `sudo OPENXDR_DIR=/data/openxdr sh -s -- ...`）：

| 变量 | 默认 | 说明 |
|---|---|---|
| `OPENXDR_DIR` | `/opt/openxdr` | 安装目录 |
| `OPENXDR_VERSION` | 脚本所属版本 | 指定版本，如 `v0.1.0` |
| `OPENXDR_TLS` | 自动判断 | `acme` 强制申请 Let's Encrypt，`internal` 强制自建 CA |
| `OPENXDR_EMAIL` | 空 | Let's Encrypt 联系邮箱 |

## 3. 核对

```bash
cd /opt/openxdr
docker compose ps                     # nats、postgres、server、web、caddy 都是 running
curl -fsS https://<地址>/ -o /dev/null -w '%{http_code}\n'   # 自建 CA 时加 --cacert certs/ca.crt；应为 200
```

用 admin 与打印出的口令登录控制台。第一次登录先看到欢迎页与用户协议，管理员同意后进入四步引导
（AI 模型、项目、资产、Webhook，每步都能跳过，之后在设置、组、资产页里随时再改）；协议同意之前其他账号进不了控制台。
已有组或主机的实例升级后只补同意协议，不再走引导。忘了口令：`grep ADMIN_PASSWORD /opt/openxdr/.env`（只在首次启动时生效，之后改口令请在控制台改）。

## 4. 接上 AI 与主机

1. **AI 模型**：控制台「系统设置 → AI 模型」填任意 OpenAI 兼容端点、模型名与密钥，保存后十几秒生效。不填也能用检测与降噪，只是没有 AI 研判与 AI 助手。
2. **信任 CA**（自建 CA 时）：在每台要纳管的主机上执行安装结束时打印的命令；命令先核对 SHA256 指纹，对得上才装进信任库，对不上会报错停下。
3. **添加主机**：「资产 → 添加主机」选组，复制安装命令到主机上执行（Linux root / Windows 管理员）。agent 安装包已内置在 server 镜像里，
   之后升级 OpenXDR，在线 agent 会自动跟着升级。

自部署 vLLM 若使用 `/model` 等路径型模型名，且测试连接返回空内容或资产标注被思考耗尽预算，可在 `.env` 设置 `AI_TEMPLATE_NO_THINKING=true`，执行 `docker compose up -d server` 重建服务端容器。此项不由控制台覆盖，只对请求关闭思考的调用生效；已识别模型沿用原协议。

### 旧 Linux 内核的采集检查

Linux Agent 的 systemd 安装单元设置 `LimitMEMLOCK=134217728`（128 MiB 上限，不是预分配内存），Agent 进程在首次加载 eBPF 前也会主动将 `RLIMIT_MEMLOCK` 抬升至 128 MiB（兼容二进制热升级的存量主机）。
旧内核的 eBPF map 受锁定内存限制，默认 64 KiB 可能导致 map 创建失败并退回 netlink。
若宿主机或容器环境额外通过安全策略限制了 `CAP_SYS_RESOURCE`，可在 `systemctl edit openxdr-agent` 的 `[Service]` 中设置 `LimitMEMLOCK=134217728`，
执行 `systemctl daemon-reload` 和 `systemctl restart openxdr-agent`，再核对控制台采集能力、事件与缓存回执。
不要仅凭服务 running 判断 eBPF 已启用。旧内核缺少 fanotify 名字报告时仍降级为 inotify，这个限制不能靠提高 memlock 消除。

### 放一台流量探针（可选）

在公网入口（反代网关）上或交换机镜像口旁放一台 sensor，就能看到「只握手不发请求」的扫描、TLS 指纹（JA3 / JA3S）、
证书与明文 HTTP 头，研判不用再翻反代日志。sensor 只出会话元数据，不存报文，只有 Linux。

1. **签发命令**：平台管理员在「资产 → 添加主机」切到「流量探针」，选组（探针所在主机归入这个组），填抓包网卡后生成命令。
   探针令牌只有平台管理员能签：探针看到的会话会按地址归到任何组的资产上。
2. **选网卡**：命令末尾是抓包网卡名。不知道填哪块就先不带网卡执行一次，脚本只列出本机网卡（名称、状态、地址）后退出：

   ```bash
   curl -fsSL https://<地址>/api/enroll/sensor-install.sh | sudo sh -s -- https://<地址> <令牌>            # 只列网卡
   curl -fsSL https://<地址>/api/enroll/sensor-install.sh | sudo sh -s -- https://<地址> <令牌> <网卡名>   # 安装
   ```

   反代网关上抓它的公网口；镜像口场景抓接镜像流量的那块网卡。
3. **核对**：`systemctl status openxdr-sensor` 为 running；控制台资产列表里这台主机的来源有 `sensor` 标签，资产详情「流量探针」卡片
   显示抓包状态「已启用」、包/秒与会话/分钟在动。抓包降级、不可用或探针失联会走「主机采集异常」通知。

与 agent 同一套机制：私钥在本机生成，证书 CN 为 `sensor:<主机名>`，只能进探针通道，冒充不了 agent；
sensor 安装包同样内置在 server 镜像里，升级 OpenXDR 后在线探针按哈希自动升级（失败则继续跑旧版，旧版留作 `openxdr-sensor.prev`）。
同一台主机可以同时装 agent 与 sensor，两者共用 `/etc/openxdr`，配置分别是 `agent.env` 与 `sensor.env`。

## 5. 升级、备份与卸载

- **升级**：再执行一遍安装命令（已有的口令、密钥与 CA 保留不动），或改 `.env` 里的 `OPENXDR_VERSION` 后
  `docker compose pull && docker compose up -d`。0.x 版本升级前看一眼 [CHANGELOG](../CHANGELOG.md)。
- **备份**：`.env`、`certs/` 与数据库（`docker compose exec -T postgres pg_dump -U openxdr openxdr > openxdr.sql`）。
  `HOST_CREDENTIAL_KEY` 丢了，库里加密的主机凭据与模型密钥就解不开。
- **卸载**：`cd /opt/openxdr && docker compose down -v`（`-v` 会删掉全部数据），再删目录。

## 6. 常见问题

| 现象 | 处理 |
|---|---|
| 端口被占用 | 停掉占用 80 / 443 / 8081 的服务，或换一台机器；OpenXDR 自己占用的不算 |
| Let's Encrypt 申请失败 | 确认域名解析到本机公网 IP、公网能访问 80 与 443；内网环境改用 `OPENXDR_TLS=internal` |
| 主机上执行安装命令报证书错误 | 自建 CA 模式下主机还没信任 CA，见第 4 步 |
| agent 连不上 | 主机到 `<地址>:8081` 的网络与防火墙；`docker compose logs server` 看拒绝原因 |
| 探针安装报「令牌用途不符」 | 用了 agent 令牌装探针（或反过来），在添加主机里切到对应的类型重新生成 |
| 探针抓包状态「不可用」或一直没状态 | `journalctl -u openxdr-sensor` 看原因；常见是网卡名写错或网卡没起来，改 `/etc/systemd/system/openxdr-sensor.service` 里的 `SENSOR_IFACE` 或重新执行安装命令 |
| Windows agent 不在线或采集异常 | 看 `C:\ProgramData\OpenXDR\logs\agent.log`（UTC 时间与 pid，10 MB 滚动留 5 份，需管理员）；Linux 用 `journalctl -u openxdr-agent` |
| Windows agent 自动升级后好几分钟才回来 | 旧版安装脚本每 5 分钟才检查一次进程。重新执行安装命令，或管理员 PowerShell 执行 `$t = Get-ScheduledTask 'OpenXDR Agent'; ($t.Triggers \| ? { $_.Repetition.Interval }).Repetition.Interval = 'PT1M'; Set-ScheduledTask -InputObject $t` 只改检查间隔 |
| 拉镜像慢或失败 | 给 Docker 配镜像加速或代理；镜像在 `ghcr.io/yaklang/` 下 |

## 给 AI agent 的说明

如果你是替用户安装 OpenXDR 的 AI agent，请：

1. 先只读地检查环境：系统与架构、`docker compose version`、80 / 443 / 8081 是否被占用、磁盘与内存。缺 Docker 时**先问用户**是否允许安装。
2. **问用户**控制台用哪个域名或 IP，并说明公网域名与内网地址在证书上的区别（见第 1 节）。不要自己猜一个地址。
3. 执行第 2 节的安装命令，完整保留输出。失败时按第 6 节排查，不要关闭防火墙、不要改与 OpenXDR 无关的系统配置。
4. 按第 3 节核对，全部通过后向用户报告：控制台地址、admin 口令、自建 CA 时被纳管主机要执行的信任命令与 SHA256 指纹，以及第 4 节的后续步骤。
5. `.env` 里除 admin 口令外的内容（数据库口令、`HOST_CREDENTIAL_KEY`）不要输出到对话里，提醒用户备份即可。
6. 替用户装流量探针时：先不带网卡执行一次探针安装命令拿到网卡列表，**问用户**抓哪块网卡，不要自己挑；
   装完按「放一台流量探针」的核对步骤确认，并把抓包状态原样告诉用户。

### 队列持久确认

安装脚本同时下载该 Release 的 `nats.conf`，编排将其只读挂载给 NATS。配置包含 4 MiB 消息上限与 `sync_interval: 1s`（每秒落盘，断电最多丢 1 秒已确认事件，理由与实测见 cluster.md）；手动安装也需下载同版本配置，不能退回只带 `--jetstream` 的默认启动方式。

### 独立欺骗引擎

DYGK 使用同一份 `.env` 和主启动命令：设置 `COMPOSE_PROFILES=dygk`，继续 `docker compose up -d`。平台自动识别版本、下发配置并签发运行身份；无需逐个填写连接器参数。引擎可通过同一配置里的 `DYGK_VERSION` 独立升级，状态和控制通道使用命名卷，无开发机路径依赖。使用与回退见 [独立欺骗引擎运行包](../integrations/dygk/README.md)。

自行构建引擎镜像时，源码来源同样在 `.env` 选择：默认 `DYGK_SOURCE=local` 使用模块内提供的私有源码，显式设置 `remote` 才拉取远端；缺失源码不会自动回退。预构建镜像运行时无需这些构建选项。详见 [源码来源配置](../integrations/dygk/README.md#源码来源配置)。

### 情报订阅认证

ThreatFox 与 URLhaus 需要 abuse.ch Auth-Key。可在「系统设置 → 外部情报查询」保存（需要
`HOST_CREDENTIAL_KEY`），或在部署 `.env` 中设置 `ABUSE_CH_AUTH_KEY` 后重建 server 容器。
不要把密钥或包含密钥的下载链接提交到仓库。配置后在「威胁情报」点击「立即同步」，以最近成功时间和同步结果验收。

# 多载体诱饵：布放、运行与事件

运行实现已抽离至独立引擎，统一接入与云端部署见 [运行包说明](../integrations/dygk/README.md)。

此实现位于 `ssh-decoy` worktree。控制台提供统一登记与事件查看；`decoyhost` 是显式启动的独立运行端。没有自动修改生产服务、真实用户 Shell 或已有文件。

## 支持范围

| 载体 | 已实现 | 尚未覆盖 |
| --- | --- | --- |
| SSH | `decoyhost -host-key` 统一认证回传；原 `sshdecoy` 本地实验入口保留；固定 Banner、拒绝全部认证 | 旧 JSONL 文件批量导入 |
| HTTP / HTML | 独立监听时根路径即诱饵页（扫描可发现），另有专用 `/decoy/<id>` 前缀供挂到业务路由；归档/状态页、一次性标记链接 | 登录仿真、真实业务响应替换、其他应用协议 |
| 文件 | 在指定父目录新建 `archive-<id>/<resource>`（目录名不带 decoy 字样）；Linux inotify 打开监视 | Windows 读取监视、进程身份归属、文件回连标记 |
| 模拟 Shell | stdin/stdout 的固定虚拟目录与命令；可作为专用诱饵账号的 forced-command | 自动创建账号或修改 sshd、真实命令执行 |
| 服务 Hook | Go `decoy.HTTPHandler` 可挂载到专用路由，也可反向代理到独立运行端 | 任意服务的通用二进制 Hook、真实服务全局插桩 |

HTTP、文件、模拟 Shell 各有独立版本模板，并可选择 `decoy` / `pause` / `padding`。新载体没有沿用 SSH 的效果结论：其暂停提示和 8 KiB 文本的实际干预效果尚未经过模型测试。文件标记目前只是内容中的关联标签，不会自行回连。

## 登记与运行

1. 控制台「资产 → 诱饵管理」选择组、资产、载体与策略。
2. HTTP/SSH 登记独立端口；文件登记单个 `.md` 文件名；模拟 Shell 使用固定资源 `simulated-shell`。不接受自定义模板、目录穿越或业务响应正文。
3. 新运行端点击「签发运行令牌」。令牌只显示一次，24 小时有效，持有有效租约的运行端每次续租顺延 24 小时，数据库仅保存 SHA-256；重新签发会立即使旧令牌失效。该接口需要组管理员且全局角色至少 analyst，或全局管理员。
4. 在授权目标主机上显式运行；从控制台取得令牌后，通过环境变量传入，不放进命令行参数、聊天或 shell 历史：

```bash
# server/ 内构建，再经既有运维或执行审批流程分发到目标主机。
go build -o /tmp/decoyhost ./cmd/decoyhost

# 在运行目标的交互式 shell 中输入令牌（输入不回显）。
read -rs DECOY_RUNTIME_TOKEN
export DECOY_RUNTIME_TOKEN

# HTTP：监听 IP 显式指定；端口与策略从平台取，不允许命令行覆盖。
/tmp/decoyhost -platform https://aidr.example.internal -deployment <登记UUID> -listen-host 127.0.0.1

# SSH：使用诱饵专用主机私钥，不复用真实 sshd 的密钥。
/tmp/decoyhost -platform https://aidr.example.internal -deployment <登记UUID> -host-key /srv/aidr-decoys/ssh_host_ed25519_key

# 文件：父目录由管理员预先创建，仅管理员可写；允许运维批准的用户读取。
/tmp/decoyhost -platform https://aidr.example.internal -deployment <登记UUID> -file-root /srv/aidr-decoys   # 父目录须 root 所有、属组与其他用户不可写

# 模拟 Shell：同一入口从登记读取载体，以 stdin/stdout 交互。
/tmp/decoyhost -platform https://aidr.example.internal -deployment <登记UUID>
```

HTTP 默认只监听回环，暴露到内网需显式选择监听 IP，或将**专用诱饵路由**反向代理到它。挂载前确认路由属于诱饵，不要覆盖业务路由。页面仅链接当前诱饵前缀，不依赖 Host 头、不引用第三方，不读取登录表单或密码。调用 `HTTPHandler` 做嵌入式 Hook 时，集成方必须同时保留授权定期核验、超时和并发限制；直接挂载函数不包含这些进程级保障。

模拟 Shell 只支持 `help`、`pwd`、`ls`、`cat README.md`、`verify <marker>`、`exit`。没有宿主文件读取、子进程、管道、命令替换或网络工具。每会话最多 32 轮、每行最多 1 KiB、运行端最多两分钟。绑定专用账号的系统配置需要管理员自行按现有流程完成；本程序不修改任何真实账号配置。

## 文件生命周期与可见性

文件运行端创建独占目录，已有目录或文件一律拒绝覆盖。只支持 Linux 打开监视；其他平台明确报不支持。`file_installed` 在监视成功建立后才上报，`file_opened` 只表示 inotify 捕获打开，不证明读取正文、AI 身份或恶意行为。

监视到修改、删除、移动或队列溢出即停止，保留失败记录到 stderr。正常退出和授权核验失败都会尝试清理；删除前核对文件内容和类型，已变化的文件保留现场，不递归删除目录。强制结束进程或机器断电无法保证清理，遗留目录会使下次布放拒绝覆盖，需管理员核对后处理。

运行端自身清理在 watcher 关闭后执行，避免把自己的清理读取计为诱饵访问。尚未实现其他平台进程的来源排除，杀毒、备份、运维工具都可能产生打开事件；不能据此自动告警为攻击。外部变更与内容核对依赖父目录仅由管理员写入，不用于敌对用户可写的共享目录。

## 认证、失效与事件

- `GET /api/decoy-profiles`：载体/策略元数据，无模板正文。
- `GET/POST /api/decoys`：登记查询/创建；字段 `{assetId, kind, profile, port, resource}`。
- `POST /api/decoys/<id>/token`：签发或轮换令牌；与审计同事务。
- `POST /api/decoys/<id>/revoke`：撤销登记并清除令牌；保留历史。
- `GET /api/decoys/<id>/observations`：按当前资产组授权查看最近 100 条，返回 `more` 标记。
- `GET /api/decoy-runtime/<id>/config` 与 `POST .../events`：专用运行端接口，以 `Authorization: Bearer <token>` 认证，不依赖浏览器会话。

令牌绑定单个登记、资产和签发时的组；过期、撤销、迁组后立即拒绝 API 请求。空闲运行端每 30 秒核验，平台明确拒绝（撤销、过期、迁组、配置变化）立即关闭服务或清理文件；网络不通或平台 5xx 容忍到最后一次成功核验后 60 秒，仍未恢复再停止，单次抖动不让诱饵下线。原独立 SSH 进程不具备这条轮询链，仍需手工停止。不能把“撤销登记”直接等同于已确认远程进程停止。

事件只接受 `{id, kind}`，资产与模板由登记确定；客户端不能提交原始命令、IP、密码、用户名或伪造资产。UUID 幂等，重复 ID 的不同内容拒绝；每登记滚动 24 小时最多 1000 条。运行端对访问类事件抽样：同类事件 10 分钟内只上报首条（标记命中、文件安装/删除、模拟 Shell 启动逐条上报），因此观察数不是访问次数，爆破或爬虫也不会几分钟耗尽配额让诱饵停服。达到上限或上报失败时，运行端停止继续提供诱饵。平台故障因此会降低诱饵可用性，这是当前明确的失败策略。收到事件只证明持有布放令牌的运行端作了报告，不是主机远程证明。

事件种类：`http_page`（已接到页面请求，不证明浏览器读完正文）、`marker_used`、`file_installed`、`file_opened`、`file_removed`、`shell_started`、`shell_action`。不记录模拟终端输入原文；标记使用也不证明 AI 身份。正常文件退出会尝试回写删除事件，令牌已撤销或平台不可用时无法确认回写，不能用事件缺失推断文件仍存在或已清理。

HTTP 最多 16 个并发请求槽，单次响应正文有界；每代令牌的标记只成功入库一次，数据库唯一约束阻止跨实例重放；令牌轮换生成新标记。旧实例重启后再遇到已消费标记，平台拒绝重复事件，运行端按上报失败策略停止。平台客户端只接受 HTTPS origin（测试时仅 IP 回环允许 HTTP），不跟随重定向、不使用环境 HTTP 代理。

## 巡检避让与后续工作

Pi 普通会话与沙箱上下文均包含当前组 `decoy_exclusions`，只带登记 ID、资产、载体、端口和资源，不带模板正文、标记或令牌。历史撤销登记也保留在避让清单，因为可能存在未清理的旧服务或文件。最多 500 条，截断有明确提示。

这是提示层的避让，不是对任意 shell 命令的强制路径过滤，也没有宣称能自动排除所有平台进程。

当前形成“登记 → 显式启动 → 认证事件入库 → 控制台查看 → 人工提交复核”的闭环。仍需继续完成 Agent 专用远程布放指令、Windows 文件监视、其他服务协议适配，以及通知和演练时间窗管理。不会把低置信观察直接提升成高危攻击。

## 人工复核与保留期

组内 analyst（全局角色至少 analyst）和管理员可在观察列表点击「提交复核」。接口为 `POST /api/decoys/<id>/observations/<observation-id>/review`。只接受访问类观察；安装、删除和 Banner 准备等生命周期事件不能提交复核。

标记命中（`marker_used`、`ssh_marker_followed`）在入库同一事务里自动开单，审计记为 system；页面访问、文件打开等噪声较大的观察仍需人工提交。同一事务创建原始证据、告警、incident、观察关联和审计；并发或重复提交返回同一个 incident。普通访问为低危，标记使用为中危，始终保留 `attribution=unconfirmed`，不携带诱饵指令正文或秘密。incident 按现有链路研判，分析师可使用已有结案/误报操作。只含诱饵观察的 incident 仅站内复核，不向外部机器人推送；同主机真实告警按关联窗口并入后照常走通知。含诱饵观察的 incident 始终计入待复核，AI 判良性也不会被自动结案。

自动响应额外排除仅有 `decoy.observation.*` 告警的资产，即便模型判 malicious 且置信度很高，也不会仅凭诱饵观察自动隔离该主机。带诱饵观察的主机须另有本机高危（≥4）独立告警才可能自动隔离：其他资产的告警或并入的本机低危噪声都不能解除排除；原有响应开关、白名单和审计不变。

普通观察跟随 `RETENTION_DAYS` 清理，最低保留 48 小时，覆盖 24 小时令牌、配额与幂等窗口；已关联复核 incident 的观察保留。删除时再次核对关联，避免清理过程中刚提交的证据被删。`RETENTION_DAYS=0` 仍表示禁用保留期清理。每轮按 10000 条一批清理到清完为止。

新 SSH 回传事件使用 `ssh_` 前缀，仅上报 Banner 准备、认证尝试、标记跟随/拒绝/耗尽，不上传用户名、密码、来源地址和会话原文。原 SSH 标记仍由监听器逐连接生成、限时且单次使用；不套用 HTTP 的每代固定标记约束。

## 验证

```bash
# server/
go test -race ./internal/decoy ./deception/... ./cmd/decoyhost
go test -race -tags integration -p 1 ./internal/api ./internal/agentchat ./internal/response ./internal/janitor -run 'Test(SSHDecoy|Decoy)'
go build ./...
# web/
npm run build
npm run lint
```

集成测试必须配置独立 `INTEGRATION_DATABASE_URL`，会清空测试表。覆盖 HTML 请求和标记回传、幂等和配额、令牌轮换/过期/迁组/撤销、文件保护、真实 Linux 打开监视、模拟 Shell 不执行宿主命令、跨组与敏感信息排除。

### 运行租约与凭据文件

`decoyhost` 在创建文件或监听端口前申请运行租约，准备完成后回报 running，随后每 30 秒检查配置并续租；90 秒未续租则过期。同一登记只允许一个有效的受管实例，旧实例不能恢复已过期租约，必须重新启动生成新实例 ID。令牌轮换后新实例需等待旧租约结束或过期。租约只证明持有令牌的程序进行了回报，不证明主机身份、外部可达性，也不能强制终止断网或被暂停的进程。

控制台每 15 秒刷新状态，区分未回报、启动中、自报在线、退出、失败、心跳过期以及等待停止确认。撤销或令牌失效不会被当成已退出：旧程序无法再认证退出回报时，状态最终显示心跳过期。事件接口在登记首次申请租约后，只接收有效 running 实例的事件；未申请过租约的旧客户端保留原有令牌认证兼容路径。

Linux 可通过 `-token-file /受控目录/runtime-token` 提供令牌，文件必须为普通文件、0600 或更严格权限（systemd `$CREDENTIALS_DIRECTORY` 内允许 systemd 自己设置的属组只读 0440），拒绝符号链接、可执行权限与其他用户访问权限。不能同时设置 `DECOY_RUNTIME_TOKEN`。不要把明文令牌写进安装命令、Shell 历史或平台 EXEC；现有 EXEC 会保留完整命令审计。Windows 凭据文件 ACL 校验尚未实现，仍只支持受控环境变量。

控制台现支持显式开启的 Linux SSH 远程安装，见下节。开发验证没有启动生产服务，也没有修改真实 SSH、业务 HTTP 响应、登录 Shell 配置或现有业务文件。

### Linux 常驻服务配置

新增 `cmd/decoyunit`，根据 HTTPS 平台地址、登记 UUID、载体和监听 IP 生成不含秘密的 systemd unit；不安装或启动服务。运行端通过 `-expected-kind` 核对平台载体后才申请租约，避免拿错配置启动另一类服务。支持 SSH、HTTP、文件，模拟 Shell 不作常驻服务。凭据经 systemd `LoadCredential` 提供，动态用户与每登记独立目录限制权限。完整安装、停止、轮换与残留处理见 [Linux 部署步骤](../deploy/decoy/README.md)。控制台安装入口复用此生成器，目标主机服务实机验收仍待完成。


### 控制台远程安装

组管理员（全局角色至少 analyst）可对全新登记点击「远程安装」，填写独立核对的 SSH SHA256 主机指纹、目标架构，以及监听 IP（SSH/HTTP）或文件父目录（文件载体，要求同 [Linux 部署步骤](../deploy/decoy/README.md)，脚本在目标上再核对属主与权限）。指纹可以是目标任一类主机密钥：平台依次按 ed25519、ECDSA、RSA 握手，直到出示的密钥与指纹一致；不一致的握手不提交凭据。只支持已明确标记为 Linux、当前组保存了 SSH 凭据的资产，以及 SSH/HTTP 非特权端口或文件载体。不接受已签发令牌、已有运行实例或已有安装尝试的登记。模拟 Shell 不作常驻服务。

- `DECOY_SSH_ENABLED=false` 默认关闭；开启还需 `HOST_CREDENTIAL_KEY`、HTTPS `ENROLL_PUBLIC_URL` 与 `DECOY_DIST_DIR`。
- 安装包固定名称 `decoyhost-linux-amd64` / `decoyhost-linux-arm64`；要求 `CGO_ENABLED=0` 的 Linux 64 位静态 ELF，最大 32 MiB。镜像构建包含两种架构的运行端，目录默认 `/opt/openxdr/decoy-dist`。裸机服务需自行构建并配置目录。
- `GET /api/decoy-install/status` 返回配置开关状态；不代表目标可连接或安装包已经验收。
- `POST /api/decoy-install/<id>` 接受 `{fingerprint, arch, listenHost}`，服务端按登记资产查找同组凭据，不接受任意凭据或目标地址。
- 资产锁内检查组权限、领取与现有 SSH 纳管共用的凭据租约、签发运行令牌，并把安装意图与审计同时提交。审计失败不下发；并发请求只允许一个进入安装。
- SSH 校验操作者提供的主机指纹与目标 hostname；脚本、令牌及安装包只走加密 stdin，使用固定 `sh -s` / `sudo -n sh -s` 入口，原始输出不记录。远端复核 Linux、架构、systemd 250+ 与包哈希，不访问第三方下载源。
- 每登记二进制放在 `/opt/aidr-decoy/<UUID>/decoyhost`，不覆盖共享二进制。配置、unit、状态目录有残留时拒绝安装；现有业务配置不作修改。SSH 使用新生成的专用主机密钥。
- 状态区分 idle、installing、installed、unconfirmed；installed 仅说明脚本结束，不代表运行端已在线。连接中断、取消或结果回写失败都不能推断远端没有副作用；不会自动重试。服务端中断后仍残留的 installing 超过三分钟在列表显示为未确认，不能再次安装。

连接、认证、主机指纹或主机名核对失败发生在脚本执行前，目标没有副作用：登记退回全新状态、未下发的令牌作废，修正后可直接重试。脚本开始执行后的失败仍记为未确认，先在目标检查独立 unit、目录与运行租约，确认现场处置完成后撤销旧登记、建立新登记；不提供覆盖式修复。安装请求不随浏览器断开而中断，nginx 对 `/api/decoy-install/` 放宽到 200 秒。运行令牌在运行端持续续租期间自动顺延；停止续租 24 小时后到期，轮换依照部署说明执行。撤销仍以运行端定期检查停止为主，失联时需人工确认进程与文件。

已验证接口权限、并发、审计事务、失败状态与 SSH 身份校验/传输机制。已在 systemd 252 隔离容器中完成安装、启动与回收验收（见末节），真实目标主机与生产端到端验收仍未完成；没有在生产开启该开关。


### systemd 252 凭据启动回归

2026-10-19 在隔离的 Debian/systemd 252.39 容器中，使用真实 `InstallScript`、真实 `decoyhost` 和进程内 HTTPS 平台替身完成 HTTP、SSH、文件三类载体验收：服务取得 running 租约、实际访问产生对应观察、正常停止回报 stopped；文件载体同时验证原文件和子目录清理。平台替身不验证数据库事务和实际 SSH 投递，因此这不是生产端到端验收。

此次启动失败包含两个需要区分的因素：

- 验收容器 `/run` 为 private 挂载，systemd 252 的凭据子进程创建的挂载无法传播回服务。非 root 进程看到 root 所有的空目录，root 服务也找不到 token。仅在一次性容器内部将 `/run` 设置为 shared 后，三类载体均通过；没有放宽服务 UID、capability 或凭据权限。[systemd 252 的实现](https://github.com/systemd/systemd/blob/v252/src/core/execute.c#L2951) 明确依赖 `/run` 的挂载传播。
- `os.OpenRoot` 还会额外要求父目录具有读权限。新增回归证明“目录只能遍历、已知文件可读”时旧读取函数失败。Linux 读取改用 `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` 直接打开已知文件，在同一描述符上校验普通文件和权限后读取；不需要列举父目录，保留符号链接拒绝及大小/内容限制，FIFO 不会阻塞启动。

可重复的验收入口为 `server/internal/decoy/systemd_acceptance_test.go`，通过 `systemdacceptance` build tag 和 `DECOY_SYSTEMD_ACCEPTANCE=1` 双重启用，且要求 root Docker 容器。先静态编译测试程序和 `decoyhost-linux-amd64`，复制到一次性 systemd 容器的 `/opt/acceptance`，设置 `DECOY_TEST_DIST_DIR=/opt/acceptance`，运行 `-test.run '^TestSystemdCredentialAcceptance$' -test.v -test.timeout 120s`。

容器应无外网、无宿主目录挂载、使用私有 cgroup namespace；在容器内部执行 `mount --make-shared /run`。不要在宿主机执行该验收或改变宿主挂载传播。测试会在容器中安装服务并临时修改 CA 信任库，结束后必须销毁整个容器，连同其中的令牌、密钥、文件和 unit。普通单元测试不执行这些操作。

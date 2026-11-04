# 文档导入与主机纳管

状态：已实现任意结构运维文档的 AI 提取、可编辑预览、资产与凭据入库、显式 SSH 安装入口；真实 Linux/Windows
远程安装仍需目标环境验收。导入成功、安装脚本成功、Agent 在线是三个不同状态。

## 操作流程

1. 通过可信 HTTPS 打开控制台，在资产页选择「从文档导入」和目标组。
2. 上传或粘贴现有运维文档，无需套模板。支持 UTF-8 文本（Markdown、CSV、JSON、YAML、配置和日志等）、DOCX、XLSX、PDF、PNG/JPEG/TIFF/WebP。上传最大 20 MiB，PDF 最多 30 页，提取文字最大 1 MiB、100 台主机。点击预览后调用配置的 AI 服务。
3. 根据原文行号核对主机名、地址、系统、端口、用户名和凭据关联，可编辑字段、删除误识别行、丢弃某条凭据。缺失系统等问题须修正后才能保存。勾选确认后入库；密码、私钥不出现在预览结果中。
4. 主机先显示「待纳管」。凭据页可删除凭据，也可单独点击「使用凭据纳管」。
5. 提供通过可信渠道独立核对的 SSH SHA256 主机指纹，再确认安装。
6. 安装脚本完成后等待 Agent 的 mTLS 注册和心跳；不能把安装响应当成已经在线。

只有该组 admin 或全局 admin 可导入、列出凭据元数据、删除凭据和发起安装。
导入本身不连接主机，也不会执行文档中的命令。AI 只做字段提取，不注册工具。原文（包括凭据）会发送至 `AI_BASE_URL` 指定的模型服务；部署者应选择适合处理运维凭据的服务。原文及模型原始响应不写入数据库、日志或审计。

## AI 提取与确认

端点、密钥与模型跟控制台「系统设置」里的 AI 配置走（默认取 `AI_BASE_URL` / `AI_API_KEY` / `AI_MODEL`），模型名未设置时使用 Pi 模型。未配置模型时明确提示，不会伪装成 AI 解析。AI 超时为 180 秒；结果截断、格式错误或凭据与原文不一致时整次拒绝，不能悄悄导入部分结果。

无需修改文档写法，例如：“应用节点 app-01，Ubuntu，地址 192.0.2.10；SSH 账号 ops，端口 2222，密码为交接记录中的明确值。”模型按语义识别，主机与凭据关联不清时提示人工核对。视觉模型可能识别错误，预览不是自动授权。

含凭据的预览需要 `HOST_CREDENTIAL_KEY`：凭据以 AES-GCM 加密引用返回，绑定当前用户、目标组，30 分钟过期。无凭据文档不要求该密钥。确认直接提交修正后的元数据及引用，不重复调用模型、不重新读取原文；后端重新校验并整批原子入库。HA 节点共享密钥即可处理同一预览，不依赖进程内缓存。删除凭据引用只登记资产。

文件读取不运行宏、不跟随外部链接。图片原始字节直接发送给视觉模型；PDF 使用 Poppler（`pdfinfo`、`pdftoppm`）逐页渲染后发送，不做本地 OCR。官方 server 镜像包含 PDF 渲染组件。DOCX 正文、页眉页脚、脚注以及 XLSX 工作表文字直接提取；内嵌图片同样直接发送。预览支持查看原图及定位来源页。最多 30 张图片或 PDF 页面，图像总量 20 MiB。转换临时目录仅当前系统用户可读，结束即清理。加密文件、旧版 DOC/XLS 等格式请先转换为 PDF。

视觉请求使用 `AI_VISION_MODEL`，未配置则使用研判模型（再回退 Pi 模型）；端点和密钥与上面相同。模型必须支持 OpenAI 兼容的 `image_url` 内容，服务不回退本地 OCR。图片中的凭据必须带有效图像引用，并提示人工对照核对；后端无法逐字验证视觉识别准确性。纯文本凭据仍要求与原文逐字一致。

## 结构化格式兼容

旧 `/preview`、`/commit` 接口仍保留确定性结构化导入，供已有调用方使用；控制台使用新的 AI 链路。以下格式仍可直接作为 AI 输入，不再是强制模板。
不会因为密码、私钥出现在文档中而拒绝整份文档，也不会把原文当普通知识文档保存。

Markdown 主机表格：

```markdown
| 主机名 | IP | 系统 | 端口 | 账号 | 密码 |
|---|---|---|---|---|---|
| app-01 | 192.0.2.10 | linux | 22 | root | 示例占位密码 |
| win-01 | 192.0.2.20 | windows | 22 | Administrator | 示例占位密码 |
```

YAML 文件、Markdown 内的 yaml/yml 代码块，以及等价 JSON 的 `hosts` 列表：

```yaml
hosts:
  - hostname: app-01
    address: 192.0.2.10
    os: linux
    port: 22
    username: root
    password: "示例占位密码"
  - hostname: app-02
    address: 192.0.2.11
    os: linux
    username: deploy
    private_key: |
      此处填写完整 PEM/OpenSSH 私钥；本占位文本不可导入
    passphrase: "仅加密私钥需要"
```

字段：`hostname`、`address`、`os`、`port`、`username`、`password`、`private_key`、
`passphrase`、`host_key`。`host_key` 可选，必须是有效 `SHA256:…` SSH 主机指纹。
密码与私钥二选一；可不提供凭据，只导入资产。含竖线、多行的密码或私钥使用 YAML，
不要塞进 Markdown 表格。私钥会在导入时验证格式和解密口令。

`os` 支持写 family（`linux` / `windows`）或发行版名——`ubuntu 24.04`、`rocky linux 9`、
`kylin v10`、`麒麟`、`统信 UOS`、`Windows Server 2022` 都认，归一后资产上只存 family
（供 Sigma 求值过滤与升级选包），发行版与版本存进 `os_display` 展示；agent 上线后由
设备清单读到的实测值（`/etc/os-release` 的 `PRETTY_NAME`、Windows 注册表）覆盖声明的值。
省略 `os` 时默认 `linux`；认不出的写法（如 `macos`）该行报错，宁拒不猜。

主机名省略时使用地址，但远程纳管要求其与目标 `hostname` 一致；IPv6 地址请显式填写
合法主机名。已有同组资产且尚无凭据时可补充凭据，保留已有资产字段。已有凭据、跨组或未分组资产冲突时整批拒绝，不覆盖已有身份、不跨组挪用资产、不部分提交。

## 凭据存储

- 配置 `HOST_CREDENTIAL_KEY`：base64 编码的 32 字节随机密钥，可用 `openssl rand -base64 32`
  生成。通过受保护的环境变量注入，不提交仓库，不存入普通设置表。
- 使用 AES-256-GCM，每条凭据独立随机 nonce。附加认证数据绑定凭据 ID、资产、组、
  地址、端口、用户名、类型和主机指纹，调换密文或连接参数会导致解密失败。
- 数据库存储在独立的 `host_credentials` 表；Ent 敏感字段、API DTO 和模型只读视图
  都不暴露密文或明文。数据库备份仍按敏感数据管理。
- 原始文档不入库；审计只记录操作、资产/组标识和数量，不记录凭据、文档或远程输出。
- 主机移组、移出组或删除组时删除对应凭据，不把旧组授权下的登录身份自动交给新组。
- HA 各节点必须配置同一密钥，密钥与数据库分开备份。当前不提供在线轮换工具；
  不得直接替换密钥，否则已有凭据不能解密。丢失密钥后需删除旧凭据并重新导入；已有同组资产可以重新关联凭据。

## 使用凭据安装

服务端需要：

| 环境变量 | 默认值 | 用途 |
|---|---|---|
| `HOST_CREDENTIAL_KEY` | 空 | 空时禁止导入含凭据的文档；纯资产导入仍可用 |
| `ENROLL_SSH_ENABLED` | `false` | 显式开启使用保存凭据进行 SSH 安装 |
| `ENROLL_PUBLIC_URL` | 空 | 主机可访问的可信 HTTPS 控制台地址，用于下载 Agent 和证书注册 |
| `ENROLL_GRPC_URL` | 空 | Agent 可访问的 gRPC 地址；生产使用 mTLS |
| `TLS_CA_KEY_FILE` | 空 | mTLS 签发密钥，参见 [部署与使用手册](deployment.md#添加主机) |
| `AGENT_DIST_DIR` | 空 | 各平台 Agent 安装包目录 |

SSH 纳管要求 mTLS 在线签发可用。Linux 需要 root，或具有免交互 sudo 权限的账号。Windows 需要已启用 OpenSSH、
可使用 PowerShell 的管理员账号。本轮不提供 WinRM、RDP 或交互式 sudo 密码提权。
这些 Windows 凭据仍可入库，但未配置 OpenSSH 时不能自动安装。

连接固定目标并核验 SSH 主机指纹，然后核对实际主机名；仅执行平台内置安装脚本。
接入令牌绑定组、有效期 5 分钟，调用结束即撤销。每条凭据有数据库租约，避免 HA
节点重复发起安装。安装过程最多两分钟，客户端中断会关闭连接；超时、连接中断或
脚本失败均表示**未确认完成**，应先核对服务和平台心跳，不能断言没有副作用后盲目重试。
远程 stdout/stderr 不回传前端或写入日志。

## 安装与升级失败保护

Agent 将待签私钥写入 `agent.key.pending`；申请被拒绝不覆盖已有私钥。收到新证书后先
校验公私钥匹配，再写入独立的 `identity-<uuid>` 目录，最后原子替换 `agent.env`。
旧身份文件保留，失败不会让已有证书配上一把新私钥。

自动升级的二进制替换失败时恢复原路径；旧版保留 `.prev`。这不等价于启动后的健康
自动回滚，后者仍需额外的运行时验收机制。

### 安装包发布签名

agent 会自动升级成 server 分发目录里的版本，所以拿下一个 server 节点，就能往全网推恶意 agent。
发布签名把这条路堵上：

- **私钥**：发布私钥只放在发布者自己的机器上，不进 server 节点。
  `server/cmd/signrelease keygen <私钥文件>` 生成，打印的公钥十六进制在构建 agent 时设为 `OPENXDR_RELEASE_PUBKEY`，编进二进制。
- **签名**：每次往分发目录放安装包，同时放 `signrelease sign <私钥> <平台> <安装包>` 生成的 `<安装包>.sig`。
  签名覆盖 `openxdr-agent-release-v1\0` + 平台 + `\0` + 安装包 SHA-256。server 注册时把它随升级指示下发（`upgrade_signature`），
  server 不持有私钥，也不校验。
- **校验**：嵌了公钥的 agent 在下载之前先验签，没有签名、签名对不上平台或哈希，一律不升级，继续跑当前版本。
  没嵌公钥的构建（开源默认，包括 release 工作流）只校验哈希，与以往一致。
- **切换**：先把带公钥的 agent 签好名放进分发目录，现有 agent 按以往规则升级上去，之后的升级就都要签名。
- **私钥丢了**：已部署的 agent 再也不接受新安装包，只能逐台重装，所以私钥要单独备份。

## API

- `GET /api/host-import/status`：`credentialStorage`、`sshEnrollment`、`aiParsing` 能力状态。
- `POST /api/host-import/extract`：multipart `groupId`、`file` → `{document,images:[{name,dataUrl}]}`；仅组管理员可用，敏感响应禁止缓存。
- `POST /api/host-import/analyze`：`{groupId,document,images}` → 后台任务 `{id,status}`，立即返回；模型在服务端跑，关掉窗口、换页、刷新都不打断。同一组同时只有一份在解析（409），全局并发 2（429）。
- `GET /api/host-import/analyze?groupId=`：读自己在这个组最近一次的提取，`status` 为 none / running / done / failed，done 时 `result` 为 `{hosts}`：主机含可编辑元数据、`lines`、`images`（从 1 开始的图像编号）、`issues`、`needsReview` 及可选 `credentialToken`，不返回秘密。文档原文只在内存里交给模型、不落库；结果只存封存后的凭据令牌，一小时后清掉，确认导入后立即清掉。`DELETE` 同路径放弃这次结果。
- `POST /api/host-import/confirm`：`{groupId,hosts,confirmed:true}` → `{assetIds}`；无模型调用。移除 `credentialToken` 表示不保存该凭据。重复主机、过期引用、跨用户/组引用及现有资产冲突均拒绝。
- `POST /api/host-import/preview`：`{groupId,document,images}` → `{digest,hosts}`，hosts 不包含秘密。
- `POST /api/host-import/commit`：`{groupId,document,digest}` → `{assetIds}`，重新解析原文并
  检查摘要，单事务提交。摘要用于核对预览内容，不是授权凭证。
- `GET /api/host-import/credentials?groupId=…`：仅凭据元数据。
- `DELETE /api/host-import/credentials/{id}`：删除凭据，不卸载 Agent、不删除资产。
- `POST /api/host-import/credentials/{id}/enroll`：`{fingerprint}`，显式安装；成功响应
  `{status:"installed",message:…}`，不代表已在线。

前端入口：`web/src/components/ImportHostsModal.tsx`。
解析、加密及 SSH：`server/internal/hostimport/`；接口：`server/internal/api/hostimport.go`。

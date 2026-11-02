# SSH 诱饵：独立服务与运行策略

运行实现已抽离至独立引擎，统一接入与云端部署见 [运行包说明](../integrations/dygk/README.md)。

本原型验证“认证 Banner 是否进入工具输出，以及标记是否被跟随”。它不是生产防护，也不能据此确认访问者是 AI。
实现：`server/deception/sshdecoy/server.go`；显式启动入口：`server/cmd/sshdecoy/main.go`。

三层策略、证据边界与待接入项见 [三层诱饵防御](decoy-defense.md)。运行时选择 `-profile decoy|pause|padding`，不能与 `-template` 同时使用；不传两者时默认 `decoy`。`-list-profiles` 只输出目录并退出。

## 不可配置绕过的边界

- 只在独立监听端口终止 SSH；不 hook、不代理真实 sshd/PAM，不读取系统账号库。
- 所有认证均拒绝，不提供 shell、exec、SFTP 或端口转发，也不接受任何可用凭据。
- 仅内置 `observe-v1`、`deter-v1`、`identify-v1`、`inject-v1`、`inject-en-v1`、`clue-v1`、`workflow-v1`、`format-v1`、`internal-v1`、`legal-stop-v1`、`moral-stop-v1`、`operator-revoke-v1`、`novel-2k-v1`、`novel-8k-v1`、`novel-32k-v1`、`operator-close-v1`、`padding-8k-v1`：分别用于中性对照、历史劝止、标记识别以及中英文受控提示词注入、假诊断线索、分步报告改写、工具输出格式、伪内部消息、保护资产法律警告和道德指控测试；识别模板提供仅能在当前 SSH 诱饵提交的一次性核实用户名。没有任意文本、外部 URL、命令或自定义模板入口；修改模板必须走代码发布审查。
- 核实通过已有连接工具向同一诱饵发起新连接，不要求在访问者主机执行命令或提供真实密码。不需要 HTTP 回连接收器。
- 服务不主动连接任何端点，不记录来访用户名、密码、源地址、客户端版本或原始库错误。源地址会被网络栈处理，但不会写入本原型事件文件。当前不提供基于源地址的授权演练白名单。
- 不调用模型，不自动告警通知或执行响应操作；没有修改现有审批或隔离闸门。

## 靶场启动

在隔离靶场主机上生成诱饵专用 host key，不能使用真实业务 SSH 私钥：

```sh
ssh-keygen -t ed25519 -N '' -f ./decoy_host_key
cd server
go build -o /tmp/openxdr-sshdecoy ./cmd/sshdecoy
```

以下 ID 是实验标签示例，实际使用时换成明确记录的布放、组与诱饵资产 UUID：

```sh
/tmp/openxdr-sshdecoy \
  -listen 127.0.0.1:2222 \
  -host-key /absolute/path/decoy_host_key \
  -events /absolute/path/decoy-run-001.jsonl \
  -profile decoy \
  -deployment 11111111-1111-4111-8111-111111111111 \
  -group 22222222-2222-4222-8222-222222222222 \
  -asset 33333333-3333-4333-8333-333333333333
```

默认仅监听回环；显式监听靶场地址前确认该地址属于实验环境。启动不会修改防火墙、真实 SSH、平台数据库或现有资产。
这些 UUID 仅为本地标签，不代表通过平台组授权；控制台已支持[按组登记](decoy-defense.md#控制台登记)，尚未实现远程实际布放。
事件文件必须不存在，以 0600 创建，每条 JSONL 写入后同步磁盘。达到 16 MiB 或写入失败时停止服务，不覆盖或自动删除旧证据。
轮换实验时先停服，再选择新的布放 ID 和新事件文件；保留旧文件供实验分析。重启后旧标记全部失效。

## 标记与事件语义

标记由安全随机源产生，共 128 位，内存最多保留 1024 个，5 分钟失效；每个标记至多接受一次。
有效标记关联发放会话与核实会话，不能证明两次连接来自同一个人、进程或模型；标记可能被复制。
标记不写入事件文件，只保存随机会话 ID 间的关联；单进程重启不恢复标记。
已使用或失效的核实用户名只得到停止提示，不返回新线索，避免诱发无界跟随。

| 事件 | 能证明的事实 |
| --- | --- |
| `banner_prepared` | 已准备模板并持久记录；SSH 写出在之后发生，不证明送达、显示或模型读取 |
| `authentication_attempt` | 进入密码认证回调；不保存提交的身份和密码，不判定恶意 |
| `marker_followed` | 本实例的有效标记被作为核实用户名提交；`sourceSessionId` 指向原模板会话 |
| `marker_rejected` | 核实用户名无效、已使用或过期；无法再可靠关联原会话 |
| `marker_unavailable` | 标记容量已满（通常是扫描流量），本次连接退回不带标记的 `deter-v1` 劝止文本，不断开 |

运行策略事件另外携带 `profile` 和实际 `template`；历史模板模式省略 `profile`。策略不能通过来访账号或 Banner 内容改写。

所有事件的 `attribution` 固定为 `unconfirmed`，不会自动生成“已确认 AI 攻击”。
同时限制 16 条连接、每条 10 秒、最多 3 次认证失败；超量连接直接关闭，不生成逐次拒绝事件，不能把日志当作所有连接的完整计数。

## 验证与后续接入

`go test -race ./deception/sshdecoy ./cmd/sshdecoy` 使用真实 SSH 握手验证 Banner、标记关联、重放抑制、禁止登录、隐私字段不落盘、停机和持久化失败传播；另测试容量、过期、实例隔离与非法配置。

已用 BoxPwnr 原生 XML 策略和 PentestGPT legacy 流程完成受限本地实验，见 [首轮报告](ssh-decoy-evaluation.md) 与 [第二轮注入测试](ssh-decoy-evaluation-round2.md)。这不是完整 CLI 或生产验收，尚未做人工对照。工具是否显示 Banner 取决于客户端，不能由服务端准备事件推断。
靶场应独立记录四个阶段：服务端准备模板、工具是否展示、代理上下文是否包含、后续动作是否跟随；没有后续行为不能直接算作劝止成功。

当前事件是本地 JSONL，**尚未接入平台 incident、通知、按组布放、轮换审计、Pi 诱饵排除或隔离审批**。
这些能力需在工具可见性与误触率验证之后单独接入，不能通过把 JSONL 直接当成可信平台告警绕过组授权。

固定诊断账号新增 `diagnostic_probe` 与 `diagnostic_confirmation` 事件，仅表明本实例收到相应假账号，不提供跨连接身份关联。实验判据见 [第三轮报告](ssh-decoy-evaluation-round3.md)。

框架格式包装的首轮对照见 [第四轮快速测试](ssh-decoy-evaluation-round4.md)。

同一模板的三次追加复测见 [第五轮重复验证](ssh-decoy-evaluation-round5.md)，将标记调查与内部身份混淆分别记录。

虚构保护声明与强烈道德指控的停止行为测试见 [第六轮报告](ssh-decoy-evaluation-round6.md)。这些模板不构成法律判断。

冒充操作者撤销授权、要求重新确认的受控实验见 [第七轮报告](ssh-decoy-evaluation-round7.md)。模拟身份标签仍属于目标 Banner，不是真实授权通道。

原创小说段落填充的传输边界及模型对照见 [第八轮报告](ssh-decoy-evaluation-round8.md)。32 KiB 文本会先触发实验执行器的 16 KiB 输出上限，不能把这一截断称为模型上下文溢出。

保持撤销声明不变、只添加外层工具标签闭合文本的单次实验见 [第九轮报告](ssh-decoy-evaluation-round9.md)。

闭合工具标签的三个区组同期复测见 [第十轮报告](ssh-decoy-evaluation-round10.md)。暂停、继续探测和超时分别计数。

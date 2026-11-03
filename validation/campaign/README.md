# 攻击活动回放

真实生产事件的事件序列（脱敏）走**真实入库处理器 + 仓库规则与时序规则 + 关联引擎**回放，断言事件归属、横向边、
合成告警与升级标记。它验证的是 detectcheck（单事件规则对拍）与 `validation/temporal/`（时序规则）覆盖不到的一层：
告警怎样被组织成 incident、能不能升级到有人看。**关联与研判的改动都要过这里的用例。**

```sh
# 从 server/ 运行，需独立测试 PostgreSQL（INTEGRATION_DATABASE_URL）
go test -tags integration -p 1 ./internal/correlate -run TestCampaignReplay -count=1 -v
```

CI 的集成测试步骤已自动包含，不需要新增服务。

## 语料格式

- `assets`：主机名、组、地址（`assets.ip_addrs`）。
- `timeline`：按事件时间的条目。事件条目给 `id`、`at`（真实时间）、`asset`、`class`（OCSF）、`username`、`raw`（事件体，
  与采集端产出的结构一致）；`repeat` + `every` 表示同一事件按间隔重复，`users` 给出重复时轮换的登录用户名。
  `triage` 条目把某条事件的告警所在的 incident 标成已研判（`verdict`，`notified` 表示当时已推送），模拟研判引擎在那一刻的结论。
- 回放把整条时间线平移到「喷洒开始于一小时前」，事件按时间顺序逐条入库，模拟时间每过一分钟跑一次关联批次。

## 2026-11-02 Prowl 跳板横向（`2026-11-02-prowl-pivot.json`）

复盘见 [docs/attack-campaign-design.md](../../docs/attack-campaign-design.md)。外部人员拿 Prowl 攻防平台（uos-server，10.1.1.170）的
admin 弱口令重新部署 AWD 比赛，攻陷靶机容器 `range_c11_comp1_t2`（docker `4f173e0d45b0`）当跳板，对其他组的纳管主机 SSH 口令喷洒。
生产上跳板容器的告警全部并进 11-01 建的 uos-server 噪声 incident（2389 条告警），受害主机各自成「可疑」incident，没人收到通知。

语料（事件形状取自生产只读副本，按告警与事件的 `(id, ts)` 小范围回查）：

| 阶段 | 内容 |
|---|---|
| 宿主机噪声 | dockerd 解析 dnslog（4 级，噪声 incident 的起点）；运维插件经 SSH（10.1.1.35）每 5 分钟跑的 `whoami`、`sed /etc/locale.conf`（3 级）；另一个容器 `license-service` 里形似健康检查的 `/dev/tcp` 探活（2 级，旧 agent 没有健康检查标记）。22:00 标成「可疑」 |
| 靶机容器 | wget 下载到 /tmp、base64 Python 一行代码、`which curl python3 …` 加 `/dev/tcp` 扫描、`nohup python3 /tmp/brute.py`、`setsid … nohup pip install impacket`、`nohup python3 ssh_test.py top`。22:45 标成「可疑」且已推送 |
| 口令喷洒 | 受害方 sshd 登录失败，来源 10.1.1.170：openxdr-node2（23:10:24）、openxdr-node1（23:11:23）、lizhen-dev、openxdr-test-linux，用户名轮换 |

断言：跳板容器的告警自成 incident、不进噪声 incident，宿主机噪声仍在噪声 incident；四台受害主机上的全部告警（登录失败、
同主机 / 同账号的时序爆破）经受害方证据并进跳板的 incident，图上有 uos-server 到每台受害主机的横向边；恰好一条
`xdr:internal-lateral-spray` 落在 uos-server 上并在同一 incident；incident 最高级别 5、立即重研判、推送标记清掉、进需人工复核口径。

脱敏与改动：

- 凭据与载荷：`admin:admin`、Basic 认证头、喷洒脚本里的口令表与 base64 载荷都已去掉或截断，只保留规则匹配需要的形状；
  靶机里的用户名换成 `ctf`，运维会话的公钥指纹换成占位值；进程 GUID 不入语料（不测血缘）。
- **时间挪动**：真实时间线上 10 分钟内只有 node2、node1 两台受害主机（lizhen-dev 在 23:30:01、openxdr-test-linux 在 00:22:27、
  dynamicdefend-v2 在 00:22:50），按「10 分钟 ≥ 3 台」的阈值生产上**不会**触发 `xdr:internal-lateral-spray`。
  语料把 lizhen-dev、openxdr-test-linux 挪到 23:11:55、23:12:05，验证的是关联与升级链路，不代表阈值已覆盖本次事件；
  阈值调整另行决定。
- 数量：每台受害主机的失败次数压到 3–12 次（生产 55、80、3、180 次），足以命中登录失败与时序爆破规则。

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
admin 弱口令重新部署 AWD 比赛，攻陷靶机容器 `range_c11_comp1_t2`（docker `4f173e0d45b0`）当跳板，对其他纳管主机 SSH 口令喷洒。
生产上跳板容器的告警全部并进 11-01 建的 uos-server 噪声 incident（2389 条告警），受害主机各自成「可疑」incident，没人收到通知。

**时间是生产真实时刻（UTC），回放不平移、不挪动。** 事件形状、时刻、每台受害主机的失败次数与用户名取自生产只读副本
（按资产与时间段小范围回查告警和事件）。只有宿主机巡检噪声是生成的：首次时刻真实，之后按 5 分钟周期重复（生产实际每轮有几十秒漂移）；
同一台受害主机的多次失败按真实的首末时刻均匀铺开。

| 时刻（UTC） | 内容 |
|---|---|
| 11-02 18:01 起 | 宿主机噪声：运维插件经 SSH（10.1.1.35）每 5 分钟跑的 `whoami`、`sed /etc/locale.conf`（3 级）。18:20 标成「可疑」 |
| 18:30–18:36 | 跳板容器第一段：base64 Python、`nohup python3 /tmp/lis.py` |
| 18:49:16 | 跳板对 cache（10 次）、termix（4 次）登录失败——离 23 点的喷洒远超 60 分钟，**不能**让喷洒告警凑数 |
| 22:31–00:22 | 跳板容器第二段：wget 下载到 /tmp、base64 Python、`/dev/tcp` 扫描、多次 `nohup python3 …`、`setsid … pip install impacket`。22:45 标成「可疑」且已推送；另有 `license-service` 容器里形似健康检查的探活（2 级） |
| 23:10:24 / 23:11:23 | openxdr-node2（55 次）、openxdr-node1（80 次）登录失败 |
| 23:30:01 | lizhen-dev（3 次）：60 分钟内第三台，**喷洒告警在这里出现** |
| 11-03 00:22:27 / 00:22:50 | openxdr-test-linux（180 次）、dynamicdefend-v2（11 次） |

断言：

- 跳板容器两段活动（相隔近 4 小时）各自成 incident，都不进宿主机噪声 incident；宿主机自身的告警留在噪声 incident；别的容器不进这三个。
- 受害主机的全部告警（登录失败、同主机 / 同账号的时序爆破）经受害方证据并进当时跳板所在的 incident：cache、termix 进第一段，
  其余五台进第二段（攻击 incident），图上有 uos-server 到每台受害主机的横向边。
- 喷洒告警在 lizhen-dev 第一条登录失败之前没有、之后恰好一条（ts 即该时刻，detail 列 node2、node1、lizhen-dev）；
  00:22 的两台距首条 53 分钟，在 60 分钟去重窗口内并进同一条：openxdr-test-linux 到达时回看 60 分钟只有它和 lizhen-dev 两台，只记证据；
  dynamicdefend-v2 凑齐三台，每条累加计数并刷新 detail。最终 count = 14（lizhen-dev 3 + dynamicdefend-v2 11），`last_ts` 是
  dynamicdefend-v2 最后一条，detail 列出五台受害主机的地址与次数，不含 18:49 的 cache、termix。
- 攻击 incident 最高级别 5、立即重研判、推送标记清掉、进需人工复核口径。

脱敏：`admin:admin`、Basic 认证头、喷洒脚本里的口令表与 base64 载荷都已去掉或截断，只保留规则匹配需要的形状；
靶机里的用户名换成 `ctf`，运维会话的公钥指纹换成占位值；进程 GUID 不入语料（不测血缘）。
生产上噪声 incident 的起点是 11-01 dockerd 解析 dnslog，离本段太远，语料不含。

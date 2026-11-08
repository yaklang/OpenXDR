# SigmaHQ 社区规则

来自 [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)（同步于 `b7920ed`，2026-10-18），只取本平台有数据源的部分：
`rules/linux/{process_creation,file_event,network_connection}` 与 `rules/network/dns`，共 131 条。

这些规则按 [Detection Rule License (DRL) 1.1](LICENSE.Detection.Rules.md) 授权：
规则文件原样保留（含 `author` 等字段）；基于规则命中产生的消息（告警、事件、报告、通知）都会带上规则作者。

## 引入前的回测

规则能加载不等于该上线。引入前用 `server/cmd/backtest` 在生产只读副本上回放了近 3 天的真实事件（907 万条）：
每天几十到几万次命中的低价值规则（宿主机自身反复执行 `ip`、`uname`、`ping`、`last`、`id` 之类）、
明显误报、与自研规则重复且更不准的，列在 [excluded.txt](excluded.txt) 里不引入，理由逐条写明。

## 更新

```sh
git clone --depth 1 https://github.com/SigmaHQ/sigma /tmp/sigma
sh rules/sigmahq/sync.sh /tmp/sigma
cd server && go run ./cmd/sigmacheck --strict ../rules && go run ./cmd/detectcheck --strict
DATABASE_URL=<只读副本> go run ./cmd/backtest -days 3 ../rules/sigmahq   # 新增规则命中过多的加进 excluded.txt
```

中文标题不改规则文件，写在 `rules/titles.zh.json`（规则 ID → 中文）；同步新增的规则要在那里补译名，
`go test ./internal/sigma` 会检查译名表里的 ID 都对应真实规则。

本平台的引擎不支持的写法（统计型条件、未实现的修饰符）会被拒绝加载，`sigmacheck --strict` 会报出来。

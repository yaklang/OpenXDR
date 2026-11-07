# 原生导出样本

`ntopng-7.0.261106.jsonl` 来自官方 `ntop/ntopng` 镜像实际运行的 Syslog 导出，
版本 7.0.261106，镜像 digest：
`sha256:3f8a61ee93abb3d066b5bcb7ee55b92a75a231c03ad13c217958f89132faac8b`。

2026-11-07 用 Scapy 生成 10 包离线 PCAP（HTTP 一条、DNS 一条），
在 `--network none` 的容器内运行：

```text
-i /input.pcap -F syslog --shutdown-when-done --pcap-file-purge-flows -n 3
```

从独立 UNIX Syslog socket 收集 JSON 原文，未捕获真实主机流量。
地址使用文档网段，域名使用 `example.test`。
该镜像报告 Community 模式，未安装或绕过许可证；导出得到两条会话。
样本已通过 HTTPS 文件导入、带 Syslog 头导入、重复导入幂等与 PostgreSQL 落库验证。
镜像的离线运行日志包含缺少授权、capabilities 和 checks 配置的提示；这里仅验证实际导出的两条会话，
不以此证明该版本的所有实时采集、GUI 或 Pro 功能均可用。

nProbe 11.2.261106 官方镜像在缺少许可证时拒绝执行，因此未把构造样本标为 nProbe 原生导出。

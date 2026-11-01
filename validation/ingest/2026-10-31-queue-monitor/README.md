# 队列监控优化与部署验收

2026-10-31，基于 `74f129152` 的本次改动，先部署后提交。发布使用
`ALLOW_DIRTY=1 deploy/ha/release.sh`，node2 → node1，部署标签 `74f129152-dirty`。
两节点 server 镜像均为 `sha256:ad9ea2a48eaaf6c4c12a09d71145d2482373f3d67a7523a654f498b34a8dd02e`；
web 镜像为 `sha256:47e015cfc6af4884a10806982cb3bcc022ef9ea33b32a64207441dd89fd1ffc3`。
原版本保留为 `pre-74f129152-dirty`，回滚按 HA 发布脚本说明合并现有 compose override。

## 改动与验证边界

每轮先检查流副本，再查询分片；整轮共用 5 秒截止时间。轮询游标在超时后继续向后，
避免后面的分片长期饥饿。新增逐分片最近成功采样时间，启动值为 0；失败不覆盖上次成功值。
不改变发布、消费确认、重试、分片或副本数。

回归覆盖：健康检查先于阻塞分片、统一 context 的取消、失败保留旧值与时间、
33 轮单分片采样覆盖 32 个分片及回绕、待办与未确认消息合计；独立真实 NATS 验证 3 条待办。

## 线上观察

- 两节点 `readyz`、VIP 后端与 web 入口均返回 200。
- 第二轮采样：两节点各 32 个分片均已成功采样，最大年龄约 6.09 / 3.25 秒，待办均为 0。
- 后续采样：最大年龄约 2.77 / 9.92 秒；新增 Agent 事件处理量分别为 1141 / 1203，
  两节点均未暴露新的 pipeline failure 计数。待办分别为 7 / 1；这是同一队列的不同时间快照，不能求和。
- PostgreSQL 仍为 node1 主库、node2 同步备库，timeline 14；采样复制 lag 为 0。
- SQL 读取最新事件，采样年龄分别约 0.91 秒、2.23 秒，证明业务事件继续落库。
- Leader API 多次返回两个应用副本 `current=true`，也观察到 node2 暂时 `current=false, lag=1`。
  `/jsz` 本地视图中的大 lag 不作为集群结论；本轮不宣称复制波动消除，也未迁移 Leader 或调整 NATS。

这是一轮监控改动验收，不是容量或故障切换验收。原始日志与采样保存在运维控制机
`/tmp/openxdr-monitor-release-6s1q5qm3/`。首次全量集成测试因运行期间修改测试函数名导致生成入口与源码不一致，
保留失败记录；固定源码后重跑结果见本目录末尾。

## 运行源码校验

部署构建后再次确认以下两个运行源码的 SHA256 未变，随本记录一起提交：

```text
ca803bdf3f46728bc294796565be444ff36ab47048150def8222f886d1ddfc0e  server/internal/eventbus/bus.go
3cd715ef048b8efc15cf4d34e82dd6e21ffd48ffd1648df2feb1667c3407784b  server/internal/telemetry/metrics.go
```

## 最终检查结果

以下检查全部通过：server `go build ./...`、`go vet ./...`、`go test ./...`，
相关包 `go test -race ./internal/eventbus ./internal/telemetry`，
独立临时 PostgreSQL 上 `go test -tags integration -p 1 ./...`（固定源码后的完整重跑），
`sigmacheck --strict`、`detectcheck --strict`、格式与 diff 检查，以及 server/web 容器镜像构建。
检测回归为 148 个用例、0 个不符合预期；其中 33 个仍为显式记录的已知缺口。
临时测试库不连接生产，验收后停止并移除。

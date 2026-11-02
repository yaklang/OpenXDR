# HA 环境中的独立 DYGK 引擎

OpenXDR 应用双节点不等于 DYGK 引擎双节点。当前方案只在选定的一个应用节点运行
管理器，SQLite 状态保存在该节点的数据卷。不要把同一配置复制到两个节点并声称
支持自动接管；运行租约不能替代状态复制。

## 安装与重建配置

先按 [引擎构建说明](../../integrations/dygk/README.md) 提供锁定版本源码并构建、验证
独立镜像，将镜像导入目标节点。公开镜像发布另受上游分发授权限制。

在选定节点的 `/opt/openxdr-ha` 操作：

1. 备份现有 Compose 和 `.env`，保留原有文件权限；备份可能含凭据，不提交到 Git。
2. 将本目录的 `docker-compose.dygk.yml` 放在主 Compose 旁；仅在此节点的 `.env`
   设置 `DYGK_IMAGE` 为已导入、已验收的镜像标签或摘要，例如本次私有部署的
   `openxdr-deception:7f400b4`。此标签不是公共仓库下载地址。
3. 校验并启动：

```bash
docker compose -f docker-compose.ha-node.yml -f docker-compose.dygk.yml --profile dygk config --quiet
docker compose -f docker-compose.ha-node.yml -f docker-compose.dygk.yml up -d --no-build --no-deps server
docker compose -f docker-compose.ha-node.yml -f docker-compose.dygk.yml --profile dygk up -d --no-build --no-deps deception
```

首次启用会重建该节点 server，应先选择不持有 VIP 的节点，并确认另一节点健康。
后续 `release.sh` 自动合并目标节点已有的补充文件，但不分发该文件、不修改 `.env`、
不升级独立引擎。手工重建、停止或回滚时也要使用相同的两个 `-f` 参数。

补充配置保留原有 server 环境、网络和挂载，仅增加 Unix 控制 socket。管理器与
server 共用 `deception-control` 卷，状态使用 `deception-data` 卷，进程 UID 为
10001。沿用原 Compose 项目名与目录，避免误建一套空卷。

默认只映射 `127.0.0.1:18179`，与 HA server 的 `18080` 端口区分；控制台测试登记
也须选择 18179。真实业务接入需要另行配置入口代理、端口和访问范围，并验证站点
兼容性，不能把 `running` 当成外部访问已经打通。

2026-10-29 的现有部署已把等价字段写入 `.197` 的主 Compose，暂不需要为使用本
说明而重启。改用补充文件时先比较合并结果，确认镜像、卷名、端口和安全选项一致；
不要整份替换含有现场配置的主 Compose。

## 升级、备份与恢复

引擎升级与 server/web 滚动发布分别进行：

1. 记录当前镜像摘要、平台修订、项目名及实际数据卷名，保留旧镜像。
2. 在控制台请求停止登记，等待实例确认 `stopped`，检查监听关闭；有未确认积压时
   先排查补传，不能直接更换修订。业务网关须先安排入口维护或切换。
3. 使用上述两份 Compose 停止 `deception` 服务，待容器退出后制作数据卷的完整
   冷备份或存储快照，保留 UID/GID。不要只复制正在写入的 SQLite 主文件；控制
   socket 是运行产物，不作为数据恢复。平台数据库备份另见 [备份说明](backup-recovery.md)。
4. 修改 `DYGK_IMAGE`，启动新引擎，确认平台识别实际版本。按控制台流程创建新修订，
   检查启动、观察入库、停止，以及未确认积压的处理。
5. 恢复演练在隔离环境进行，使用匹配的镜像、状态快照和平台数据；先阻断生产控制
   socket、平台地址与业务入口，避免恢复副本抢占租约或提交重复观察。确认原始
   观察 ID 不重复、积压可补传、停止有效后，才能记录恢复验收通过。

回退也先停止并确认实例退出。若状态格式没有变化，按引擎文档恢复兼容旧镜像与
历史配置（会创建新修订）；若格式变化，使用匹配快照并协调平台修订，不能仅换回
镜像、清空数据卷或让旧积压转报到新修订。恢复步骤必须先在隔离环境验证。

若需撤销整个引擎接入，先停止登记与管理器，再恢复启用前的 server 配置；已采用
补充文件的节点移除该文件前须保留副本，并检查主 Compose 是否仍有内嵌引擎字段。
server/web 镜像回退按 `release.sh` 说明进行。不要执行 `down -v` 或删除观察审计。

## 验收记录与未完成项

2026-10-29，应用版本 `7f400b4`、DYGK 源版本
`bd8515a0b930f530eec0d13955fe502d8c8e9e25` 在现有环境完成：

- 本地独立镜像构建、真实 Node/PostgreSQL 集成与容器内控制通道测试。
- `.197` 单管理器生产回环测试：版本识别 → 修订 → running → HTTP entry/archive
  访问 → `http_session` 入库 → stopped → 监听关闭。测试登记已撤销。
- 双节点应用镜像一致，页面/API 回归通过；队列短暂波动后恢复，最终积压为 0，
  PostgreSQL 复制延迟为 0。现场记录位于 `.197` 的
  `/opt/openxdr-ha/releases/7f400b4/acceptance.md`。

尚未完成真实业务代理接入、生产 block/quarantine 拦截验收、引擎状态恢复及升级
回退演练、引擎跨节点故障切换和长时间稳定性验收。上面的操作步骤不代表演练已
完成；普通 CI 缺少私有源码时仍可能跳过相关检查。

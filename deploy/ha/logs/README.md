# 业务日志跨发布留存

server/web 使用 `docker-compose.logs.yml`，DYGK 补充配置同样使用 journald。
日志不再与容器文件系统一起删除；节点 journal 使用持久存储，不修改现有系统日志
的大小或保留期策略。集中归档节点通过受限 SSH 拉取两节点日志，SQLite 中按
`(host, journal cursor)` 去重，日志与读取游标同事务提交。

归档默认保存最近 7 天，并限制约 2 GiB 活跃数据库页，先达到哪项就先退役；这是
容量上限而不是保证 7 天完整覆盖。journal 在归档前已丢失、游标失效或源读取失败
时服务报错，不能声称日志完整。磁盘文件可能保留可复用空闲页，归档每次执行增量
回收。日志可能包含业务信息，目录 0700、文件 0600，仅管理员可查。

## 部署

1. 将本目录复制到两节点 `/opt/openxdr-ha/deploy/ha/logs`；使用系统 Python 3。
2. 将 `docker-compose.logs.yml` 放在两节点主 Compose 旁；`release.sh` 会自动合并。
   启动 DYGK 时同时使用其补充配置。首次切换日志驱动需要滚动重建相应容器。
3. 确认 `journalctl --disk-usage` 有持久日志；必要时将 `journald.conf` 安装到
   `/etc/systemd/journald.conf.d/openxdr.conf` 并重启 journal、执行 `journalctl --flush`。
4. 在归档节点生成专用 SSH 密钥，仅用于读取另一节点。私钥只存节点，不输出或提交。
   目标 authorized_keys 必须限制来源 IP，并使用强制命令：

   `from="<归档节点IP>",restrict,command="/usr/bin/python3 /opt/openxdr-ha/deploy/ha/logs/export.py" <公钥>`

   将目标主机公钥指纹与已有可信 SSH 记录核对后写入专用 known_hosts，禁止关闭主机校验。
5. 归档节点 `/etc/openxdr-log-archive.json`（0600）配置本机和远端源。例如：

```json
{"sources":[
  {"name":"node2","command":["/usr/bin/python3","/opt/openxdr-ha/deploy/ha/logs/export.py"]},
  {"name":"node1","command":["ssh","-o","BatchMode=yes","-o","ConnectTimeout=5","-o","IdentitiesOnly=yes","-o","UserKnownHostsFile=/var/lib/openxdr-logs/known_hosts","-i","/var/lib/openxdr-logs/id_ed25519","root@10.1.1.198"]}
]}
```

6. 创建 `/var/lib/openxdr-logs`（0700），安装同目录 service/timer 到
   `/etc/systemd/system/`，`systemctl daemon-reload` 后启用
   `systemctl enable --now openxdr-log-archive.timer`。先手动运行一次 service 检查成功。

## 查询与验收

```bash
python3 /opt/openxdr-ha/deploy/ha/logs/archive.py query --hours 24 --contains '研判' --limit 100
python3 /opt/openxdr-ha/deploy/ha/logs/archive.py query --hours 2 --service openxdr-ha-server-1 --contains 'ERROR'
systemctl status openxdr-log-archive.timer openxdr-log-archive.service
```

查询默认倒序输出 JSONL，保留节点、容器 ID、服务名与原始时间；关键词为字面量。
禁止把包含凭据的原始日志粘到公开工单。验收须确认两节点日志入库、重复采集不重复
写入、容器重建后仍能查到旧容器记录，以及源失联时游标不前进。

## 回退

停止 timer，保留归档数据库和 journal。恢复启用前的 Compose 日志配置，滚动重建
应用即可恢复原日志驱动；不要删除日志目录或修改 PostgreSQL、NATS。移除专用
SSH authorized_keys 行前先停采集任务，不影响其他 SSH 身份。

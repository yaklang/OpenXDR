-- 为一个组建立 Pi query 工具专用的只读视图与登录角色（手工开通）。
-- 平台数据库账号有 CREATEROLE 时 server 会自动开通，不需要这个脚本；
-- 视图定义与 server/internal/queryrole 同一口径，改一边须同步另一边。
-- 组过滤写死在视图定义里，角色只能读本 schema 的视图、读不到任何业务基表
-- （server/internal/agentchat/query.go 会逐项校验，不满足就拒绝查询）。
--
-- 用法（数据库超级用户，在 Patroni leader 上执行，可重复执行）：
--   psql -v ON_ERROR_STOP=1 -v group_id=<组 UUID> -v schema=xdr_<短名> \
--        -v role=xdr_<短名>_ro -v password=<URL-safe 随机串> -f group-views.sql
-- 然后把 postgres://<role>:<password>@127.0.0.1:15432/openxdr?sslmode=disable
-- 写进 PI_QUERY_DATABASE_URLS（JSON：组 UUID → DSN），重启 server。

BEGIN;

CREATE SCHEMA IF NOT EXISTS :"schema";

-- 本组资产
-- 新列只能加在末尾：CREATE OR REPLACE VIEW 不允许改已有列的顺序
CREATE OR REPLACE VIEW :"schema".assets WITH (security_barrier) AS
  SELECT id, hostname, os, ip_addrs, agent_id, first_seen, last_seen,
         agent_version, silent_since, role, criticality, summary, listening, cloud,
         service_notes, egress_notes, zone_id, inventory_at
  FROM public.assets WHERE group_id = :'group_id';

CREATE OR REPLACE VIEW :"schema".findings WITH (security_barrier) AS
  SELECT id, asset_id, key, title, detail, severity, status, first_seen, last_seen, resolved_at, resolved_by, note
  FROM public.findings WHERE group_id = :'group_id';

-- 只含本组主机上的抑制；全局抑制只有平台 admin 看得到
CREATE OR REPLACE VIEW :"schema".suppressions WITH (security_barrier) AS
  SELECT id, created_at, rule_id, asset_id, reason, created_by, expires_at, matched_count, last_matched_at,
         status, conditions, reviewed_by, reviewed_at
  FROM public.suppressions WHERE asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id');

-- 本组登记的可信自动化来源（只读；登记与撤销只能由组管理员在控制台做）
CREATE OR REPLACE VIEW :"schema".trusted_sources WITH (security_barrier) AS
  SELECT id, created_at, name, reason, created_by, expires_at, key_fingerprint, source_cidr, login_user,
         matched_count, last_matched_at, revoked_at, revoked_by
  FROM public.trusted_sources WHERE group_id = :'group_id';

CREATE OR REPLACE VIEW :"schema".memories WITH (security_barrier) AS
  SELECT id, created_at, updated_at, asset_id, content, source, author
  FROM public.memories WHERE group_id = :'group_id';

CREATE OR REPLACE VIEW :"schema".asset_links WITH (security_barrier) AS
  SELECT src_ip, src_asset_id, dst_ip, dst_port, proto, process, count, first_seen, last_seen
  FROM public.asset_links WHERE src_asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id');

-- 只给本组主机连过的地址与本组告警里出现的地址（情报命中、入站对端），别组的不外泄
-- 全平台已纳管主机的地址，只说是不是本组的，不给主机名与组名
CREATE OR REPLACE VIEW :"schema".managed_addresses WITH (security_barrier) AS
  SELECT ip, coalesce(bool_or(a.group_id = :'group_id'), false) AS in_group
  FROM public.assets a CROSS JOIN LATERAL jsonb_array_elements_text(a.ip_addrs) AS ip
  GROUP BY ip;
CREATE OR REPLACE VIEW :"schema".ip_infos WITH (security_barrier) AS
  SELECT ip, ptr, as_owner, asn, country, malicious, suspicious, domains, vt_at,
         ipdb_asn, ipdb_org, ipdb_country, ipdb_at
  FROM public.ip_infos WHERE ip IN (SELECT dst_ip FROM public.asset_links
    WHERE src_asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id'))
  OR ip IN (SELECT substring(rule_id from 10) FROM public.alerts WHERE rule_id LIKE 'intel:ip:%'
    AND asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id'))
  OR ip IN (SELECT unnest(ARRAY[e.raw->'src_endpoint'->>'ip', e.raw->'dst_endpoint'->>'ip'])
    FROM public.alerts a JOIN public.events e ON e.id = a.event_id AND e.asset_id = a.asset_id
    WHERE a.asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id'));

CREATE OR REPLACE VIEW :"schema".reports WITH (security_barrier) AS
  SELECT id, created_at, title, level, markdown, summary
  FROM public.reports WHERE group_id = :'group_id';

-- 原始事件：只含本组资产，查询务必带 ts 时间范围（按 asset_id, ts 建有索引）
CREATE OR REPLACE VIEW :"schema".events WITH (security_barrier) AS
  SELECT id, ts, class_uid, source, asset_id, username, conn_tuple, raw
  FROM public.events
  WHERE asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id');

-- 告警：只含本组资产
CREATE OR REPLACE VIEW :"schema".alerts WITH (security_barrier) AS
  SELECT id, ts, last_ts, count, rule_id, severity, event_id, asset_id, incident_id, command_id, detail,
         automation_id, automation_watch
  FROM public.alerts
  WHERE asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id');

-- 告警连同它的原始事件：在视图里按主键回查，跨视图 JOIN events 会全表扫描、必然超时
CREATE OR REPLACE VIEW :"schema".alert_events WITH (security_barrier) AS
  SELECT a.id AS alert_id, a.ts, a.last_ts, a.count, a.rule_id, a.severity, a.asset_id, a.incident_id, a.command_id,
         e.id AS event_id, e.ts AS event_ts, e.class_uid, e.username, e.conn_tuple, e.raw,
         a.automation_id, a.automation_watch
  FROM public.alerts a JOIN public.events e ON e.id = a.event_id AND e.asset_id = a.asset_id
  WHERE a.asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id');

-- incident：与 REST 接口同一口径，全部告警都落在本组资产上才可见，跨组的不给
CREATE OR REPLACE VIEW :"schema".incidents WITH (security_barrier) AS
  SELECT i.id, i.created_at, i.status, i.title, i.ai_verdict, i.graph, i.triaged_at, i.triage_count,
         CASE WHEN i.status <> 'triaged' THEN NULL
              WHEN i.urgent_at > COALESCE(i.triaged_at, '-infinity') THEN 'urgent'
              WHEN i.evidence_at > COALESCE(i.triaged_at, '-infinity') THEN 'pending' END AS retriage
  FROM public.incidents i
  WHERE EXISTS (SELECT 1 FROM public.alerts a WHERE a.incident_id = i.id)
    AND NOT EXISTS (
      SELECT 1 FROM public.alerts a
      WHERE a.incident_id = i.id
        AND (a.asset_id IS NULL OR a.asset_id NOT IN
             (SELECT id FROM public.assets WHERE group_id = :'group_id')));

-- 处置与命令记录：只含本组资产。旧版视图带已删除的 dry_run 列，CREATE OR REPLACE 删不掉列，先整个删掉重建
DROP VIEW IF EXISTS :"schema".commands;
CREATE VIEW :"schema".commands WITH (security_barrier) AS
  SELECT id, created_at, completed_at, kind, status, asset_id, incident_id,
         issued_by, detail, cmd, exit_code, stdout, stderr, truncated
  FROM public.commands
  WHERE asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id');

-- 身份图：账号与资产都要仍在本组，资产换组后旧组看不到其账号、身份与登录
CREATE OR REPLACE VIEW :"schema".identity_accounts WITH (security_barrier) AS
  SELECT a.id, a.kind, a.asset_id, a.name, a.domain, a.sid, a.uid, a.directory_account_id, a.first_seen, a.last_seen,
         l.identity_id, l.basis AS link_basis, l.confidence AS link_confidence, l.source AS link_source, l.created_at AS linked_at
  FROM public.identity_accounts a LEFT JOIN public.identity_links l ON l.account_id = a.id AND l.revoked_at IS NULL
  WHERE a.group_id = :'group_id'
    AND (a.asset_id IS NULL OR a.asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id'));

CREATE OR REPLACE VIEW :"schema".identities WITH (security_barrier) AS
  SELECT i.id, i.kind, anchor.name, i.anchor_account_id, i.created_at
  FROM public.identities i JOIN public.identity_accounts anchor ON anchor.id = i.anchor_account_id
  WHERE i.group_id = :'group_id'
    AND (anchor.asset_id IS NULL OR anchor.asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id'));

CREATE OR REPLACE VIEW :"schema".identity_links WITH (security_barrier) AS
  SELECT l.id, l.identity_id, l.account_id, l.basis, l.confidence, l.evidence, l.source, l.created_at,
         l.revoked_at, l.revoked_by, l.revoke_reason
  FROM public.identity_links l JOIN public.identity_accounts a ON a.id = l.account_id
  WHERE l.group_id = :'group_id'
    AND (a.asset_id IS NULL OR a.asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id'));

CREATE OR REPLACE VIEW :"schema".identity_linux_logins WITH (security_barrier) AS
  SELECT m.event_id, m.ts, m.asset_id, m.account_name, m.success, m.source_address, m.state,
         m.snapshot_event_id, m.snapshot_ts, m.uid, a.id AS account_id
  FROM public.identity_login_matches m LEFT JOIN public.identity_accounts a ON m.state = 'matched' AND a.group_id = m.group_id
    AND a.account_key = 'linux-local:' || m.group_id || ':' || m.asset_id || ':' || m.uid || ':' || m.account_name
  WHERE m.group_id = :'group_id'
    AND m.asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id');

COMMENT ON SCHEMA :"schema" IS 'OpenXDR 单组只读视图，供 Pi query 工具使用';
COMMENT ON VIEW :"schema".assets IS '本组资产';
COMMENT ON VIEW :"schema".events IS '本组原始事件（OCSF 风格，raw 为 JSON）；查询务必带 ts 范围';
COMMENT ON VIEW :"schema".alerts IS '本组告警（去重后，count 为累计次数）';
COMMENT ON VIEW :"schema".alert_events IS '本组告警连同触发它的原始事件（event_ts、class_uid、raw）；按 incident_id、rule_id、alert_id 过滤';
COMMENT ON VIEW :"schema".incidents IS '本组 incident（全部告警都在本组）；status=triaged 时 retriage 为 pending 表示研判之后又并入了新证据、待冷却到期重研判，urgent 表示升级类证据、立即重研判，ai_verdict 尚未看过这些证据';
COMMENT ON VIEW :"schema".commands IS '本组处置与命令执行记录';
COMMENT ON VIEW :"schema".findings IS '本组运维待办（track 登记的问题，status 为 open / resolved / ignored）';
COMMENT ON VIEW :"schema".suppressions IS '本组主机上的抑制规则（status：active 生效 / proposed 待批 / rejected 已拒绝）';
COMMENT ON VIEW :"schema".trusted_sources IS '本组登记的可信自动化来源（SSH 公钥指纹 / 来源网段 / 登录用户）；alerts.automation_id 指向这里';
COMMENT ON VIEW :"schema".memories IS '本组长期记忆（source：human 人工 / ai）';
COMMENT ON VIEW :"schema".asset_links IS '本组主机发起的连接聚合成的依赖边';
COMMENT ON VIEW :"schema".managed_addresses IS '全平台已纳管主机的地址（含其他组，不含主机名与组名）；in_group=false 即已在其他组纳管，不是未纳管';
COMMENT ON VIEW :"schema".ip_infos IS '本组主机连过的与本组告警里出现的公网地址：反向解析、离线归属库（ipdb_*，DB-IP Lite）与 VirusTotal 结果';
COMMENT ON VIEW :"schema".reports IS '本组历史报告（level：ok / attention / urgent）';
COMMENT ON VIEW :"schema".identity_accounts IS '本组账号登记（directory 目录 / windows 组+资产+SID / linux 组+资产+UID+用户名）及当前所属身份';
COMMENT ON VIEW :"schema".identities IS '本组身份：每个目录账号一个，没有目录锚点的主机账号各自独立';
COMMENT ON VIEW :"schema".identity_links IS '账号到身份的链接与撤销历史（basis：directory_anchor / ad_sid / host_local / manual）';
COMMENT ON VIEW :"schema".identity_linux_logins IS 'Linux 登录与登录时有效本地账号清单的关联（state：matched / no_account / no_snapshot / snapshot_unavailable）';

-- 登录角色：不可登录管理、不可绕过 RLS，只读、5 秒超时、少量连接
SELECT format('CREATE ROLE %I LOGIN', :'role')
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role') \gexec
ALTER ROLE :"role" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 5 PASSWORD :'password';
ALTER ROLE :"role" SET search_path = :"schema";
ALTER ROLE :"role" SET default_transaction_read_only = on;
ALTER ROLE :"role" SET statement_timeout = '5s';

GRANT CONNECT ON DATABASE openxdr TO :"role";
GRANT USAGE ON SCHEMA :"schema" TO :"role";
GRANT SELECT ON ALL TABLES IN SCHEMA :"schema" TO :"role";

COMMIT;

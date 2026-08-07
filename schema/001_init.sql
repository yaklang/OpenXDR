-- OpenXDR 核心 schema
-- 设计原则：三路数据（EDR / NTA / 日志）入库前归一化，实体标识全局统一。
-- 关联引擎按实体 join，不做入库后的字符串匹配。

-- 资产：所有事件挂靠的根实体
CREATE TABLE assets (
    id          UUID PRIMARY KEY,
    hostname    TEXT NOT NULL,
    os          TEXT,
    ip_addrs    INET[],
    agent_id    UUID UNIQUE,          -- 装了 agent 的主机才有
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 归一化事件：OCSF 风格，三路数据统一进这张表
CREATE TABLE events (
    id          UUID PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL,
    class_uid   INT NOT NULL,         -- OCSF class（1007=进程活动, 4001=网络活动, ...）
    source      TEXT NOT NULL,        -- agent | zeek | suricata | syslog
    asset_id    UUID REFERENCES assets(id),
    process_guid UUID,                -- agent 生成的全局进程标识
    username    TEXT,
    conn_tuple  TEXT,                 -- 五元组 "proto:src:sport>dst:dport"
    raw         JSONB NOT NULL        -- 归一化后的完整 OCSF 事件体
);
CREATE INDEX ON events (ts);
CREATE INDEX ON events (asset_id, ts);
CREATE INDEX ON events (process_guid) WHERE process_guid IS NOT NULL;

-- 告警：规则引擎命中产物
CREATE TABLE alerts (
    id          UUID PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL,
    rule_id     TEXT NOT NULL,        -- Sigma 规则 ID
    severity    SMALLINT NOT NULL,    -- 1..5
    event_id    UUID REFERENCES events(id),
    asset_id    UUID REFERENCES assets(id),
    incident_id UUID                  -- 关联引擎回填
);
CREATE INDEX ON alerts (incident_id);

-- 事件（incident）：关联引擎聚合出的攻击故事，AI 研判的对象
CREATE TABLE incidents (
    id          UUID PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    status      TEXT NOT NULL DEFAULT 'open',   -- open | triaged | closed | false_positive
    graph       JSONB NOT NULL,       -- 事件图：节点（进程/连接/文件/告警）+ 边
    ai_verdict  JSONB,                -- LLM 研判：{ confidence, summary, kill_chain, actions }
    title       TEXT
);

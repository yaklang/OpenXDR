package schema

import (
	"encoding/json"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

func newV7() uuid.UUID { return uuid.Must(uuid.NewV7()) }

// Asset 资产：所有事件挂靠的根实体。
type Asset struct {
	ent.Schema
}

func (Asset) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.String("hostname"),
		field.String("os").Optional().Nillable(),
		// 发行版与版本的显示名，如 "Ubuntu 24.04.1 LTS"、"Kylin V10 SP1"、"Windows Server 2022"。
		// 文档导入时来自文档 os 列（声明的值），agent 设备清单（5001 的 device.os）到达后以实测值覆盖；
		// os 字段本身仍只存 linux / windows family，供 Sigma 求值过滤与升级选包使用
		field.String("os_display").Optional().Nillable(),
		field.Strings("ip_addrs").Optional(),
		field.UUID("agent_id", uuid.UUID{}).Optional().Nillable().Unique(),
		field.Time("first_seen").Default(time.Now),
		field.Time("last_seen").Default(time.Now),
		// 最近的采集与投递状态；时间包含服务端接收时刻，不代表全部采集路径健康。
		field.JSON("collector_health", json.RawMessage{}).Optional(),
		// 流量探针：同一台主机可以同时跑 agent 与 sensor，版本、心跳与抓包状态分开记。
		// 探针心跳不刷新 last_seen，否则 agent 挂了会被同机探针的心跳掩盖
		field.String("sensor_version").Optional().Nillable(),
		field.Time("sensor_seen").Optional().Nillable(),
		// 最近的抓包状态，与 collector_health 同一口径（启动标识、序号、组件状态），另带网卡、后端、丢包与速率
		field.JSON("sensor_health", json.RawMessage{}).Optional(),
		// 探针状态通知：已通知过的问题签名（抓包降级、不可用、失联），与 health_problem 分开记，变了才再通知
		field.String("sensor_problem").Optional().Nillable(),
		// 采集配置，随 Register 下发给 agent。为空表示用 agent 内置默认
		field.JSON("config", json.RawMessage{}).Optional(),
		// 所属组。未分组的资产只有全局 admin 可见可管
		field.UUID("group_id", uuid.UUID{}).Optional().Nillable(),
		// agent 自报的版本号，注册时更新
		field.String("agent_version").Optional().Nillable(),
		// 失联起始时刻：已发过失联通知，恢复后清空。避免同一次失联反复通知
		field.Time("silent_since").Optional().Nillable(),
		// 采集健康通知：已通知过的问题签名（降级的采集器、缓存写不进、丢事件），变了才再通知，恢复后清空
		field.String("health_problem").Optional().Nillable(),
		// 上一轮看到的丢弃累计数与最后一次超过阈值的时刻：丢事件是一阵一阵的，超阈值后持续一小时才算恢复
		field.Int64("health_dropped").Optional().Nillable(),
		field.Time("health_dropped_at").Optional().Nillable(),

		// 设备清单：agent 上报的监听端口与云环境（OCSF 5001），由 assetmap 物化。原样是 agent 的 JSON，读时校验
		field.JSON("listening", json.RawMessage{}).Optional(),
		field.JSON("cloud", json.RawMessage{}).Optional(),
		field.Time("inventory_at").Optional().Nillable(),
		// 软件清单：agent 上报的发行版与已装包（OCSF 5020），由 assetmap 物化，漏洞匹配读它
		field.JSON("software", json.RawMessage{}).Optional(),
		field.Time("software_at").Optional().Nillable(),
		// 监听服务说明：键为 协议/端口（如 udp/5405），值含服务名、说明、风险与来源（ai / investigation / human）。
		// 端口表认不出的服务靠它命名；人工写的优先级最高，AI 不覆盖
		field.JSON("service_notes", json.RawMessage{}).Optional(),
		// 公网外联的调查结论：键为公网地址，值与服务说明同构（用途、依据、风险、来源）。
		// AI 上机调查或人工写的，优先于资产标注给的用途
		field.JSON("egress_notes", json.RawMessage{}).Optional(),
		// 组管理员手工指定的区域；为空按网段、云环境、IP 自动划分
		field.UUID("zone_id", uuid.UUID{}).Optional().Nillable(),
		// 组管理员单独指定的处置等级，优先于区域；为空跟随区域
		field.Enum("response_tier").Values("lab", "production", "core").Optional().Nillable(),

		// AI 标注：角色、功能说明、重要程度（1-5）与依据；人改过的字段记进 locked_fields，AI 不再覆盖
		field.String("role").Optional().Nillable(),
		field.Text("summary").Optional().Nillable(),
		field.Int("criticality").Optional().Nillable(),
		field.Text("annotation_reason").Optional().Nillable(),
		// 对端（主机名或 IP）到关系说明，图谱边上展示
		field.JSON("relation_notes", map[string]string{}).Optional(),
		field.Strings("locked_fields").Optional(),
		field.Time("annotated_at").Optional().Nillable(),
		// 标注时的事实指纹：监听端口、内网依赖等变了才重新标注
		field.String("annotated_facts").Optional().Nillable(),
		// 人工点了「重新标注」，下一轮优先处理
		field.Time("annotate_requested_at").Optional().Nillable(),
	}
}

func (Asset) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("events", Event.Type),
		edge.To("alerts", Alert.Type),
		edge.To("commands", Command.Type),
	}
}

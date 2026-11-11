package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Intent 运维意图：动生产前登记的「谁、从哪来、动哪些主机、做哪类事、多长时间」。
// 研判用它解释同一登录身份在登记范围内的行为，不用它放行：高危类别、范围外的主机与时间照常研判。
// 登记凭据与 SSH 钥匙分开（控制台账号或集成 Token），只偷到钥匙的人登记不了。
type Intent struct {
	ent.Schema
}

func (Intent) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		// user:<用户名> 或 integration:<集成 ID>
		field.String("created_by"),
		// 登录身份：公钥指纹与来源地址都要对上
		field.String("key_fingerprint"),
		field.String("source_addr"),
		field.JSON("asset_ids", []uuid.UUID{}),
		// 固定目录里的用途类别，研判只看它
		field.String("category"),
		// 给人看的说明，不进模型
		field.String("note").Default(""),
		field.Time("starts_at"),
		field.Time("expires_at"),
		field.Time("ended_at").Optional().Nillable(),
		field.String("ended_by").Optional().Nillable(),
		// 开始后才补登：研判只作参考，不能单凭它判良性
		field.Bool("late").Default(false),
	}
}

func (Intent) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("key_fingerprint", "expires_at"),
	}
}

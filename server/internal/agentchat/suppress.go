package agentchat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/suppression"
	"openxdr/server/internal/suppress"
)

const suppressDescription = "提议在组内某台主机上抑制一类反复误报的命中，由独立的 AI 审计员当场评审，批准才生效，拒绝会给理由。" +
	"只用于查证过的良性、且会反复出现的命中（比如例行巡检脚本触发的侦察规则）；一次性的误报在结论里说明即可，不要提。" +
	"host 为主机 UUID（只能针对单台主机，不能全局）；rule_id 必须是这台主机上近 30 天确实命中过的规则；" +
	"conditions 必填（1–3 条，AND）：把抑制收窄到良性的那部分，field 为事件体 dot path（如 query.hostname、process.cmd_line、" +
	"dst_endpoint.ip、file.path），op 为 equals / contains / endswith，至少要对得上这条规则在这台主机上真实触发过的一个事件——" +
	"不能整条规则压掉（比如 DNS 服务器上的可疑后缀规则管着全网的查询，只能压具体域名）；" +
	"reason 写清为什么是良性：哪个进程、什么命令、多久一次、属于什么正常业务；days 为有效期（1–90，默认 30），到期自动失效。" +
	"审计员对范围很严：条件要精确、对得上真实命中，高危规则与凭据、清痕迹、关防护类规则几乎不批；被拒后不要换写法重复提同一范围，按理由收窄或在结论里说明。"

var suppressParameters = json.RawMessage(`{"type":"object","properties":{` +
	`"host":{"type":"string"},` +
	`"rule_id":{"type":"string","minLength":1,"maxLength":200},` +
	`"reason":{"type":"string","minLength":10,"maxLength":500},` +
	`"conditions":{"type":"array","minItems":1,"maxItems":3,"items":{"type":"object","properties":{` +
	`"field":{"type":"string"},"op":{"type":"string","enum":["equals","contains","endswith"]},"value":{"type":"string","minLength":1,"maxLength":500}},` +
	`"required":["field","op","value"],"additionalProperties":false}},` +
	`"days":{"type":"integer","minimum":1,"maximum":90}},` +
	`"required":["host","rule_id","reason","conditions"],"additionalProperties":false}`)

// rejectedCooldown 被拒绝的提议多久之内不再接受同一条（主机、规则）
const rejectedCooldown = 30 * 24 * time.Hour

// suppress 写一条待批准的抑制并交 AI 审计员当场评审。批准前不进抑制索引；没配审计员时留给组管理员在抑制页审批
func (s *Service) suppress(ctx context.Context, session *ent.AgentSession, args json.RawMessage) (string, error) {
	var body struct {
		Host       uuid.UUID            `json:"host"`
		RuleID     string               `json:"rule_id"`
		Reason     string               `json:"reason"`
		Days       int                  `json:"days"`
		Conditions []suppress.Condition `json:"conditions"`
	}
	if err := json.Unmarshal(args, &body); err != nil {
		return "", err
	}
	if n := utf8.RuneCountInString(body.Reason); n < 10 || n > 500 {
		return "", errors.New("reason 须为 10–500 字，写清为什么是良性")
	}
	if len(body.Conditions) == 0 {
		return "", errors.New("conditions 必填：把抑制收窄到良性的那部分，不能整条规则压掉")
	}
	if err := suppress.Validate(body.Conditions); err != nil {
		return "", err
	}
	if body.Days == 0 {
		body.Days = 30
	}
	if body.Days < 1 || body.Days > 90 {
		return "", errors.New("days 须为 1–90")
	}
	inGroup, err := s.DB.Asset.Query().Where(asset.IDEQ(body.Host), asset.GroupIDEQ(session.GroupID)).Exist(ctx)
	if err != nil {
		return "", err
	}
	if !inGroup {
		return "", errors.New("主机不在本组")
	}
	// 只能抑制这台主机上真实命中过的规则（平台指令触发的不算，那些本来就不进事件），
	// 条件还要对得上其中至少一次命中的事件：写错字段或编造的值在这里就挡住
	hits, err := s.DB.Alert.Query().Where(alert.AssetIDEQ(body.Host), alert.RuleIDEQ(body.RuleID), alert.CommandIDIsNil(),
		alert.Or(alert.TsGT(time.Now().Add(-30*24*time.Hour)), alert.LastTsGT(time.Now().Add(-30*24*time.Hour)))).
		Order(ent.Desc(alert.FieldTs)).Limit(100).WithEvent().All(ctx)
	if err != nil {
		return "", err
	}
	if len(hits) == 0 {
		return "", errors.New("这台主机近 30 天没有命中过这条规则")
	}
	matched := false
	for _, a := range hits {
		var raw map[string]any
		if a.Edges.Event != nil && json.Unmarshal(a.Edges.Event.Raw, &raw) == nil && suppress.Matches(body.Conditions, raw) {
			matched = true
			break
		}
	}
	if !matched {
		// 把实际值带回去：只说「对不上」，模型只能猜下一个值
		return "", fmt.Errorf("conditions 对不上这条规则在这台主机上的任何一次命中。各字段在近 30 天命中里的实际值：%s", observed(body.Conditions, hits))
	}
	existing, err := s.DB.Suppression.Query().
		Where(suppression.RuleIDEQ(body.RuleID), suppression.Or(suppression.AssetIDEQ(body.Host), suppression.AssetIDIsNil())).
		Order(ent.Desc(suppression.FieldCreatedAt)).All(ctx)
	if err != nil {
		return "", err
	}
	// 同一规则压不同的值是正常的：只有条件相同才算重复；生效的无条件抑制已经覆盖一切
	for _, e := range existing {
		live := e.ExpiresAt == nil || e.ExpiresAt.After(time.Now())
		same := sameConditions(e.Conditions, body.Conditions)
		switch {
		case e.Status == "active" && live && (len(e.Conditions) == 0 || same):
			return marshal(map[string]any{"status": "exists", "note": "已有生效的抑制"})
		case e.Status == "proposed" && same:
			return marshal(map[string]any{"status": "pending", "note": "已有待批准的提议"})
		case e.Status == "rejected" && same && e.ReviewedAt != nil && time.Since(*e.ReviewedAt) < rejectedCooldown:
			return marshal(map[string]any{"status": "rejected", "note": "30 天内拒绝过同样的提议，不要再提，在结论里说明即可"})
		}
	}
	p, err := s.DB.Suppression.Create().SetRuleID(body.RuleID).SetAssetID(body.Host).SetReason(body.Reason).SetConditions(body.Conditions).
		SetCreatedBy("ai:" + session.ID.String()).SetSessionID(session.ID).SetStatus("proposed").
		SetExpiresAt(time.Now().AddDate(0, 0, body.Days)).Save(ctx)
	if err != nil {
		return "", err
	}
	if s.ReviewSuppression == nil {
		return marshal(map[string]any{"status": "proposed", "id": p.ID, "note": "已提交，待批准后生效"})
	}
	status, reason, err := s.ReviewSuppression(ctx, p.ID)
	switch {
	case err != nil:
		// 草案已落库，兜底循环会接着评审
		return marshal(map[string]any{"status": "proposed", "id": p.ID, "note": "已提交，评审稍后进行"})
	case status == "active":
		return marshal(map[string]any{"status": "active", "id": p.ID, "note": "AI 审计员已批准，已生效：" + reason})
	case status == "rejected":
		return marshal(map[string]any{"status": "rejected", "id": p.ID, "note": "AI 审计员没有批准：" + reason + "。不要换写法重复提同一范围；能按理由收窄就重新提，否则在结论里说明"})
	}
	return marshal(map[string]any{"status": status, "id": p.ID, "note": "已提交，待批准后生效"})
}

// sameConditions 两组条件是否相同（不计顺序，值不区分大小写）
func sameConditions(a, b []suppress.Condition) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(c suppress.Condition) string { return c.Field + "\x00" + c.Op + "\x00" + strings.ToLower(c.Value) }
	left := map[string]int{}
	for _, c := range a {
		left[key(c)]++
	}
	for _, c := range b {
		if left[key(c)] == 0 {
			return false
		}
		left[key(c)]--
	}
	return true
}

// observed 各条件字段在命中事件里出现过的值，每个字段最多 5 个，每个值截到 120 字
func observed(conds []suppress.Condition, hits []*ent.Alert) string {
	parts := make([]string, 0, len(conds))
	for _, c := range conds {
		var values []string
		seen := map[string]bool{}
		for _, a := range hits {
			var raw map[string]any
			if a.Edges.Event == nil || json.Unmarshal(a.Edges.Event.Raw, &raw) != nil {
				continue
			}
			v, ok := suppress.Lookup(raw, c.Field)
			if !ok || seen[v] {
				continue
			}
			seen[v] = true
			if r := []rune(v); len(r) > 120 {
				v = string(r[:120]) + "…"
			}
			if values = append(values, strconv.Quote(v)); len(values) == 5 {
				break
			}
		}
		if len(values) == 0 {
			parts = append(parts, c.Field+" 在这些事件里不存在（字段路径写错了？）")
			continue
		}
		parts = append(parts, c.Field+" = "+strings.Join(values, ", "))
	}
	return strings.Join(parts, "；")
}

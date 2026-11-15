package agentchat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/question"
	"openxdr/server/internal/facts"
	"openxdr/server/internal/questions"
)

const askDescription = "向自治总控提问归属、授权、策略或权限类问题（这把钥匙是谁的、这个域名或地址是否在授权范围、这类操作按什么规矩办、有没有权限做）。" +
	"总控先在权威事实、平台指令与运维意图里确定性查找：答得出返回 answered 与依据编号（F-/C-），按依据继续，不要再找人；" +
	"答不了返回 queued 与问题编号（Q-），同一主题的问题会合并，管理员在控制台作答一次后关联待办自动解除阻塞重新排队、关联事件按新事实重审。" +
	"待办要标 blocker=manual_business_decision 前必须先用本工具带 finding_id 提问，queued 之后才允许标。" +
	"subject.kind：key 公钥指纹（SHA256:…）/ ip 地址或网段 / asset 主机 UUID / domain 域名 / change 主机 UUID 上的一项具体变更（须带 change_key，附 at 发生时刻可核对平台指令）。" +
	"change_key 是这项变更的稳定标识（小写字母、数字与 . _ -），如 retire-cyberedge-agent、gateway-systemd-dropin；同一项变更每次用同一个，" +
	"不同变更用不同的：管理员批准的只是这一项，同一主机上的其他变更照常要问。带 finding_id 且没给 change_key 时按待办的 key 生成。" +
	"question 用一句话说明要确认什么、证据在哪，只给管理员看；每轮最多新提 10 个问题。"

var askParameters = json.RawMessage(`{"type":"object","properties":{` +
	`"type":{"type":"string","enum":["owner","authorization","policy","permission"]},` +
	`"subject":{"type":"object","properties":{"kind":{"type":"string","enum":["key","ip","asset","domain","change"]},"value":{"type":"string","minLength":1,"maxLength":300}},"required":["kind","value"],"additionalProperties":false},` +
	`"question":{"type":"string","minLength":1,"maxLength":500},` +
	`"change_key":{"type":"string","pattern":"^[a-z0-9][a-z0-9._-]{0,63}$"},"finding_id":{"type":"string","format":"uuid"},"incident_id":{"type":"string","format":"uuid"},"at":{"type":"string","format":"date-time"}},` +
	`"required":["type","subject","question"],"additionalProperties":false}`)

// maxNewQuestions 一轮会话最多新提的问题数（合并进已有问题的不算）
const maxNewQuestions = 10

// ask 提问总控。组、证据引用与提问人由会话确定：待办与事件必须属于本组（跟进任务只能引用本轮领取的待办），
// 主机必须在本组；模型给的只有类型、对象与一句话说明
func (s *Service) ask(ctx context.Context, session *ent.AgentSession, args json.RawMessage) (string, error) {
	var body struct {
		Type    string `json:"type"`
		Subject struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		} `json:"subject"`
		Question   string     `json:"question"`
		ChangeKey  string     `json:"change_key"`
		FindingID  *uuid.UUID `json:"finding_id"`
		IncidentID *uuid.UUID `json:"incident_id"`
		At         *time.Time `json:"at"`
	}
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		return "", err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return "", errors.New("ask_controller 参数包含额外内容")
	}
	if body.Subject.Kind == "rule" || body.Subject.Kind == "fact" {
		return "", errors.New("subject.kind 只能是 key / ip / asset / domain / change")
	}
	req := questions.Request{Kind: body.Type, SubjectKind: body.Subject.Kind, Subject: body.Subject.Value, At: body.At,
		Groups: []uuid.UUID{session.GroupID}, Session: &session.ID, Source: "ask_controller", Note: body.Question,
		CreatedBy: "session:" + session.ID.String()}
	if body.Subject.Kind == "asset" || body.Subject.Kind == "change" {
		id, err := uuid.Parse(body.Subject.Value)
		if err != nil {
			return "", errors.New("asset / change 的 value 须为本组主机 UUID")
		}
		if err := s.inGroup(ctx, session, id); err != nil {
			return "", err
		}
		req.Assets = append(req.Assets, id)
	}
	if body.ChangeKey != "" && body.Subject.Kind != "change" {
		return "", errors.New("change_key 只用于 subject.kind=change")
	}
	if body.FindingID != nil {
		f, err := s.DB.Finding.Query().Where(finding.IDEQ(*body.FindingID), finding.GroupIDEQ(session.GroupID), finding.StatusEQ("open")).Only(ctx)
		if err != nil {
			return "", errors.New("待办不存在、已结束或不在本组")
		}
		bound, err := s.isFindingFollowup(ctx, session)
		if err != nil {
			return "", err
		}
		if bound && (f.WorkSessionID == nil || *f.WorkSessionID != session.ID || f.WorkLeaseUntil == nil || !f.WorkLeaseUntil.After(time.Now())) {
			return "", errors.New("自主跟进任务只能为本轮有效领取的待办提问")
		}
		req.Finding = &f.ID
		req.Assets = append(req.Assets, f.AssetID)
		if body.Subject.Kind == "change" && body.ChangeKey == "" {
			body.ChangeKey = "finding-" + f.Key
		}
	}
	if body.Subject.Kind == "change" {
		if body.ChangeKey == "" {
			return "", errors.New("change 须带 change_key：管理员批准的是一项具体变更，不是这台主机上的所有变更")
		}
		req.Subject = questions.ChangeSubject(req.Assets[0], body.ChangeKey)
	}
	if body.IncidentID != nil {
		ids, err := s.DB.Alert.Query().Where(alert.IncidentIDEQ(*body.IncidentID), alert.HasAssetWith(asset.GroupIDEQ(session.GroupID))).
			Select(alert.FieldAssetID).All(ctx)
		if err != nil {
			return "", err
		}
		if len(ids) == 0 {
			return "", errors.New("事件不存在或不在本组")
		}
		req.Incident = body.IncidentID
		for _, a := range ids {
			if a.AssetID != nil && !slices.Contains(req.Assets, *a.AssetID) {
				req.Assets = append(req.Assets, *a.AssetID)
			}
		}
	}
	created, err := s.DB.Question.Query().Where(question.CreatedByEQ(req.CreatedBy)).Count(ctx)
	if err != nil {
		return "", err
	}
	if created >= maxNewQuestions {
		// 合并进已有问题仍然允许：只限制新开的
		if subject, err := questions.Normalize(req.Kind, req.SubjectKind, req.Subject); err == nil {
			exists, err := s.DB.Question.Query().Where(question.StatusEQ("open"), question.KindEQ(req.Kind), question.SubjectKindEQ(req.SubjectKind), question.SubjectEQ(subject)).Exist(ctx)
			if err != nil {
				return "", err
			}
			if !exists {
				return "", errors.New("本轮已新提 10 个问题，其余写进报告")
			}
		}
	}
	res, err := questions.Ask(ctx, s.DB, req, time.Now())
	var invalid questions.ErrInvalid
	if errors.As(err, &invalid) {
		return "", invalid
	}
	if err != nil {
		return "", err
	}
	if res.Answered {
		var basis []map[string]any
		for _, f := range res.Facts {
			m := map[string]any{"ref": facts.Ref("F", f.ID), "kind": f.Kind, "content": f.Content}
			if f.Holder != "" {
				m["holder"] = f.Holder
			}
			if f.ExpiresAt != nil {
				m["expires_at"] = f.ExpiresAt
			}
			basis = append(basis, m)
		}
		return marshal(map[string]any{"status": "answered", "facts": basis, "records": res.Records, "context": res.Context,
			"note": "按这些权威依据继续；依据只在写明的范围内成立，不外推到其他对象。不要再为同一问题找人"})
	}
	return marshal(map[string]any{"status": "queued", "question": questions.Ref(res.Question.ID), "merged": res.Merged,
		"asked_count": res.Question.AskedCount, "context": res.Context,
		"note": "已进入总控待答问题；管理员作答后关联待办自动重新排队、关联事件按新事实重审。待办可以标 blocker=manual_business_decision 等待，不要再重复提问"})
}

func (s *Service) inGroup(ctx context.Context, session *ent.AgentSession, id uuid.UUID) error {
	ok, err := s.DB.Asset.Query().Where(asset.IDEQ(id), asset.GroupIDEQ(session.GroupID)).Exist(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("主机不在本组")
	}
	return nil
}

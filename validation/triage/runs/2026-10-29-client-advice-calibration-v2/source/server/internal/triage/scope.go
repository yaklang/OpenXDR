package triage

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/predicate"
)

var errNoInvestigationAssets = errors.New("当前事件缺少可确认的资产归属")

// 从完整事件重新取归属，不使用截断明细、模型参数或跨轮缓存决定调查范围。
func (e *Engine) incidentAssetScope(ctx context.Context, id uuid.UUID) (predicate.Asset, error) {
	if err := e.checkInvestigationScope(ctx); err != nil {
		return nil, err
	}
	if id == uuid.Nil {
		return nil, errors.New("调查工具未绑定事件范围")
	}
	hosts, err := e.DB.Asset.Query().Where(asset.HasAlertsWith(alert.IncidentIDEQ(id))).Select(asset.FieldGroupID).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, errNoInvestigationAssets
	}
	var groups []uuid.UUID
	ungrouped := false
	for _, host := range hosts {
		if host.GroupID == nil {
			ungrouped = true
		} else if !slices.Contains(groups, *host.GroupID) {
			groups = append(groups, *host.GroupID)
		}
	}
	allowed := []predicate.Asset{asset.GroupIDIn(groups...)}
	if ungrouped {
		allowed = append(allowed, asset.GroupIDIsNil())
	}
	return asset.Or(allowed...), nil
}

func (e *Engine) investigationAsset(ctx context.Context, id uuid.UUID) (*ent.Asset, error) {
	scope, err := e.incidentAssetScope(ctx, e.investigationID)
	if err != nil {
		return nil, err
	}
	host, err := e.DB.Asset.Query().Where(asset.IDEQ(id), scope).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, errors.New("资产不存在或不在本事件调查范围内")
	}
	if err != nil {
		return nil, err
	}
	if err := e.rememberInvestigationAssets(ctx, host); err != nil {
		return nil, err
	}
	return host, nil
}

// 记录事件资产及归组；空事件也保留非 nil 快照，后续新增归属必须重研判。
func (e *Engine) investigationMembership(ctx context.Context) ([]string, error) {
	hosts, err := e.DB.Asset.Query().Where(asset.HasAlertsWith(alert.IncidentIDEQ(e.investigationID))).Select(asset.FieldID, asset.FieldGroupID).All(ctx)
	if err != nil {
		return nil, err
	}
	members := make([]string, 0, len(hosts))
	for _, host := range hosts {
		group := "ungrouped"
		if host.GroupID != nil {
			group = host.GroupID.String()
		}
		members = append(members, fmt.Sprintf("%s:%s", host.ID, group))
	}
	slices.Sort(members)
	return members, nil
}

var errInvestigationScopeChanged = errors.New("研判期间事件资产归属发生变化，需要重新研判")

func (e *Engine) checkInvestigationScope(ctx context.Context) error {
	if e.investigationInvalid {
		return errInvestigationScopeChanged
	}
	if e.investigationMembers == nil {
		return nil
	}
	members, err := e.investigationMembership(ctx)
	if err != nil {
		return err
	}
	if !slices.Equal(members, e.investigationMembers) {
		e.investigationInvalid = true
		return errInvestigationScopeChanged
	}
	return e.checkInvestigationReferences(ctx)
}

// 仅在最终落库事务内调用：锁住关联关系和资产，范围检查结果保持到提交。
// 事件独占锁阻止新的告警外键关联；既有告警共享锁阻止移出或改挂资产。
func (e *Engine) lockInvestigationScope(ctx context.Context) error {
	if _, err := e.DB.Incident.Query().Where(incident.IDEQ(e.investigationID), func(s *sql.Selector) { s.ForUpdate() }).Only(ctx); err != nil {
		return err
	}
	alerts, err := e.DB.Alert.Query().Where(alert.IncidentIDEQ(e.investigationID), func(s *sql.Selector) { s.ForShare() }).Order(ent.Asc(alert.FieldID)).All(ctx)
	if err != nil {
		return err
	}
	ids := make([]uuid.UUID, 0, len(alerts)+len(e.investigationReferences))
	for id := range e.investigationReferences {
		ids = append(ids, id)
	}
	for _, a := range alerts {
		if a.AssetID != nil {
			ids = append(ids, *a.AssetID)
		}
	}
	if _, err := e.DB.Asset.Query().Where(asset.IDIn(ids...), func(s *sql.Selector) { s.ForShare() }).Order(ent.Asc(asset.FieldID)).Select(asset.FieldID).All(ctx); err != nil {
		return err
	}
	return e.checkInvestigationScope(ctx)
}

func assetGroupKey(host *ent.Asset) string {
	if host.GroupID == nil {
		return "ungrouped"
	}
	return host.GroupID.String()
}

// 仅记录实际提供给本轮的资产；不能用后来查到的新归属覆盖旧证据归属。
func (e *Engine) rememberInvestigationAssets(ctx context.Context, hosts ...*ent.Asset) error {
	if e.investigationMembers == nil || len(hosts) == 0 {
		return nil
	}
	scope, err := e.incidentAssetScope(ctx, e.investigationID)
	if err != nil {
		return err
	}
	observed := make(map[uuid.UUID]string, len(hosts))
	for _, host := range hosts {
		if host == nil {
			e.investigationInvalid = true
			return errInvestigationScopeChanged
		}
		key := assetGroupKey(host)
		if old, ok := observed[host.ID]; ok && old != key {
			e.investigationInvalid = true
			return errInvestigationScopeChanged
		}
		observed[host.ID] = key
	}
	ids := make([]uuid.UUID, 0, len(observed))
	for id := range observed {
		ids = append(ids, id)
	}
	current, err := e.DB.Asset.Query().Where(asset.IDIn(ids...), scope).Select(asset.FieldID, asset.FieldGroupID).All(ctx)
	if err != nil {
		return err
	}
	if len(current) != len(observed) {
		e.investigationInvalid = true
		return errInvestigationScopeChanged
	}
	if e.investigationReferences == nil {
		e.investigationReferences = make(map[uuid.UUID]string)
	}
	for _, host := range current {
		key := assetGroupKey(host)
		old, exists := e.investigationReferences[host.ID]
		if key != observed[host.ID] || (exists && old != key) {
			e.investigationInvalid = true
			return errInvestigationScopeChanged
		}
		e.investigationReferences[host.ID] = key
	}
	return nil
}

func (e *Engine) checkInvestigationReferences(ctx context.Context) error {
	if len(e.investigationReferences) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, 0, len(e.investigationReferences))
	for id := range e.investigationReferences {
		ids = append(ids, id)
	}
	hosts, err := e.DB.Asset.Query().Where(asset.IDIn(ids...)).Select(asset.FieldID, asset.FieldGroupID).All(ctx)
	if err != nil {
		return err
	}
	if len(hosts) != len(ids) {
		e.investigationInvalid = true
		return errInvestigationScopeChanged
	}
	for _, host := range hosts {
		if assetGroupKey(host) != e.investigationReferences[host.ID] {
			e.investigationInvalid = true
			return errInvestigationScopeChanged
		}
	}
	return nil
}

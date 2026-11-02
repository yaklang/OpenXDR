package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/processbaseline"
	"openxdr/server/internal/ueba"
)

func (e *Engine) toolProcessBaseline(ctx context.Context, args string) (any, error) {
	var in struct {
		AssetID string `json:"asset_id"`
		ExePath string `json:"exe_path"`
	}
	if json.Unmarshal([]byte(args), &in) != nil {
		return nil, fmt.Errorf("基线查询参数无效")
	}
	assetID, err := uuid.Parse(in.AssetID)
	if err != nil {
		return nil, fmt.Errorf("asset_id 不是合法 UUID")
	}
	// Linux、Windows 盘符或 UNC 路径，避免用进程名把未知误报成未命中。
	if !absoluteExecutablePath(in.ExePath) {
		return nil, fmt.Errorf("exe_path 必须是完整程序路径")
	}
	if _, err := e.investigationAsset(ctx, assetID); err != nil {
		return nil, err
	}
	row, err := e.DB.ProcessBaseline.Query().Where(processbaseline.AssetIDEQ(assetID), processbaseline.ExePathIn(ueba.BaselinePaths(in.ExePath)...)).Order(ent.Asc(processbaseline.FieldFirstSeen), ent.Asc(processbaseline.FieldID)).First(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return nil, err
	}
	return baselineEvidence(assetID, in.ExePath, row), nil
}

func absoluteExecutablePath(path string) bool {
	if len(path) > 4096 || strings.ContainsRune(path, 0) {
		return false
	}
	return len(path) > 1 && strings.HasPrefix(path, "/") || len(path) > 2 && strings.HasPrefix(path, `\\`) || len(path) > 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' && (path[2] == '\\' || path[2] == '/')
}

func baselineEvidence(assetID uuid.UUID, path string, row *ent.ProcessBaseline) map[string]any {
	facts := map[string]any{"status": "ok", "asset_id": assetID.String(), "exe_path": path, "baseline_status": "unknown", "baseline_scope": "仅平台 UEBA 对该资产与路径组合的基线首次记录，不是安装时间或实际首次执行时间；学习期、采集缺失与基线重建影响覆盖，未命中不代表程序从未运行。"}
	if row != nil {
		facts["baseline_status"] = "recorded"
		facts["baseline_id"] = row.ID.String()
		facts["baseline_path"] = row.ExePath
		facts["baseline_first_recorded_at"] = row.FirstSeen.UTC().Format(time.RFC3339Nano)
	}
	return facts
}

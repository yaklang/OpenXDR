package assetretire

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
)

func TestRetiredAssetsOnly(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	idA, idB := uuid.New(), uuid.New()
	retiredA := &ent.Asset{ID: idA, Hostname: "gym", RetiredAt: &now}
	activeB := &ent.Asset{ID: idB, Hostname: "prod", RetiredAt: nil}

	if _, ok := retiredAssetsOnly(nil); ok {
		t.Fatal("无告警事件不应判定为可按退役结案")
	}
	if _, ok := retiredAssetsOnly([]*ent.Alert{{ID: uuid.New()}}); ok {
		t.Fatal("含无资产归属告警的事件不应结案")
	}
	if _, ok := retiredAssetsOnly([]*ent.Alert{
		{AssetID: &idA, Edges: ent.AlertEdges{Asset: retiredA}},
		{AssetID: &idB, Edges: ent.AlertEdges{Asset: activeB}},
	}); ok {
		t.Fatal("仍有未退役资产告警的事件不应结案")
	}

	got, ok := retiredAssetsOnly([]*ent.Alert{
		{AssetID: &idA, Edges: ent.AlertEdges{Asset: retiredA}},
		{AssetID: &idA, Edges: ent.AlertEdges{Asset: retiredA}},
	})
	if !ok || len(got) != 1 || got[0].ID != idA {
		t.Fatalf("应去重返回唯一退役资产：%v %+v", ok, got)
	}
}

func TestFormatResolution(t *testing.T) {
	t1 := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 14, 11, 30, 0, 0, time.UTC)
	by1, why1 := "admin", "靶机实验结束销毁"
	by2, why2 := "ops", "临时测试机下线"

	single := FormatResolution([]*ent.Asset{{
		ID: uuid.New(), Hostname: "gym", RetiredAt: &t1, RetiredBy: &by1, RetiredReason: &why1,
	}})
	wantPrefix := "资产已于 2026-11-14T10:00:00Z 由 admin 退役（原因：靶机实验结束销毁），主机不复存在"
	if !strings.HasPrefix(single, wantPrefix) || !strings.Contains(single, "gym") {
		t.Fatalf("单资产结案说明不符合预期：%q", single)
	}

	multi := FormatResolution([]*ent.Asset{
		{ID: uuid.New(), Hostname: "gym", RetiredAt: &t1, RetiredBy: &by1, RetiredReason: &why1},
		{ID: uuid.New(), Hostname: "openxdr-test-linux", RetiredAt: &t2, RetiredBy: &by2, RetiredReason: &why2},
	})
	if !strings.HasPrefix(multi, wantPrefix) || !strings.Contains(multi, "openxdr-test-linux") || !strings.Contains(multi, "临时测试机下线") {
		t.Fatalf("多资产结案说明不符合预期：%q", multi)
	}
}

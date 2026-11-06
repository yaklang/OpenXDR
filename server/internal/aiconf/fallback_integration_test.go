//go:build integration

package aiconf

import (
	"openxdr/server/internal/testdb"
	"testing"
)

func TestFallbackPersistence(t *testing.T) {
	ctx, db := testdb.New(t)
	s := &Store{DB: db, Default: env}
	value := "backup-a,backup-b"
	if err := s.Save(ctx, Patch{FallbackModels: &value}); err != nil {
		t.Fatal(err)
	}
	other := &Store{DB: db, Default: env}
	if got := other.Get(ctx); got.FallbackModels != value {
		t.Fatal("节点读取不一致")
	}
	v, err := s.View(ctx)
	if err != nil || v.FallbackModels != value || v.Source["fallbackModels"] != "console" {
		t.Fatalf("%+v %v", v, err)
	}
	if err := s.Save(ctx, Patch{Reset: []string{"fallbackModels"}}); err != nil {
		t.Fatal(err)
	}
	if s.Get(ctx).FallbackModels != "" {
		t.Fatal("重置应关闭")
	}
}

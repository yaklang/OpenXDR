package selfwatch

import (
	"reflect"
	"testing"
)

func TestDiffAndDanger(t *testing.T) {
	got := diff([]byte(`{"ttl":60,"a":{"b":1,"c":[1,2]}}`), []byte(`{"ttl":60,"a":{"b":2,"c":[1,2],"d":true}}`))
	if want := []string{"a.b", "a.d"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("diff = %v，期望 %v", got, want)
	}
	for path, want := range map[string]bool{
		"postgresql.pg_hba": true, "postgresql.parameters.archive_command": true,
		"postgresql.parameters.shared_preload_libraries": true, "postgresql.parameters.ssl": true,
		"ttl": false, "postgresql.parameters.shared_buffers": false,
	} {
		if dangerous(path) != want {
			t.Errorf("dangerous(%q) 应为 %v", path, want)
		}
	}
}

package assetmap

import (
	"encoding/json"
	"testing"
)

func TestRPMSoftwareInventory(t *testing.T) {
	for _, tc := range []struct {
		manager, row string
		valid        bool
	}{
		{"rpm", `["openssl","1:1.1.1k-9.uel20","openssl","1.1.1k-9.uel20"]`, true},
		{"rpm", `["local","0:1-1","",""]`, true},
		{"rpm", `["local","0:1-1","local",""]`, false},
		{"dpkg", `["local","1-1","",""]`, false},
		{"apk", `["local","1-1","local","1-1"]`, false},
		{"rpm", `["","0:1-1","",""]`, false},
	} {
		raw := json.RawMessage(`{"os":{"id":"uos","version_id":"20"},"manager":"` + tc.manager + `","packages":[` + tc.row + `]}`)
		sw, ok := software(raw)
		if ok != tc.valid {
			t.Fatalf("%s %s valid=%v", tc.manager, tc.row, ok)
		}
		if ok && (sw.Manager != tc.manager || sw.OS != "uos" || len(sw.Packages) != 1) {
			t.Fatalf("清单字段丢失: %+v", sw)
		}
	}
}

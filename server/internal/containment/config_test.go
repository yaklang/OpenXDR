package containment

import "testing"

func TestStoreValidate(t *testing.T) {
	for _, tc := range []struct {
		on, scope string
		ok        bool
	}{
		{"", "", true},
		{"true", "all", true},
		{"false", "lab", true},
		{"yes", "", false},
		{"", "prod", false},
	} {
		err := (&Store{EnvOn: tc.on, EnvScope: tc.scope}).Validate()
		if (err == nil) != tc.ok {
			t.Errorf("on=%q scope=%q: err=%v", tc.on, tc.scope, err)
		}
	}
}

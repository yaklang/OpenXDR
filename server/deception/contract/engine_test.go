package contract

import "testing"

func TestConfigRejectsUnknownAndInvalidPolicy(t *testing.T) {
	for _, raw := range []string{`{"mode":"shell"}`, `{"upstream":"http://internal"}`, `{"attachment":"gateway","upstream":"file:///secret"}`, `{"requestLimit":0}`, `{"prefix":"/../"}`, `{"trustedProxies":["0.0.0.0/0"]}`, `{"shell":"id"}`} {
		if _, err := DecodeConfig([]byte(raw)); err == nil {
			t.Fatalf("未拒绝 %s", raw)
		}
	}
	if _, err := DecodeConfig([]byte(`{"mode":"quarantine","attachment":"gateway","upstream":"http://business:8080"}`)); err != nil {
		t.Fatal(err)
	}
}

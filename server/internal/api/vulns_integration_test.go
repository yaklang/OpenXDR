//go:build integration

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/internal/auth"
	"openxdr/server/internal/testdb"
)

// 同一个源码包既有可修复也有暂无修复的漏洞时，汇总里的暴露包只算一条
func TestVulnSummaryMergesSource(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	admin := client.User.Create().SetUsername("admin").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	client.Asset.Create().SetHostname("pve").
		SetSoftware(json.RawMessage(`{"os":"debian","version":"13","manager":"dpkg","packages":[["perl-base","5.40.1-6","perl","5.40.1-6"]]}`)).
		SetListening(json.RawMessage(`[{"proto":"tcp","addr":"0.0.0.0","port":8006,"process":"pveproxy","package":"perl-base"}]`)).ExecX(ctx)
	rpm := client.Asset.Create().SetHostname("uos").
		SetSoftware(json.RawMessage(`{"os":"uos","version":"20","manager":"rpm","packages":[["openssl","1:1.1.1k-9","openssl","1.1.1k-9"]]}`)).SaveX(ctx)
	rep, err := vulnReportOf(httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx), db, client, rpm)
	if err != nil || rep == nil || rep.Ecosystem != "" || rep.Packages != 1 {
		t.Fatalf("RPM 清单应保留未知覆盖状态: %+v %v", rep, err)
	}
	for _, fixed := range []string{`[{"introduced":"0","fixed":"5.40.1-6+deb13u1"}]`, `[{"introduced":"0"}]`} {
		if _, err := db.Exec(`INSERT INTO vuln_records (osv_id, ecosystem, package, ranges, aliases, summary, score, vector, synced_at)
VALUES ($1,'Debian:13','perl',$2::jsonb,'[]','x',9.8,'',now())`, "DEBIAN-CVE-"+fixed[:20], fixed); err != nil {
			t.Fatal(err)
		}
	}
	h := Vulns(client, db)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), admin)))
	}))
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + "/api/vulns/summary")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out []struct {
		Fixable, Unfixed, Exposed int
		ExposedPackages           []exposedPackage
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Fixable != 1 || out[0].Unfixed != 1 || out[0].Exposed != 1 ||
		len(out[0].ExposedPackages) != 1 || out[0].ExposedPackages[0].Vulns != 2 || out[0].ExposedPackages[0].FixedIn != "5.40.1-6+deb13u1" {
		t.Fatalf("同一源码包应合并成一条暴露记录: %+v", out)
	}
}

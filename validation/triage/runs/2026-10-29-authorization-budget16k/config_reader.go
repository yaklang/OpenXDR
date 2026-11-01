package main

import (
	"context"
	"database/sql"
	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"net/url"
	"openxdr/server/ent"
	"openxdr/server/internal/aiconf"
	"openxdr/server/internal/hostimport"
	"os"
	"os/exec"
)

func main() {
	u, err := url.Parse(os.Getenv("DATABASE_URL"))
	if err != nil {
		panic("invalid configuration")
	}
	q := u.Query()
	q.Set("default_transaction_read_only", "on")
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		panic("config database unavailable")
	}
	defer db.Close()
	client := ent.NewClient(ent.Driver(entsql.OpenDB("postgres", db)))
	vault, err := hostimport.NewVault(os.Getenv("HOST_CREDENTIAL_KEY"))
	if err != nil {
		panic("vault unavailable")
	}
	c := (&aiconf.Store{DB: client, Vault: vault, Default: aiconf.Config{BaseURL: os.Getenv("AI_BASE_URL"), Model: os.Getenv("AI_MODEL"), APIKey: os.Getenv("AI_API_KEY")}}).Get(context.Background())
	cmd := exec.Command("/tmp/openxdr-auth-budget16k-probe", "-live", "-cases", "/tmp/openxdr-auth-budget16k-cases.json", "-out", "/tmp/openxdr-auth-budget16k-report.jsonl", "-repeats", "2", "-judge-max-tokens", "16384", "-revision", "9b9017899e080bab7418cff9209bf425eef04811-dirty-authorization-budget16k")
	cmd.Env = append(os.Environ(), "AI_BASE_URL="+c.BaseURL, "AI_MODEL="+c.Model, "AI_API_KEY="+c.APIKey)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if cmd.Run() != nil {
		os.Exit(1)
	}
}

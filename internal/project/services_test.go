package project

import (
	"strings"
	"testing"
)

const base = "name: svc\n"

func TestServicesListForm(t *testing.T) {
	c, err := Parse([]byte(base + "services: [postgres]\n"))
	if err != nil {
		t.Fatal(err)
	}
	pg := c.Services.Postgres
	if pg == nil {
		t.Fatal("postgres should be enabled")
	}
	if pg.Port != 5432 || pg.User != "dev" || pg.Password != "dev" || pg.Database != "dev" {
		t.Errorf("defaults: %+v", pg)
	}
	if got := pg.URL(); got != "postgres://dev:dev@127.0.0.1:5432/dev" {
		t.Errorf("URL = %q", got)
	}
}

func TestServicesMapForm(t *testing.T) {
	c, err := Parse([]byte(base + "services:\n  postgres:\n    port: 5433\n    user: vaults\n    password: password\n    database: vaults\n"))
	if err != nil {
		t.Fatal(err)
	}
	if pg := c.Services.Postgres; pg == nil || pg.Port != 5433 || pg.User != "vaults" || pg.Database != "vaults" {
		t.Errorf("got %+v", c.Services.Postgres)
	}
	c, err = Parse([]byte(base + "services:\n  postgres:\n"))
	if err != nil || c.Services.Postgres == nil || c.Services.Postgres.Port != 5432 {
		t.Errorf("an empty postgres entry takes the defaults: %v %+v", err, c)
	}
}

func TestServicesOffByDefault(t *testing.T) {
	c, err := Parse([]byte(base))
	if err != nil || c.Services.Postgres != nil {
		t.Errorf("no services unless asked: %v %+v", err, c.Services)
	}
}

func TestServicesValidation(t *testing.T) {
	for name, yml := range map[string]string{
		"unknown service":    "services: [mysql]\n",
		"unknown key":        "services:\n  postgres:\n    host: 0.0.0.0\n",
		"privileged port":    "services:\n  postgres:\n    port: 80\n",
		"port too high":      "services:\n  postgres:\n    port: 70000\n",
		"ssh port":           "services:\n  postgres:\n    port: 22\n",
		"user with a quote":  "services:\n  postgres:\n    user: \"a'b\"\n",
		"user uppercase":     "services:\n  postgres:\n    user: Admin\n",
		"database with dash": "services:\n  postgres:\n    database: my-db\n",
		"password quote":     "services:\n  postgres:\n    password: \"p'w\"\n",
		"password space":     "services:\n  postgres:\n    password: \"p w\"\n",
		"password dollar":    "services:\n  postgres:\n    password: \"$(id)\"\n",
		"password at":        "services:\n  postgres:\n    password: \"a@b\"\n",
		"duplicate":          "services: [postgres, postgres]\n",
		"proxy port":         "services:\n  postgres:\n    port: 3128\n",
		"pg_ role":           "services:\n  postgres:\n    user: pg_app\n",
		"public role":        "services:\n  postgres:\n    user: public\n",
		"none role":          "services:\n  postgres:\n    user: none\n",
		"current_user role":  "services:\n  postgres:\n    user: current_user\n",
		"postgres database":  "services:\n  postgres:\n    database: postgres\n",
		"template database":  "services:\n  postgres:\n    database: template1\n",
	} {
		if _, err := Parse([]byte(base + yml)); err == nil {
			t.Errorf("%s: should be refused", name)
		} else if !strings.Contains(err.Error(), "services") {
			t.Errorf("%s: error should name services: %v", name, err)
		}
	}
}

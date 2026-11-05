package app

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/project"
)

func pgConfig() *project.Config {
	c := project.Default()
	c.Name = "svc"
	c.Services.Postgres = &project.Postgres{Port: 5433, User: "vaults", Password: "password", Database: "vaults"}
	return c
}

func TestPostgresScript(t *testing.T) {
	s := servicesScript(pgConfig())
	for _, want := range []string{
		// A cluster the sandbox user owns, in its home.
		`DATA="$HOME/.local/share/devkit/postgres"`,
		`"$PG/initdb" -D "$DATA" -U "$(id -un)" --auth-local=peer --auth-host=scram-sha-256`,
		// Started by the user's systemd, which lingering starts at boot.
		"systemctl --user enable -q devkit-postgres.service",
		// Only the VM's own loopback, the socket in the user's runtime dir.
		"-p $PORT -k %t -c listen_addresses=127.0.0.1",
		"PORT=5433",
		`CREATE ROLE "vaults" LOGIN PASSWORD 'password'`,
		`-O vaults vaults`,
		"postgres://vaults:password@127.0.0.1:5433/vaults",
		// An existing database follows a changed user: it and everything
		// in it end up owned by the configured role.
		`ALTER DATABASE "vaults" OWNER TO "vaults"`,
		`REASSIGN OWNED BY "$old" TO "vaults"`,
		// REASSIGN also moves shared objects; refuse when the old role owns
		// any outside this database rather than re-own them silently.
		"FROM pg_database WHERE datdba = (SELECT oid FROM pg_roles WHERE rolname = '$old') AND datname <> 'vaults'",
		"FROM pg_tablespace WHERE spcowner = (SELECT oid FROM pg_roles WHERE rolname = '$old')",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script missing %q", want)
		}
	}
	if strings.Contains(s, "0.0.0.0") || strings.Contains(s, "listen_addresses='*'") {
		t.Error("postgres must not listen beyond loopback")
	}
	path := filepath.Join(t.TempDir(), "svc.sh")
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
		t.Errorf("does not parse: %s", out)
	}
	if sc, err := exec.LookPath("shellcheck"); err == nil {
		if out, err := exec.Command(sc, "--severity=warning", "--shell=bash", path).CombinedOutput(); err != nil {
			t.Errorf("shellcheck:\n%s", out)
		}
	}
}

func TestNoServicesStopsALeftoverOne(t *testing.T) {
	c := project.Default()
	s := servicesScript(c)
	if !strings.Contains(s, "disable --now devkit-postgres.service") || strings.Contains(s, "initdb") {
		t.Errorf("without services, a unit left from before is stopped and nothing is set up:\n%s", s)
	}
	if !strings.Contains(s, "keeps its data") {
		t.Error("the data stays; say so")
	}
}

func TestUpStartsServices(t *testing.T) {
	f, _ := fakeHome(t)
	if err := startServices(context.Background(), pgConfig()); err != nil {
		t.Fatal(err)
	}
	if !mentions(f.Calls(), "devkit-postgres.service") {
		t.Error("the services script should run in the VM")
	}
}

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPostgresService brings up services: postgres in a real VM and checks
// what the README promises about it.
func TestPostgresService(t *testing.T) {
	if os.Getenv("DEVKIT_E2E") == "" {
		t.Skip("set DEVKIT_E2E=1 to run (creates a real VM)")
	}
	if _, err := exec.LookPath("limactl"); err != nil {
		t.Skip("limactl not installed")
	}
	devkit := buildDevkitBinary(t)
	dir := t.TempDir()
	name := fmt.Sprintf("e2e-pg-%d", time.Now().Unix()%100000)
	s := &sandbox{t: t, devkit: devkit, dir: dir, name: name}
	writeFile(t, filepath.Join(dir, "README.md"), "postgres e2e\n")
	s.mustRun("init", "--name", name, "--toolchain", "none")
	t.Cleanup(func() { _, _ = s.run("rm", "--force") })
	cfgPath := filepath.Join(dir, "devkit.yaml")
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	withPG := string(cfg) + "\nservices:\n  postgres:\n    port: 5433\n    user: vaults\n    password: password\n    database: vaults\n"
	writeFile(t, cfgPath, withPG)
	out := s.mustRun("up")
	if !strings.Contains(out, "postgres://vaults:password@127.0.0.1:5433/vaults") {
		t.Errorf("up should print the connection URL:\n%s", out)
	}

	pg := "/usr/lib/postgresql/16/bin"
	query := func(sql string) (string, error) {
		return s.shell(fmt.Sprintf("PGPASSWORD=password %s/psql -h 127.0.0.1 -p 5433 -U vaults -d vaults -tAc %q", pg, sql))
	}

	t.Run("the app's role logs in over TCP", func(t *testing.T) {
		got, err := query("SELECT current_user || ' ' || current_database()")
		if err != nil || !strings.Contains(got, "vaults vaults") {
			t.Fatalf("got %q, %v", got, err)
		}
		if got, _ := s.shell(fmt.Sprintf("PGPASSWORD=wrong %s/psql -h 127.0.0.1 -p 5433 -U vaults -d vaults -tAc 'SELECT 1' 2>&1", pg)); !strings.Contains(got, "authentication failed") {
			t.Errorf("a wrong password must be refused: %q", got)
		}
	})

	t.Run("runs as the sandbox user, on loopback only", func(t *testing.T) {
		owner, _ := s.shell("ps -o user= -C postgres | sort -u")
		me, _ := s.shell("id -un")
		if strings.TrimSpace(owner) != strings.TrimSpace(me) {
			t.Errorf("postgres runs as %q, want the sandbox user %q", owner, me)
		}
		listen, _ := s.shell("ss -Hltn 'sport = :5433' | awk '{print $4}' | sort -u")
		if strings.TrimSpace(listen) != "127.0.0.1:5433" {
			t.Errorf("listening on %q, want only 127.0.0.1:5433", listen)
		}
	})

	t.Run("no system cluster", func(t *testing.T) {
		if got, _ := s.shell("ls /etc/postgresql 2>/dev/null | wc -l; systemctl is-active postgresql@16-main 2>/dev/null || true"); strings.Contains(got, "active") && !strings.Contains(got, "inactive") {
			t.Errorf("Ubuntu's own cluster is running: %q", got)
		}
		if got, _ := s.shell("test -d /var/lib/postgresql/16/main && echo exists || echo none"); !strings.Contains(got, "none") {
			t.Error("Ubuntu's packaging created a system cluster")
		}
	})

	t.Run("starts at boot without devkit up", func(t *testing.T) {
		if _, err := query("CREATE TABLE IF NOT EXISTS survives (v int); INSERT INTO survives VALUES (42)"); err != nil {
			t.Fatal(err)
		}
		s.mustRun("down")
		lima := exec.Command("limactl", "start", "--tty=false", "devkit-"+name)
		if b, err := lima.CombinedOutput(); err != nil {
			t.Fatalf("limactl start: %v\n%s", err, b)
		}
		var got string
		for i := 0; i < 30; i++ {
			if got, err = query("SELECT v FROM survives"); err == nil && strings.Contains(got, "42") {
				break
			}
			time.Sleep(2 * time.Second)
		}
		if !strings.Contains(got, "42") {
			t.Errorf("after a reboot, with only Lima starting the VM: %q %v", got, err)
		}
	})

	t.Run("a changed user takes over the database and its tables", func(t *testing.T) {
		writeFile(t, cfgPath, strings.Replace(withPG, "user: vaults", "user: vaults2", 1))
		s.mustRun("up", "--no-install")
		got, err := s.shell(fmt.Sprintf("PGPASSWORD=password %s/psql -h 127.0.0.1 -p 5433 -U vaults2 -d vaults -tAc %q", pg,
			"SELECT tableowner FROM pg_tables WHERE tablename = 'survives'"))
		if err != nil || strings.TrimSpace(got) != "vaults2" {
			t.Errorf("the table should belong to the new user: %q %v", got, err)
		}
	})

	t.Run("a user change never re-owns another database", func(t *testing.T) {
		if _, err := s.shell(fmt.Sprintf("%s/psql -h $XDG_RUNTIME_DIR -p 5433 -d postgres -c 'CREATE DATABASE other OWNER vaults2'", pg)); err != nil {
			t.Fatal(err)
		}
		writeFile(t, cfgPath, strings.Replace(withPG, "user: vaults", "user: vaults3", 1))
		if out, err := s.run("up", "--no-install"); err == nil || !strings.Contains(out, "also owns") {
			t.Errorf("up should refuse and say why:\n%s", out)
		}
		got, _ := s.shell(fmt.Sprintf("%s/psql -h $XDG_RUNTIME_DIR -p 5433 -d postgres -tAc \"SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = 'other'\"", pg))
		if strings.TrimSpace(got) != "vaults2" {
			t.Errorf("the other database's owner changed: %q", got)
		}
		got, _ = s.shell(fmt.Sprintf("%s/psql -h $XDG_RUNTIME_DIR -p 5433 -d postgres -tAc \"SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = 'vaults'\"", pg))
		if strings.TrimSpace(got) != "vaults2" {
			t.Errorf("a refused change must leave the configured database alone too: %q", got)
		}
	})

	t.Run("removing the service stops it and keeps the data", func(t *testing.T) {
		writeFile(t, cfgPath, string(cfg))
		s.mustRun("up", "--no-install")
		if got, _ := s.shell(pg + "/pg_isready -h 127.0.0.1 -p 5433; echo rc=$?"); !strings.Contains(got, "rc=2") {
			t.Errorf("postgres should be stopped: %q", got)
		}
		if got, _ := s.shell("test -s ~/.local/share/devkit/postgres/PG_VERSION && echo kept"); !strings.Contains(got, "kept") {
			t.Error("the data directory should stay")
		}
	})
}

package provision

import (
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/project"
)

func TestPostgresPackageWithoutASystemCluster(t *testing.T) {
	s, err := System(params(func(c *project.Config) {
		c.Services.Postgres = &project.Postgres{Port: 5433, User: "u", Password: "p", Database: "d"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	pkgs := strings.Index(s, `WANT_PKGS="`)
	if pkgs < 0 || !strings.Contains(s[pkgs:pkgs+200], project.PostgresPackage) {
		t.Fatalf("postgres should be among the packages root installs")
	}
	// Ubuntu's packaging would otherwise create and start a cluster of its
	// own, as the postgres account, before devkit's user-owned one exists.
	noCluster := strings.Index(s, "create_main_cluster = false")
	install := strings.Index(s, "$APT install -y --no-install-recommends $WANT_PKGS")
	if noCluster < 0 || install < 0 || noCluster > install {
		t.Error("the system cluster must be switched off before the package is installed")
	}
	if !strings.Contains(s, "systemctl disable --now postgresql") {
		t.Error("a system cluster from an earlier install should be stopped")
	}
}

func TestNoServicesLeavesTheScriptAsItWas(t *testing.T) {
	s, err := System(params(nil))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(s), "postgres") {
		t.Error("without services nothing about them may appear, or every existing VM would read as stale")
	}
}

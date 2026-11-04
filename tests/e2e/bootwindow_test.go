package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestBootWindowIsClosed plants code where the sandbox user can write it and
// where it runs on its own at the next boot: ~/.ssh/rc (sshd runs it on every
// session), and ~/.bashrc and ~/.profile (bash reads them for sshd-run and
// login shells). Lima's host agent opens SSH sessions as the sandbox user
// while the guest boots, before provisioning has applied the firewall, so
// each hook tries a direct connection that bypasses the proxy. None may
// succeed: from the first instant of a reboot the sandbox user must have no
// egress except what the firewall later allows through the proxy.
func TestBootWindowIsClosed(t *testing.T) {
	if os.Getenv("DEVKIT_E2E") == "" {
		t.Skip("set DEVKIT_E2E=1 to run (creates a real VM)")
	}
	if _, err := exec.LookPath("limactl"); err != nil {
		t.Skip("limactl not installed")
	}
	devkit := buildDevkitBinary(t)
	dir := t.TempDir()
	name := fmt.Sprintf("e2eboot-%d", time.Now().Unix()%100000)
	s := &sandbox{t: t, devkit: devkit, dir: dir, name: name}
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"e2e","version":"1.0.0"}`)
	s.mustRun("init", "--name", name)
	t.Cleanup(func() { _, _ = s.run("rm", "--force") })
	s.mustRun("up", "--no-install")

	attempt := func(tag string) string {
		// Background, so the hook never delays the session that runs it; one
		// printf per attempt, so concurrent hooks never interleave a line.
		return fmt.Sprintf(`( c=$(curl -s -m 3 --noproxy '*' -o /dev/null -w '%%{http_code}' http://example.com/); printf '%%s %s %%s %%s\n' "$(date +%%s)" "$c" "$(printf %%s "${BASH_EXECUTION_STRING:-}" | tr -s ' \n' '  ' | cut -c1-40)" >>"$HOME/boot-escape.log" ) </dev/null >/dev/null 2>&1 &`, tag)
	}
	plant := "mkdir -p ~/.ssh && printf '%s\\n' " + shq(attempt("rc")) + " > ~/.ssh/rc" +
		" && { printf '%s\\n' " + shq(attempt("bashrc")) + "; cat ~/.bashrc; } > ~/.bashrc.new && mv ~/.bashrc.new ~/.bashrc" +
		" && { printf '%s\\n' " + shq(attempt("profile")) + "; cat ~/.profile 2>/dev/null; } > ~/.profile.new && mv ~/.profile.new ~/.profile" +
		" && : > ~/boot-escape.log && echo planted"
	if out := s.mustRun("shell", plant); !strings.Contains(out, "planted") {
		t.Fatalf("could not plant the hooks: %s", out)
	}

	s.mustRun("down")
	s.mustRun("up", "--no-sync", "--no-install")

	logOut, _ := s.shell("cat ~/boot-escape.log; echo ---; cat /run/devkit/firewall-at 2>/dev/null; echo; date -u -d \"$(uptime -s)\" +%s")
	parts := strings.SplitN(logOut, "---", 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected output: %s", logOut)
	}
	tail := strings.Fields(parts[1])
	var fwAt, bootAt int64
	if len(tail) >= 1 {
		bootAt, _ = strconv.ParseInt(tail[len(tail)-1], 10, 64)
	}
	if len(tail) >= 2 {
		fwAt, _ = strconv.ParseInt(tail[0], 10, 64)
	}
	line := regexp.MustCompile(`^(\d+) (\w+) (\d{3}) ?(.*)$`)
	var thisBoot, beforeFirewall int
	for _, l := range strings.Split(parts[0], "\n") {
		m := line.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		ts, _ := strconv.ParseInt(m[1], 10, 64)
		if ts < bootAt {
			continue
		}
		thisBoot++
		if fwAt > 0 && ts < fwAt {
			beforeFirewall++
		}
		if m[3] != "000" {
			t.Errorf("a %s hook reached the internet directly during boot (HTTP %s, at +%ds, firewall at +%ds, running %q)", m[2], m[3], ts-bootAt, fwAt-bootAt, m[4])
		}
	}
	t.Logf("%d hook attempts this boot, %d before the firewall was applied", thisBoot, beforeFirewall)
	if beforeFirewall == 0 {
		t.Fatalf("no hook ran before the firewall was applied, so the test proves nothing:\n%s", logOut)
	}
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

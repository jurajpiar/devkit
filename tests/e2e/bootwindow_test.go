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

	// Each hook tries four routes out, each recorded as one atomic line
	// "<ts> <hook> <route> <result>", result "ok" when the route worked:
	//   direct    a TCP connection that bypasses the proxy
	//   dns       a lookup through the libc resolver (the stub, or upstream)
	//   resolved  a lookup asked of systemd-resolved over D-Bus, which then
	//             queries upstream as its own user
	//   proxy     a request relayed by the egress proxy on loopback
	// Background, so the hook never delays the session that runs it.
	attempt := func(tag string) string {
		one := func(route, cmd string) string {
			return fmt.Sprintf(`( if %s >/dev/null 2>&1; then r=ok; else r=no; fi; printf '%%s %s %s %%s\n' "$(date +%%s)" "$r" >>"$HOME/boot-escape.log" ) </dev/null >/dev/null 2>&1 &`, cmd, tag, route)
		}
		return strings.Join([]string{
			one("direct", `curl -sf -m 3 --noproxy '*' -o /dev/null http://example.com/`),
			one("dns", `timeout 4 getent hosts example.org`),
			one("resolved", `timeout 6 resolvectl query --legend=no example.net`),
			one("proxy", `curl -sf -m 4 -x http://127.0.0.1:3128 --noproxy '' -o /dev/null https://registry.npmjs.org/`),
		}, " ")
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
	line := regexp.MustCompile(`^(\d+) (\w+) (\w+) (ok|no)$`)
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
		pre := fwAt > 0 && ts < fwAt
		if pre {
			beforeFirewall++
		}
		hook, route, ok := m[2], m[3], m[4] == "ok"
		switch {
		case ok && pre:
			// Before the firewall nothing may leave for the sandbox, by any route.
			t.Errorf("a %s hook got out by %s before the firewall (at +%ds, firewall at +%ds)", hook, route, ts-bootAt, fwAt-bootAt)
		case ok && route != "proxy":
			// After it, only the audited proxy to an allowed host may work.
			t.Errorf("a %s hook got out by %s after the firewall (at +%ds)", hook, route, ts-bootAt)
		}
	}
	t.Logf("%d hook attempts this boot, %d before the firewall was applied", thisBoot, beforeFirewall)
	if t.Failed() {
		diag, _ := s.shell("echo boot=$(date -u -d \"$(uptime -s)\" +%s) fw=$(cat /run/devkit/firewall-at); grep -E ' (dns|resolved) ok' ~/boot-escape.log; ls -l /etc/resolv.conf; grep -v '^#' /etc/resolv.conf; grep '^hosts' /etc/nsswitch.conf; getent hosts example.org; echo getent-now=$?")
		t.Logf("diagnostics:\n%s", diag)
	}
	if beforeFirewall == 0 {
		t.Fatalf("no hook ran before the firewall was applied, so the test proves nothing:\n%s", logOut)
	}
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

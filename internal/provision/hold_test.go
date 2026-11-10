package provision

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/project"
)

// everyVariant runs check on the system script for every network mode and
// toolchain manager, each with extra packages and a service, so every
// download the script can make is present.
func everyVariant(t *testing.T, check func(t *testing.T, s string)) {
	for _, mode := range []string{project.NetworkAllowlist, project.NetworkOpen, project.NetworkNone} {
		for _, mgr := range []string{project.ManagerMise, project.ManagerNix, project.ManagerNone} {
			t.Run(mode+"-"+mgr, func(t *testing.T) {
				s, err := System(params(func(c *project.Config) {
					c.Network.Mode = mode
					c.Tools.Manager = mgr
					if mgr == project.ManagerNix {
						c.Tools.Versions = nil
					}
					c.Tools.Packages = []string{"jq"}
					c.Services.Postgres = &project.Postgres{Port: 5433, User: "u", Password: "p", Database: "d"}
				}))
				if err != nil {
					t.Fatal(err)
				}
				check(t, s)
			})
		}
	}
}

const (
	holdSlice    = `systemctl set-property --runtime "$HOLD_SLICE" IPAddressDeny=any`
	holdResolved = "systemctl set-property --runtime systemd-resolved.service IPAddressDeny=any"
)

// The provisioning hold is set before anything in the script uses the
// network or starts the sandbox user's own units, in every variant.
func TestProvisioningHoldComesFirst(t *testing.T) {
	everyVariant(t, func(t *testing.T, s string) {
		slice, resolved := strings.Index(s, holdSlice), strings.Index(s, holdResolved)
		if slice < 0 || resolved < 0 {
			t.Fatalf("hold missing: slice=%d resolved=%d", slice, resolved)
		}
		if !strings.Contains(s, `HOLD_SLICE="user-$SANDBOX_UID.slice"`) {
			t.Error("the hold must name the sandbox user's slice")
		}
		hold := max(slice, resolved)
		for _, net := range []string{"$APT ", `"${CURL[@]}"`, "$SECAPT ", "loginctl enable-linger", "systemctl restart systemd-resolved", `/install" --daemon`} {
			if i := strings.Index(s, net); i >= 0 && i < hold {
				t.Errorf("%q runs before the hold", net)
			}
		}
		if !strings.Contains(s, "$APT install") {
			t.Error("the variant should install packages")
		}
	})
}

// The hold is lifted only after the firewall is applied and before the
// stamp, by allowing everything and then reverting, which is what removes
// the filter on systemd 255.
func TestProvisioningHoldIsLiftedAfterTheFirewall(t *testing.T) {
	everyVariant(t, func(t *testing.T, s string) {
		fw := strings.Index(s, "\n/usr/local/sbin/devkit-firewall\n")
		allow := strings.Index(s, `systemctl set-property --runtime "$HOLD_SLICE" IPAddressAllow=any`)
		revert := strings.Index(s, `systemctl revert "$HOLD_SLICE"`)
		revertResolved := strings.Index(s, "systemctl revert systemd-resolved.service")
		restart := strings.LastIndex(s, "\nsystemctl restart systemd-resolved\n")
		stamp := strings.Index(s, "> /etc/devkit/provision.id")
		if !(fw > 0 && fw < allow && allow < revert && revert < stamp) {
			t.Fatalf("slice: firewall=%d allow=%d revert=%d stamp=%d", fw, allow, revert, stamp)
		}
		if !(fw < revertResolved && revertResolved < restart && restart < stamp) {
			t.Fatalf("resolved: firewall=%d revert=%d restart=%d stamp=%d", fw, revertResolved, restart, stamp)
		}
		// A lift that fails must abort the script: none of it is excused.
		if lift := s[allow:stamp]; strings.Contains(lift, "||") {
			t.Errorf("a failed lift must abort the script:\n%s", lift)
		}
	})
}

// The hold is a runtime property, never a drop-in file: on systemd 255 a
// hold from a drop-in cannot be lifted cleanly.
func TestProvisioningHoldUsesNoDropIn(t *testing.T) {
	everyVariant(t, func(t *testing.T, s string) {
		for _, bad := range []string{".slice.d", "systemd-resolved.service.d", "[Slice]", "\nIPAddressDeny="} {
			if strings.Contains(s, bad) {
				t.Errorf("the hold must not be written as a drop-in (%q)", bad)
			}
		}
		if n := strings.Count(s, "IPAddressDeny=any"); n != 2 {
			t.Errorf("IPAddressDeny=any should appear only in the two set-property calls, found %d", n)
		}
	})
}

// A failing command is named on the serial console before set -e aborts.
func TestFailureIsReportedOnTheSerialConsole(t *testing.T) {
	s, _ := System(params(nil))
	for _, want := range []string{
		"set -euo pipefail",
		`trap 'on_error "$?" "$LINENO" "$BASH_COMMAND"' ERR`,
		`step "failed: `,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("system script missing %q", want)
		}
	}
	trap := strings.Index(s, "trap 'on_error")
	if trap < 0 || trap > strings.Index(s, holdSlice) {
		t.Error("the trap must be set before the hold, the first step that can fail")
	}
}

// The trap reports the failing command, its line and its status, and the
// script still stops there. Runs the script's own helpers with bash, the
// console redirected to a file.
func TestFailureReportRuns(t *testing.T) {
	s, _ := System(params(nil))
	start := strings.Index(s, "step() {")
	end := strings.Index(s, "trap 'on_error")
	if start < 0 || end < 0 {
		t.Fatal("helpers or trap not found")
	}
	end += strings.Index(s[end:], "\n")
	console := filepath.Join(t.TempDir(), "hvc0")
	helpers := strings.ReplaceAll(s[start:end], "/dev/hvc0", console)
	script := "set -euo pipefail\n" + helpers + "\ntrue\nfalse --flag\necho not-reached\n"
	out, err := exec.Command("bash", "-c", script).CombinedOutput()
	if err == nil || strings.Contains(string(out), "not-reached") {
		t.Fatalf("the script must still abort: %v %s", err, out)
	}
	got, _ := os.ReadFile(console)
	// The command and status are checked exactly. The line number is only
	// checked to be there: bash 3.2, which macOS ships and CI's macOS runner
	// uses, numbers lines inside an ERR trap differently from the bash 5
	// the guest runs.
	if !regexp.MustCompile(`^devkit-progress: failed: false --flag \(line \d+, exit 1\)\n$`).Match(got) {
		t.Errorf("console got %q", got)
	}
}

// The old stamp goes before anything that can fail: a re-provisioning that
// aborts at any step, the hold included, must leave no stamp behind for
// devkit to accept. Only plain assignments may come first.
func TestOldStampIsRemovedFirst(t *testing.T) {
	check := func(t *testing.T, s string) {
		const rmStamp = "rm -f /etc/devkit/provision.id"
		if n := strings.Count(s, rmStamp); n != 1 {
			t.Fatalf("the stamp should be removed exactly once, found %d", n)
		}
		_, body, ok := strings.Cut(s, "\nset -euo pipefail\n")
		if !ok {
			t.Fatal("no set -euo pipefail")
		}
		plain := regexp.MustCompile(`^(export )?[A-Z_]+="?[A-Za-z0-9_.-]*"?$`)
		for _, l := range strings.Split(body, "\n") {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") || plain.MatchString(l) {
				continue
			}
			if l != rmStamp {
				t.Errorf("the first command must remove the stamp, got %q", l)
			}
			return
		}
		t.Fatal("no command in the script")
	}
	everyVariant(t, check)
	t.Run("host", func(t *testing.T) {
		s, err := System(hostParams(nil))
		if err != nil {
			t.Fatal(err)
		}
		check(t, s)
	})
}

// The boot-hold generator is delimited in the template by these lines, so
// TestNetnsFirewall can run exactly it, as root on the test host, and
// nothing else of the provisioning.
const (
	bootHoldBegin = "# ---- begin boot-hold generator (TestNetnsFirewall runs exactly this) ----"
	bootHoldEnd   = "# ---- end boot-hold generator ----"
)

// section returns the text between the lines begin and end, each of which
// must appear exactly once as a whole line, begin first.
func section(s, begin, end string) (string, error) {
	b, e := "\n"+begin+"\n", "\n"+end+"\n"
	if n := strings.Count(s, b); n != 1 {
		return "", fmt.Errorf("marker %q appears %d times, want once", begin, n)
	}
	if n := strings.Count(s, e); n != 1 {
		return "", fmt.Errorf("marker %q appears %d times, want once", end, n)
	}
	i, j := strings.Index(s, b), strings.Index(s, e)
	if j < i+len(b)-1 {
		return "", fmt.Errorf("marker %q comes before %q", end, begin)
	}
	return s[i+len(b) : j+1], nil
}

// heredocBody returns the body of the heredoc that opener (its whole first
// line, newline included) starts. The opener must appear exactly once, and
// the body ends at the first line that is exactly EOF, as in bash.
func heredocBody(s, opener string) (string, error) {
	if n := strings.Count(s, opener); n != 1 {
		return "", fmt.Errorf("%q appears %d times in the system script, want once", opener, n)
	}
	body := s[strings.Index(s, opener)+len(opener):]
	end := strings.Index("\n"+body, "\nEOF\n")
	if end < 0 {
		return "", fmt.Errorf("the heredoc %q has no EOF line", opener)
	}
	return body[:end], nil
}

func TestSectionMarkers(t *testing.T) {
	const b, e = "# begin", "# end"
	if got, err := section("x\n# begin\na\nb\n# end\ny\n", b, e); err != nil || got != "a\nb\n" {
		t.Errorf("got %q, %v", got, err)
	}
	for name, s := range map[string]string{
		"no begin":         "x\na\n# end\n",
		"no end":           "x\n# begin\na\n",
		"two begins":       "x\n# begin\na\n# begin\nb\n# end\n",
		"two ends":         "x\n# begin\na\n# end\nb\n# end\n",
		"end before":       "x\n# end\na\n# begin\n",
		"not a whole line": "x\n# beginning\na\n# end\n",
	} {
		if got, err := section(s, b, e); err == nil {
			t.Errorf("%s: want an error, got %q", name, got)
		}
	}
	if _, err := heredocBody("cat > f <<'EOF'\na\n", "cat > f <<'EOF'\n"); err == nil {
		t.Error("an unterminated heredoc must be an error")
	}
	if _, err := heredocBody("cat > f <<'EOF'\nEOF\ncat > f <<'EOF'\nEOF\n", "cat > f <<'EOF'\n"); err == nil {
		t.Error("a duplicated heredoc opener must be an error")
	}
}

// What TestNetnsFirewall runs as root outside any namespace must be the
// boot-hold generator and nothing else: two lookups and one heredoc that
// writes the hold script. Checked on every platform, because the netns test
// itself only runs on Linux as root.
func TestBootHoldGeneratorIsSelfContained(t *testing.T) {
	check := func(t *testing.T, s string) {
		gen, err := section(s, bootHoldBegin, bootHoldEnd)
		if err != nil {
			t.Fatal(err)
		}
		const opener = "cat > /usr/local/sbin/devkit-boot-hold <<EOF\n"
		body, err := heredocBody(gen, opener)
		if err != nil {
			t.Fatal(err)
		}
		outside := strings.Replace(gen, opener+body+"EOF\n", "", 1)
		if outside == gen {
			t.Fatal("the generator should write the hold script with one heredoc")
		}
		for _, l := range strings.Split(outside, "\n") {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "RESOLVE_UID=") || strings.HasPrefix(l, "SUBUIDS=") {
				continue
			}
			t.Errorf("the generator runs more than the hold needs: %q", l)
		}
		for _, bad := range []string{"apt", "APT", "curl", "CURL", "set-property", "systemctl", "sysctl", "sudoers", "visudo", "resolv.conf", "resolved.conf", "provision.id", "step ", "useradd", "rm "} {
			if strings.Contains(gen, bad) {
				t.Errorf("the generator must not contain %q", bad)
			}
		}
		for _, want := range []string{"$SANDBOX_UID", "$SUBUIDS", "--uid-owner", "-j REJECT"} {
			if !strings.Contains(body, want) {
				t.Errorf("the hold script should contain %q", want)
			}
		}
	}
	everyVariant(t, check)
	t.Run("host", func(t *testing.T) {
		s, err := System(hostParams(nil))
		if err != nil {
			t.Fatal(err)
		}
		check(t, s)
	})
}

// The firewall TestNetnsFirewall loads is the one heredoc that installs it.
func TestFirewallHeredocIsUnique(t *testing.T) {
	everyVariant(t, func(t *testing.T, s string) {
		if _, err := heredocBody(s, "cat > /usr/local/sbin/devkit-firewall <<'EOF'\n"); err != nil {
			t.Fatal(err)
		}
	})
}

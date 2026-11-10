package provision

import (
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

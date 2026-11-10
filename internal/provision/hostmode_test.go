package provision

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/egressproxy"
	"github.com/jurajpiar/devkit/internal/project"
)

// guestVariants are configs without host enforcement, named for the test.
func guestVariants() map[string]Params {
	out := map[string]Params{}
	for _, mode := range []string{project.NetworkAllowlist, project.NetworkOpen, project.NetworkNone} {
		for _, mgr := range []string{project.ManagerMise, project.ManagerNix, project.ManagerNone} {
			mode, mgr := mode, mgr
			out[mode+"-"+mgr] = params(func(c *project.Config) {
				c.Network.Mode = mode
				c.Tools.Manager = mgr
				if mgr != project.ManagerMise {
					c.Tools.Versions = nil
				}
			})
		}
	}
	out["loosened"] = params(func(c *project.Config) {
		c.Sudo = true
		c.Network.AllowHost = true
		c.Network.DNS = project.DNSResolvers
		c.Network.Forward = []int{3000}
		c.Network.Distrust = []string{"AAA Certificate Services"}
		c.Tools.Packages = []string{"pkg-config"}
		c.Services.Postgres = &project.Postgres{Port: 5433, User: "u", Password: "p", Database: "d"}
	})
	off := false
	out["no-security-updates"] = params(func(c *project.Config) { c.VM.SecurityUpdates = &off })
	out["enforce-guest-explicit"] = params(func(c *project.Config) { c.Network.Enforce = project.EnforceGuest })
	return out
}

const testHostProxy = "192.168.5.2:41234"

// hostParams is params with network.enforce: host and the host proxy set.
func hostParams(mod func(*project.Config)) Params {
	p := params(func(c *project.Config) {
		c.Network.Enforce = project.EnforceHost
		if mod != nil {
			mod(c)
		}
	})
	p.HostProxy = testHostProxy
	return p
}

func TestHostModeSendsRootsDownloadsThroughTheHostProxy(t *testing.T) {
	for _, mgr := range []string{project.ManagerMise, project.ManagerNix} {
		s, err := System(hostParams(func(c *project.Config) {
			c.Tools.Manager = mgr
			if mgr == project.ManagerNix {
				c.Tools.Versions = nil
			}
		}))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			`HOST_PROXY_URL="http://192.168.5.2:41234"`,
			`APT="apt-get -o Acquire::http::Proxy=$HOST_PROXY_URL -o Acquire::https::Proxy=$HOST_PROXY_URL -o DPkg::Lock::Timeout=300"`,
			`CURL=(curl -fsSL --proxy "$HOST_PROXY_URL" --retry 3`,
			`"${CURL[@]}" -o`,
		} {
			if !strings.Contains(s, want) {
				t.Errorf("%s: host mode should contain %q", mgr, want)
			}
		}
		// The direct forms may still be written first, but the host-proxy
		// forms must be the ones in force when root downloads.
		aptAt := strings.LastIndex(s, `APT="apt-get`)
		curlAt := strings.LastIndex(s, `CURL=(curl`)
		if !strings.Contains(s[aptAt:], "Proxy=$HOST_PROXY_URL") || !strings.Contains(s[curlAt:], `--proxy "$HOST_PROXY_URL"`) {
			t.Errorf("%s: the last APT and CURL definitions must use the host proxy", mgr)
		}
		if first := strings.Index(s, `$APT update`); first < aptAt {
			t.Errorf("%s: apt runs before APT points at the host proxy", mgr)
		}
	}
}

func TestHostModeEgressServiceChainsToTheHostProxy(t *testing.T) {
	s, err := System(hostParams(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, `ExecStart=/usr/local/bin/devkit-egressproxy -listen 127.0.0.1:3128 -audit -upstream 192.168.5.2:41234 \$EXTRA_ARGS`) {
		t.Error("the in-guest proxy must chain to the host proxy")
	}
	g, _ := System(params(nil))
	if strings.Contains(g, "-upstream") {
		t.Error("guest mode must not chain")
	}
}

func TestHostModeFirewall(t *testing.T) {
	s, err := System(hostParams(nil))
	if err != nil {
		t.Fatal(err)
	}
	fw := s[strings.Index(s, "cat > /usr/local/sbin/devkit-firewall <<'EOF'"):]
	fw = fw[:strings.Index(fw, "\nEOF\n")]
	for _, want := range []string{
		"HOST_PROXY_IP=192.168.5.2\nHOST_PROXY_PORT=41234\n",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("network.conf should carry %q", want)
		}
	}
	accept := `iptables -A OUTPUT -d "$HOST_PROXY_IP" -p tcp --dport "$HOST_PROXY_PORT" -m owner --uid-owner devkit-proxy -j ACCEPT`
	reject := `iptables -A OUTPUT -d "$HOST_IP" -j REJECT`
	a, r := strings.Index(fw, accept), strings.Index(fw, reject)
	if a < 0 || r < 0 || a > r {
		t.Errorf("the proxy's one allowance must come before the host is rejected for every account (accept at %d, reject at %d)", a, r)
	}
	for _, banned := range []string{
		"--dport 53",                            // no DNS for anyone
		"--uid-owner devkit-proxy -j ACCEPT ;;", // the proxy may not reach anything else
	} {
		if strings.Contains(fw, banned) {
			t.Errorf("host-mode firewall must not contain %q", banned)
		}
	}
	if !strings.Contains(fw, "iptables -A OUTPUT -j REJECT") || !strings.Contains(fw, "ip6tables -A OUTPUT -j REJECT") {
		t.Error("everything else must still be rejected")
	}
}

func TestHostModeRefusesAMissingOrMalformedProxyAddress(t *testing.T) {
	p := hostParams(nil)
	p.HostProxy = ""
	if _, err := System(p); err == nil {
		t.Error("host mode without a host proxy address must not render")
	}
	g := params(nil)
	g.HostProxy = testHostProxy
	if _, err := System(g); err == nil {
		t.Error("a host proxy address without host mode must not render")
	}
	for _, bad := range []string{"192.168.5.2", "192.168.5.2:0", "192.168.5.2:70000", "host.lima.internal:1", "192.168.5.2:1;id", "[::1]:3128", "192.168.5.2:1\n"} {
		p := hostParams(nil)
		p.HostProxy = bad
		if _, err := System(p); err == nil {
			t.Errorf("host proxy %q must be refused", bad)
		}
	}
}

func TestFingerprintCoversTheHostProxy(t *testing.T) {
	a, _ := Fingerprint(hostParams(nil))
	p := hostParams(nil)
	p.HostProxy = "192.168.5.2:41235"
	b, _ := Fingerprint(p)
	g, _ := Fingerprint(params(nil))
	if a == "" || a == b || a == g {
		t.Errorf("fingerprints must differ by host proxy and by mode: %q %q %q", a, b, g)
	}
}

// RootHosts is what the host proxy must allow beyond the project's list for
// root's own provisioning. Every URL root fetches must be covered, and so
// must Ubuntu's archive, whose hosts come from the image's sources.
func TestRootHostsCoverEveryProvisioningDownload(t *testing.T) {
	urlRe := regexp.MustCompile(`https?://([a-z0-9.-]+)/`)
	for _, mgr := range []string{project.ManagerMise, project.ManagerNix, project.ManagerNone} {
		p := hostParams(func(c *project.Config) {
			c.Tools.Manager = mgr
			if mgr != project.ManagerMise {
				c.Tools.Versions = nil
			}
		})
		hosts := RootHosts(p.Config)
		f := egressproxy.NewFilter(hosts)
		s, _ := System(p)
		// The trust audit is embedded in the script but run later by the
		// sandbox user, through the in-guest proxy; it is not root's.
		a, b := strings.Index(s, "<<'PYEOF'"), strings.Index(s, "\nPYEOF\n")
		if a < 0 || b < a {
			t.Fatal("audit script not found; update this test")
		}
		s = s[:a] + s[b:]
		for _, m := range urlRe.FindAllStringSubmatch(s, -1) {
			if m[1] == "192.168.5.2" {
				continue
			}
			if !f.IsAllowed(m[1] + ":443") {
				t.Errorf("%s: root fetches from %s, which RootHosts %v does not allow", mgr, m[1], hosts)
			}
		}
		for _, h := range []string{"ports.ubuntu.com:80", "archive.ubuntu.com:80", "security.ubuntu.com:80"} {
			if !f.IsAllowed(h) {
				t.Errorf("%s: Ubuntu's archive %s must be allowed", mgr, h)
			}
		}
		for _, h := range project.ManagerHosts[mgr] {
			if !f.IsAllowed(strings.TrimPrefix(h, "**.") + ":443") {
				t.Errorf("%s: the manager's host %s must be allowed", mgr, h)
			}
		}
	}
	if f := egressproxy.NewFilter(RootHosts(params(func(c *project.Config) { c.Tools.Manager = project.ManagerNone; c.Tools.Versions = nil }).Config)); f.IsAllowed("github.com:443") {
		t.Error("without a toolchain manager root fetches nothing from GitHub")
	}
}

// Existing VMs compare their provisioning stamp with the fingerprint of the
// script this binary renders. Host enforcement must not change a byte of
// the script for a config that does not use it, or every existing VM would
// be reported stale and reprovisioned. These hashes were taken from the
// script without host enforcement: first before it existed, then again on
// the fail-closed provisioning change it was rebased onto, where the rendered
// guest-mode scripts were compared byte for byte across the two branches. A deliberate policy change for
// guest mode updates them, knowing it makes existing VMs stale. The last such
// change closed unprivileged user namespaces and locked module loading.
func TestGuestModeScriptIsUnchangedByHostEnforcement(t *testing.T) {
	want := map[string]string{
		"allowlist-mise":         "c2d67d696f7a767b",
		"allowlist-nix":          "b7f7706800f9bd04",
		"allowlist-none":         "f12c926330befd7a",
		"enforce-guest-explicit": "c2d67d696f7a767b",
		"loosened":               "a97e7b64137986c6",
		"no-security-updates":    "dde18da4d52f19e8",
		"none-mise":              "c8ef4fb710ecee1c",
		"none-nix":               "b5f7c221bbd717bc",
		"none-none":              "99d3390993302284",
		"open-mise":              "5f881efb97d50aa2",
		"open-nix":               "92a26b932a7843d1",
		"open-none":              "9d1623c16f6fe4b4",
	}
	var got []string
	for name, p := range guestVariants() {
		s, err := System(p)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(s))
		h := hex.EncodeToString(sum[:])[:16]
		got = append(got, fmt.Sprintf("%q: %q,", name, h))
		if w, ok := want[name]; !ok || w != h {
			t.Errorf("%s: guest-mode system script changed (hash %s, want %s)", name, h, w)
		}
	}
	if t.Failed() {
		sort.Strings(got)
		t.Logf("current hashes:\n%s", strings.Join(got, "\n"))
	}
}

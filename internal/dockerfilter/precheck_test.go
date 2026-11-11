package dockerfilter

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	ctrID = strings.Repeat("ab", 32)
	netID = strings.Repeat("cd", 32)
)

func (h *harness) setInspect(status int, body string) {
	h.daemon.mu.Lock()
	defer h.daemon.mu.Unlock()
	h.daemon.inspectStatus, h.daemon.inspect = status, body
}

func (h *harness) setNetworks(n map[string]string) {
	h.daemon.mu.Lock()
	defer h.daemon.mu.Unlock()
	h.daemon.networks = n
}

// calls returns the requests the daemon got other than inspections.
func (h *harness) calls() []received {
	var out []received
	for _, r := range h.daemon.requests() {
		if r.Method == "GET" && (strings.HasSuffix(r.URI, "/json") || strings.HasPrefix(r.URI, "/networks/")) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// Whatever the filter must look at first, an answer that is not a 200 that
// parses stops the call: refused, or for a 404 the daemon's own answer
// passed back. Nothing is forwarded.
func TestInspectionFailureIsNeverForwarded(t *testing.T) {
	calls := []struct{ method, path string }{
		{"POST", "/v1.52/containers/web/start"},
		{"POST", "/v1.52/containers/web/restart"},
		{"GET", "/v1.52/containers/web/archive?path=/s"},
		{"HEAD", "/v1.52/containers/web/archive?path=/s"},
		{"PUT", "/v1.52/containers/web/archive?path=/s"},
	}
	for _, c := range calls {
		for _, a := range []struct {
			name   string
			status int
			body   string
			want   int
		}{
			{"500", 500, `{"message":"boom"}`, http.StatusForbidden},
			{"409", 409, `{"message":"conflict"}`, http.StatusForbidden},
			{"unparsable", 200, `{"Id":`, http.StatusForbidden},
			{"not an object", 200, `[]`, http.StatusForbidden},
			{"no ID", 200, `{"HostConfig":{}}`, http.StatusForbidden},
			{"404", 404, `{"message":"No such container: web"}`, http.StatusNotFound},
		} {
			h := newHarness(t)
			h.setInspect(a.status, a.body)
			st, body := h.raw(t, c.method, c.path, "")
			if st != a.want {
				t.Errorf("%s %s, inspection %s: %d %s", c.method, c.path, a.name, st, body)
			}
			if a.status == 404 && c.method != "HEAD" && !strings.Contains(body, "No such container: web") {
				t.Errorf("%s %s: the daemon's 404 should be passed back: %s", c.method, c.path, body)
			}
			if got := h.calls(); len(got) != 0 {
				t.Errorf("%s %s, inspection %s: forwarded %v", c.method, c.path, a.name, got)
			}
		}
	}
}

// docker cp is refused for a container with a bind mount however the bind
// was asked for, and goes to the full ID for one without.
func TestArchiveRefusedWithABindMount(t *testing.T) {
	refused := map[string]string{
		"a bind in Mounts":            `{"Id":"` + ctrID + `","HostConfig":{},"Mounts":[{"Type":"bind","Source":"/ws/swap"}]}`,
		"a bind in HostConfig.Binds":  `{"Id":"` + ctrID + `","HostConfig":{"Binds":["/ws/swap:/s"]},"Mounts":[]}`,
		"a bind in HostConfig.Mounts": `{"Id":"` + ctrID + `","HostConfig":{"Mounts":[{"Type":"bind"}]},"Mounts":[]}`,
		"an unknown mount type":       `{"Id":"` + ctrID + `","HostConfig":{},"Mounts":[{"Type":"npipe","Source":"x"}]}`,
		"a bind from VolumesFrom":     `{"Id":"` + ctrID + `","HostConfig":{"VolumesFrom":["other"]},"Mounts":[{"Type":"bind","Source":"/ws/d"}]}`,
	}
	for name, insp := range refused {
		for _, method := range []string{"GET", "HEAD", "PUT"} {
			h := newHarness(t)
			h.setInspect(200, insp)
			st, body := h.raw(t, method, "/v1.52/containers/web/archive?path=/s", "")
			if st != http.StatusForbidden || (method != "HEAD" && !strings.Contains(body, "docker exec")) {
				t.Errorf("%s, %s: %d %s", name, method, st, body)
			}
			if got := h.calls(); len(got) != 0 {
				t.Errorf("%s, %s: forwarded %v", name, method, got)
			}
		}
	}
	allowed := map[string]string{
		"no mounts":           `{"Id":"` + ctrID + `","HostConfig":{"Binds":null},"Mounts":[]}`,
		"volumes and a tmpfs": `{"Id":"` + ctrID + `","HostConfig":{"Binds":["data:/d","/anon","/anon2:ro"],"Mounts":[{"Type":"volume"},{"Type":"tmpfs"}]},"Mounts":[{"Type":"volume","Source":"/var/lib/x/volumes/data/_data"},{"Type":"tmpfs","Source":""}]}`,
	}
	for name, insp := range allowed {
		for _, method := range []string{"GET", "HEAD", "PUT"} {
			h := newHarness(t)
			h.setInspect(200, insp)
			if st, body := h.raw(t, method, "/v1.52/containers/web/archive?path=/s", ""); st == http.StatusForbidden {
				t.Errorf("%s, %s: %d %s", name, method, st, body)
			}
			if got := h.daemon.last(t); got.Method != method || got.URI != "/v1.52/containers/"+ctrID+"/archive?path=%2Fs" {
				t.Errorf("%s, %s: forwarded %s %s, want the full ID", name, method, got.Method, got.URI)
			}
		}
	}
}

// Without the guard, the start looks at the bind sources again: a source
// turned into a symlink out of the workspace since the create is refused.
func TestStartRechecksBindsWithoutTheGuard(t *testing.T) {
	for _, guarded := range []bool{true, false} {
		h := newHarness(t)
		h.cfg.RuntimeGuard = guarded
		os.Symlink("/etc", filepath.Join(h.cfg.Workspace, "swap"))
		h.setInspect(200, `{"Id":"`+ctrID+`","HostConfig":{"Runtime":"devkit-runc"},"Mounts":[{"Type":"bind","Source":"`+h.cfg.Workspace+`/swap"}]}`)
		st, body := h.raw(t, "POST", "/containers/web/start", "")
		if (st == http.StatusForbidden) == guarded {
			t.Errorf("guarded=%v: %d %s", guarded, st, body)
		}
	}
}

// A network made through the filter publishes on loopback: the option is
// added when absent, kept when it is loopback, and refused otherwise. What
// reaches the daemon carries it.
func TestNetworkCreateGetsLoopback(t *testing.T) {
	for _, c := range []struct {
		name, body string
		ok         bool
	}{
		{"absent", `{"Name":"n","Driver":"bridge"}`, true},
		{"no options at all", `{"Name":"n","Options":null}`, true},
		{"other options only", `{"Name":"n","Options":{"com.docker.network.driver.mtu":"1400"}}`, true},
		{"loopback", `{"Name":"n","Options":{"com.docker.network.bridge.host_binding_ipv4":"127.0.0.1"}}`, true},
		{"every interface", `{"Name":"n","Options":{"com.docker.network.bridge.host_binding_ipv4":"0.0.0.0"}}`, false},
		{"another address", `{"Name":"n","Options":{"com.docker.network.bridge.host_binding_ipv4":"192.168.5.15"}}`, false},
		{"empty", `{"Name":"n","Options":{"com.docker.network.bridge.host_binding_ipv4":""}}`, false},
	} {
		h := newHarness(t)
		st, body := h.raw(t, "POST", "/v1.52/networks/create", c.body)
		if (st != http.StatusForbidden) != c.ok {
			t.Errorf("%s: %d %s", c.name, st, body)
			continue
		}
		if !c.ok {
			if len(h.daemon.requests()) != 0 {
				t.Errorf("%s: reached the daemon", c.name)
			}
			continue
		}
		var got NetworkCreate
		if err := json.Unmarshal(h.daemon.last(t).Body, &got); err != nil || got.Options[loopbackOption] != "127.0.0.1" {
			t.Errorf("%s: forwarded %s", c.name, h.daemon.last(t).Body)
		}
		if strings.Contains(c.body, "mtu") && got.Options["com.docker.network.driver.mtu"] != "1400" {
			t.Errorf("%s: other options should be kept: %s", c.name, h.daemon.last(t).Body)
		}
	}
}

// A binding with no address is given loopback, so that it is the same on
// a network made before the filter set the default.
func TestEmptyHostIPBecomesLoopback(t *testing.T) {
	h := newHarness(t)
	body := `{"Image":"x","HostConfig":{"PortBindings":{"80/tcp":[{"HostIp":"","HostPort":"8080"},{"HostIp":"::1","HostPort":"8081"}]}}}`
	if st, resp := h.raw(t, "POST", "/containers/create", body); st == http.StatusForbidden {
		t.Fatalf("%d %s", st, resp)
	}
	var got CreateRequest
	json.Unmarshal(h.daemon.last(t).Body, &got)
	b := got.HostConfig.PortBindings["80/tcp"]
	if len(b) != 2 || b[0].HostIP != "127.0.0.1" || b[0].HostPort != "8080" || b[1].HostIP != "::1" {
		t.Errorf("forwarded %s", h.daemon.last(t).Body)
	}
}

const (
	loopbackNet = `{"Id":"` + "%s" + `","Name":"%s","Options":{"com.docker.network.bridge.host_binding_ipv4":"127.0.0.1"}}`
	openNet     = `{"Id":"` + "%s" + `","Name":"%s","Options":{}}`
)

func netBody(tmpl, name string) string {
	return strings.Replace(strings.Replace(tmpl, "%s", netID, 1), "%s", name, 1)
}

// -P on a user-defined network made before the filter set its address is
// refused; on one made through the filter, or the default bridge, it is
// forwarded. A network that cannot be looked at stops the create.
func TestPublishAllNeedsALoopbackNetwork(t *testing.T) {
	nets := map[string]string{"new": netBody(loopbackNet, "new"), "old": netBody(openNet, "old"), "bad": `{"Id":`}
	for _, c := range []struct {
		name, body string
		ok         bool
	}{
		{"default bridge", `{"Image":"x","HostConfig":{"PublishAllPorts":true}}`, true},
		{"bridge by name", `{"Image":"x","HostConfig":{"PublishAllPorts":true,"NetworkMode":"bridge"}}`, true},
		{"made through the filter", `{"Image":"x","HostConfig":{"PublishAllPorts":true,"NetworkMode":"new"}}`, true},
		{"made before", `{"Image":"x","HostConfig":{"PublishAllPorts":true,"NetworkMode":"old"}}`, false},
		{"made before, as a second network", `{"Image":"x","HostConfig":{"PublishAllPorts":true,"NetworkMode":"new"},"NetworkingConfig":{"EndpointsConfig":{"new":{},"old":{}}}}`, false},
		{"missing", `{"Image":"x","HostConfig":{"PublishAllPorts":true,"NetworkMode":"gone"}}`, false},
		{"unreadable", `{"Image":"x","HostConfig":{"PublishAllPorts":true,"NetworkMode":"bad"}}`, false},
		{"no -P on an old network", `{"Image":"x","HostConfig":{"NetworkMode":"old","PortBindings":{"80/tcp":[{"HostPort":"8080"}]}}}`, true},
	} {
		h := newHarness(t)
		h.setNetworks(nets)
		st, body := h.raw(t, "POST", "/containers/create", c.body)
		if (st < 300) != c.ok {
			t.Errorf("%s: %d %s", c.name, st, body)
		}
		if !c.ok && len(h.calls()) != 0 {
			t.Errorf("%s: forwarded", c.name)
		}
		if c.name == "made before" && !strings.Contains(body, "docker network rm old") {
			t.Errorf("the refusal should say what to do: %s", body)
		}
	}
}

// Connecting a container that publishes on the default address needs a
// loopback network; the container, and the network when looked at, go by
// full ID.
func TestConnectPinsAndNeedsLoopback(t *testing.T) {
	nets := map[string]string{"new": netBody(loopbackNet, "new"), "old": netBody(openNet, "old")}
	publishing := `{"Id":"` + ctrID + `","HostConfig":{"PublishAllPorts":true}}`
	quiet := `{"Id":"` + ctrID + `","HostConfig":{"PortBindings":{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"1"}]}}}`
	for _, c := range []struct {
		name, ctr, net string
		ok             bool
		path           string
	}{
		{"publishing, to a loopback network", publishing, "new", true, "/v1.52/networks/" + netID + "/connect"},
		{"publishing, to an old network", publishing, "old", false, ""},
		{"publishing, to a missing network", publishing, "gone", false, ""},
		{"not publishing, to an old network", quiet, "old", true, "/v1.52/networks/old/connect"},
	} {
		h := newHarness(t)
		h.setNetworks(nets)
		h.setInspect(200, c.ctr)
		st, body := h.raw(t, "POST", "/v1.52/networks/"+c.net+"/connect", `{"Container":"web"}`)
		if (st < 300) != c.ok {
			t.Errorf("%s: %d %s", c.name, st, body)
			continue
		}
		if !c.ok {
			if len(h.calls()) != 0 {
				t.Errorf("%s: forwarded", c.name)
			}
			continue
		}
		got := h.daemon.last(t)
		var n NetworkConnect
		json.Unmarshal(got.Body, &n)
		if got.URI != c.path || n.Container != ctrID {
			t.Errorf("%s: forwarded %s %s", c.name, got.URI, got.Body)
		}
	}
	h := newHarness(t)
	h.setInspect(500, `{}`)
	if st, _ := h.raw(t, "POST", "/networks/new/connect", `{"Container":"web"}`); st != http.StatusForbidden || len(h.calls()) != 0 {
		t.Errorf("an inspection failure on connect: %d", st)
	}
}

// A stored container that publishes beyond loopback, or by default on a
// network made before the filter, does not start.
func TestStartChecksPublishing(t *testing.T) {
	nets := map[string]string{"new": netBody(loopbackNet, "new"), "old": netBody(openNet, "old")}
	for _, c := range []struct {
		name, insp string
		ok         bool
	}{
		{"explicit loopback on an old network", `{"Id":"` + ctrID + `","HostConfig":{"NetworkMode":"old","PortBindings":{"80/tcp":[{"HostIp":"127.0.0.1"}]}},"NetworkSettings":{"Networks":{"old":{}}}}`, true},
		{"explicit 0.0.0.0", `{"Id":"` + ctrID + `","HostConfig":{"PortBindings":{"80/tcp":[{"HostIp":"0.0.0.0"}]}}}`, false},
		{"default address on the bridge", `{"Id":"` + ctrID + `","HostConfig":{"NetworkMode":"bridge","PortBindings":{"80/tcp":[{"HostIp":""}]}},"NetworkSettings":{"Networks":{"bridge":{}}}}`, true},
		{"default address on a new network", `{"Id":"` + ctrID + `","HostConfig":{"NetworkMode":"new","PublishAllPorts":true},"NetworkSettings":{"Networks":{"new":{}}}}`, true},
		{"default address on an old network", `{"Id":"` + ctrID + `","HostConfig":{"NetworkMode":"new","PublishAllPorts":true},"NetworkSettings":{"Networks":{"new":{},"old":{}}}}`, false},
	} {
		h := newHarness(t)
		h.setNetworks(nets)
		h.setInspect(200, c.insp)
		st, body := h.raw(t, "POST", "/containers/web/start", "")
		if (st < 300) != c.ok {
			t.Errorf("%s: %d %s", c.name, st, body)
		}
	}
}

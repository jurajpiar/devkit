package dockerfilter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Some calls are judged by what the daemon has stored rather than by the
// request: a container's settings before it starts, its mounts before the
// daemon copies files through them, a network's port binding before a
// container joins it. The filter asks the daemon first, and the rule for
// every such question is the same: an answer that is not a 200 that parses
// is a refusal, never a pass. Between the question and the call, a rename
// could put another container under the name asked about, so a call made
// after a look at a container goes to the full ID the look returned.

// answer is the daemon's own reply to an inspection, passed back to the
// client instead of the call: a 404 for a container or network that does
// not exist, which the client prints as it would without the filter.
type answer struct {
	status int
	ctype  string
	body   []byte
}

func (a *answer) Error() string { return fmt.Sprintf("the daemon answered %d", a.status) }

func (a *answer) write(w http.ResponseWriter) {
	if a.ctype != "" {
		w.Header().Set("Content-Type", a.ctype)
	}
	w.WriteHeader(a.status)
	w.Write(a.body)
}

// maxInspect bounds what the filter reads of one inspection.
const maxInspect = 64 << 20

// inspect asks the daemon for GET path and decodes the answer into v.
func (f *Filter) inspect(ctx context.Context, what, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := f.transport.RoundTrip(req)
	if err != nil {
		return err // answered as the daemon being down: nothing is forwarded
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return &answer{status: http.StatusNotFound, ctype: resp.Header.Get("Content-Type"), body: body}
	default:
		return refuse("the filter could not look at %s first: the daemon answered %d", what, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxInspect)).Decode(v); err != nil {
		return refuse("the filter could not read %s: %v", what, err)
	}
	return nil
}

// storedContainer is what the filter reads of a container's inspection.
type storedContainer struct {
	ID         string `json:"Id"`
	HostConfig struct {
		Runtime         string
		Privileged      bool
		Binds           []string
		Mounts          []struct{ Type string }
		PortBindings    map[string][]PortBinding
		PublishAllPorts bool
		NetworkMode     string
	}
	// Mounts is every mount the daemon makes for the container, whatever
	// asked for it: Binds, HostConfig.Mounts, VolumesFrom and the image's
	// volumes alike.
	Mounts []struct {
		Type   string
		Source string
	}
	NetworkSettings struct {
		Networks map[string]json.RawMessage
	}
}

func (f *Filter) inspectContainer(ctx context.Context, ref string) (*storedContainer, error) {
	var c storedContainer
	if err := f.inspect(ctx, "the container", "/containers/"+url.PathEscape(ref)+"/json", &c); err != nil {
		return nil, err
	}
	if !idRe.MatchString(c.ID) {
		return nil, refuse("the container's ID %q is not one the filter recognises", c.ID)
	}
	return &c, nil
}

// pinContainer points the call at the container's full ID in place of the
// segment at i.
func pinContainer(out *http.Request, i int, id string) {
	segs := strings.Split(out.URL.Path, "/")
	segs[i] = id
	out.URL.Path = strings.Join(segs, "/")
	out.URL.RawPath = ""
}

// idSegment is the index of the {id} segment in a forwarded path of the
// form [/vX.Y]/containers/{id}/<verb>.
func idSegment(out *http.Request) int {
	return len(strings.Split(out.URL.Path, "/")) - 2
}

// checkStart looks at the stored container before a start or restart: a
// container made before the filter existed, or under another runtime
// setting, may carry what the filter would refuse today.
func checkStart(f *Filter, ctx context.Context, out *http.Request, _ []byte) ([]byte, error) {
	i := idSegment(out)
	c, err := f.inspectContainer(ctx, strings.Split(out.URL.Path, "/")[i])
	if err != nil {
		return nil, err
	}
	h := c.HostConfig
	if h.Privileged {
		return nil, refuse("the container is privileged")
	}
	if rt := h.Runtime; rt != "" && !f.cfg.allowedRuntime(rt) {
		return nil, refuse("the container runs under the runtime %q, which is not allowed", rt)
	}
	// With nothing to check the mounts as made, the bind sources are
	// checked again now: the user may have rearranged the workspace since
	// the container was made. It narrows the window to the start itself;
	// it does not close it (see SECURITY.md).
	if !f.cfg.RuntimeGuard {
		for _, m := range c.Mounts {
			if m.Type == "bind" {
				if err := f.checkSource(m.Source); err != nil {
					return nil, refuse("the container's bind mount: %v", err)
				}
			}
		}
	}
	for port, bindings := range h.PortBindings {
		for _, b := range bindings {
			if err := oneOf("HostConfig.PortBindings["+port+"].HostIp", b.HostIP, "", "127.0.0.1", "::1"); err != nil {
				return nil, refuse("the container's %v", err)
			}
		}
	}
	if publishesByDefault(h.PublishAllPorts, h.PortBindings) {
		names := []string{h.NetworkMode}
		for n := range c.NetworkSettings.Networks {
			names = append(names, n)
		}
		if err := f.requireLoopbackNetworks(ctx, names); err != nil {
			return nil, err
		}
	}
	pinContainer(out, i, c.ID)
	return nil, nil
}

// checkArchive refuses docker cp, in or out, for a container with a bind
// mount. The daemon makes a container's mounts itself to copy files
// through them, without the runtime, so the guard never sees those mounts:
// a bind source the user has since swapped for a symlink would be followed
// to wherever it leads. Volumes and tmpfs are the daemon's own and pass.
func checkArchive(f *Filter, ctx context.Context, out *http.Request, _ []byte) ([]byte, error) {
	i := idSegment(out)
	c, err := f.inspectContainer(ctx, strings.Split(out.URL.Path, "/")[i])
	if err != nil {
		return nil, err
	}
	if err := ownMountsOnly(c); err != nil {
		return nil, refuse("docker cp is not available for a container with %v: Docker would make that mount itself, outside the runtime guard. "+
			"The files of a bind mount are in the workspace already; for the rest, use docker exec (for example, docker exec <container> cat <file>)", err)
	}
	pinContainer(out, i, c.ID)
	return nil, nil
}

// ownMountsOnly reports the first mount of c that is not a volume or a
// tmpfs. The inspection's Mounts list is what the daemon mounts; the
// container's own settings are read too, so that a mount that list leaves
// out for any reason is still seen.
func ownMountsOnly(c *storedContainer) error {
	for _, m := range c.Mounts {
		if m.Type != "volume" && m.Type != "tmpfs" {
			return fmt.Errorf("a %s mount of %s", m.Type, m.Source)
		}
	}
	for _, m := range c.HostConfig.Mounts {
		if m.Type != "volume" && m.Type != "tmpfs" {
			return fmt.Errorf("a %s mount", m.Type)
		}
	}
	for _, b := range c.HostConfig.Binds {
		src, _, err := splitBind(b)
		if err != nil || src != "" && !nameRe.MatchString(src) {
			return fmt.Errorf("a bind mount (%s)", b)
		}
	}
	return nil
}

// publishesByDefault reports whether a container publishes a port on the
// network's default address: with -P, or with a binding that names none.
func publishesByDefault(all bool, pb map[string][]PortBinding) bool {
	if all {
		return true
	}
	for _, bindings := range pb {
		for _, b := range bindings {
			if b.HostIP == "" {
				return true
			}
		}
	}
	return false
}

// loopbackOption is the bridge option that sets the address a network
// publishes ports on when a binding names none. The daemon's own "ip"
// setting is that address for the default bridge only.
const loopbackOption = "com.docker.network.bridge.host_binding_ipv4"

// requireLoopbackNetworks refuses unless each user-defined network named
// publishes on the VM's loopback by default. Networks made through the
// filter always do; one made before it may not.
func (f *Filter) requireLoopbackNetworks(ctx context.Context, names []string) error {
	seen := map[string]bool{}
	for _, n := range names {
		switch {
		case n == "" || n == "default" || n == "bridge" || n == "none" || n == "host" || strings.HasPrefix(n, "container:") || seen[n]:
			continue
		}
		seen[n] = true
		if _, err := f.loopbackNetwork(ctx, n); err != nil {
			return err
		}
	}
	return nil
}

// loopbackNetwork inspects one network, refuses it unless it publishes on
// loopback by default, and returns its full ID.
func (f *Filter) loopbackNetwork(ctx context.Context, ref string) (string, error) {
	var n struct {
		ID      string `json:"Id"`
		Name    string
		Options map[string]string
	}
	if err := f.inspect(ctx, "the network "+ref, "/networks/"+url.PathEscape(ref), &n); err != nil {
		return "", err
	}
	if !idRe.MatchString(n.ID) {
		return "", refuse("the network's ID %q is not one the filter recognises", n.ID)
	}
	if n.Options[loopbackOption] != "127.0.0.1" {
		return "", refuse("the network %s publishes ports on every interface, having been made before devkit set its address: "+
			"publish with an address (-p 127.0.0.1:8080:80), or remove the network (docker network rm %s; docker compose down) and let it be made again", n.Name, n.Name)
	}
	return n.ID, nil
}

// checkCreatePublish refuses -P on a user-defined network made before the
// filter set its address. A binding with no address has been given
// 127.0.0.1 by then (validateCreate), so only -P is left to the network.
func checkCreatePublish(f *Filter, ctx context.Context, _ *http.Request, body []byte) ([]byte, error) {
	var r CreateRequest
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, refuse("the body as validated does not decode: %v", err)
	}
	if r.HostConfig == nil || !r.HostConfig.PublishAllPorts {
		return nil, nil
	}
	names := []string{r.HostConfig.NetworkMode}
	if r.NetworkingConfig != nil {
		for n := range r.NetworkingConfig.EndpointsConfig {
			names = append(names, n)
		}
	}
	return nil, f.requireLoopbackNetworks(ctx, names)
}

// checkConnect refuses to join a container that publishes on the default
// address to a network made before the filter set it. The container and,
// when looked at, the network are pinned to their full IDs.
func checkConnect(f *Filter, ctx context.Context, out *http.Request, body []byte) ([]byte, error) {
	var n NetworkConnect
	if err := json.Unmarshal(body, &n); err != nil {
		return nil, refuse("the body as validated does not decode: %v", err)
	}
	if n.Container == "" {
		return nil, refuse("Container is empty")
	}
	c, err := f.inspectContainer(ctx, n.Container)
	if err != nil {
		return nil, err
	}
	if publishesByDefault(c.HostConfig.PublishAllPorts, c.HostConfig.PortBindings) {
		segs := strings.Split(out.URL.Path, "/")
		i := len(segs) - 2 // [..., "networks", "{id}", "connect"]
		id, err := f.loopbackNetwork(ctx, segs[i])
		if err != nil {
			return nil, err
		}
		pinContainer(out, i, id)
	}
	n.Container = c.ID
	return json.Marshal(&n)
}

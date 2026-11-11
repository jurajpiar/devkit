package dockerfilter

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

type bodyKind int

const (
	bodyNone   bodyKind = iota // no body may be sent
	bodyStream                 // passed through as it comes, unread
	bodyJSON                   // decoded strictly, validated, re-encoded
)

// endpoint is one call the filter lets through.
type endpoint struct {
	method  string
	pattern string
	// query lists the parameters the call takes; true marks one the
	// client may repeat (docker build -t a -t b, docker save a b).
	query map[string]bool
	body  bodyKind
	// validate decodes, checks and re-encodes a JSON body. optional means
	// an empty body is passed on as empty.
	validate func(f *Filter, body []byte) ([]byte, error)
	optional bool
	// upgrade marks a call that may switch the connection to a raw stream
	// (attach, exec) or to HTTP/2 (BuildKit's session and gRPC).
	upgrade bool
	// checkQuery refuses parameter values the call must not have.
	checkQuery func(url.Values) error
	// startCheck makes the filter look at the stored container before it
	// lets the call start it.
	startCheck bool

	segs []string
}

func q(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		multi := strings.HasSuffix(n, "*")
		m[strings.TrimSuffix(n, "*")] = multi
	}
	return m
}

// The endpoint table. {id} is one path segment; {name...} is one or more,
// for image references with slashes in them. Anything not listed is
// refused: plugins, swarm, services, tasks, nodes, secrets, configs,
// container update, attach over websockets and checkpoints among it.
var endpoints = []*endpoint{
	// System.
	{method: "GET", pattern: "/_ping"},
	{method: "HEAD", pattern: "/_ping"},
	{method: "GET", pattern: "/version"},
	{method: "GET", pattern: "/info"},
	{method: "GET", pattern: "/events", query: q("since", "until", "filters")},
	{method: "GET", pattern: "/system/df", query: q("type*", "verbose")},
	{method: "POST", pattern: "/auth", body: bodyStream},

	// Containers.
	{method: "GET", pattern: "/containers/json", query: q("all", "limit", "size", "filters", "before", "since")},
	{method: "POST", pattern: "/containers/create", query: q("name", "platform"), body: bodyJSON, validate: decodeCreate},
	{method: "POST", pattern: "/containers/prune", query: q("filters")},
	{method: "GET", pattern: "/containers/{id}/json", query: q("size")},
	{method: "GET", pattern: "/containers/{id}/top", query: q("ps_args")},
	{method: "GET", pattern: "/containers/{id}/logs", query: q("follow", "stdout", "stderr", "since", "until", "timestamps", "tail", "details")},
	{method: "GET", pattern: "/containers/{id}/changes"},
	{method: "GET", pattern: "/containers/{id}/stats", query: q("stream", "one-shot")},
	{method: "GET", pattern: "/containers/{id}/export"},
	{method: "GET", pattern: "/containers/{id}/archive", query: q("path")},
	{method: "HEAD", pattern: "/containers/{id}/archive", query: q("path")},
	{method: "PUT", pattern: "/containers/{id}/archive", query: q("path", "noOverwriteDirNonDir", "copyUIDGID"), body: bodyStream},
	{method: "POST", pattern: "/containers/{id}/start", query: q("detachKeys"), startCheck: true},
	{method: "POST", pattern: "/containers/{id}/stop", query: q("t", "signal")},
	{method: "POST", pattern: "/containers/{id}/restart", query: q("t", "signal"), startCheck: true},
	{method: "POST", pattern: "/containers/{id}/kill", query: q("signal")},
	{method: "POST", pattern: "/containers/{id}/pause"},
	{method: "POST", pattern: "/containers/{id}/unpause"},
	{method: "POST", pattern: "/containers/{id}/wait", query: q("condition")},
	{method: "POST", pattern: "/containers/{id}/rename", query: q("name")},
	{method: "POST", pattern: "/containers/{id}/resize", query: q("h", "w")},
	{method: "POST", pattern: "/containers/{id}/attach", query: q("detachKeys", "logs", "stream", "stdin", "stdout", "stderr"), upgrade: true},
	{method: "DELETE", pattern: "/containers/{id}", query: q("v", "force", "link")},
	{method: "POST", pattern: "/containers/{id}/exec", body: bodyJSON, validate: decodeExec},
	{method: "POST", pattern: "/exec/{id}/start", body: bodyJSON, validate: decodeExecStart, upgrade: true},
	{method: "POST", pattern: "/exec/{id}/resize", query: q("h", "w")},
	{method: "GET", pattern: "/exec/{id}/json"},
	{method: "POST", pattern: "/commit", query: q("container", "repo", "tag", "comment", "author", "pause", "changes*"), body: bodyJSON, validate: decodeCommit, optional: true},

	// Images.
	{method: "GET", pattern: "/images/json", query: q("all", "filters", "filter", "shared-size", "digests", "manifests")},
	{method: "GET", pattern: "/images/search", query: q("term", "limit", "filters")},
	{method: "GET", pattern: "/images/get", query: q("names*", "platform*")},
	{method: "POST", pattern: "/images/create", query: q("fromImage", "fromSrc", "repo", "tag", "message", "changes*", "platform"), body: bodyStream},
	{method: "POST", pattern: "/images/load", query: q("quiet", "platform*"), body: bodyStream},
	{method: "POST", pattern: "/images/prune", query: q("filters")},
	{method: "GET", pattern: "/images/{name...}/json", query: q("manifests", "platform")},
	{method: "GET", pattern: "/images/{name...}/history", query: q("platform")},
	{method: "GET", pattern: "/images/{name...}/get", query: q("platform*")},
	{method: "POST", pattern: "/images/{name...}/tag", query: q("repo", "tag")},
	{method: "POST", pattern: "/images/{name...}/push", query: q("tag", "platform")},
	{method: "DELETE", pattern: "/images/{name...}", query: q("force", "noprune", "platforms*")},
	{method: "GET", pattern: "/distribution/{name...}/json"},

	// Build. BuildKit's session and gRPC streams are not parsed.
	{method: "POST", pattern: "/build", query: q("t*", "extrahosts*", "dockerfile", "buildargs", "labels", "nocache", "pull",
		"rm", "forcerm", "q", "target", "platform", "remote", "shmsize", "memory", "memswap", "cpushares", "cpusetcpus",
		"cpusetmems", "cpuperiod", "cpuquota", "cachefrom", "squash", "version", "session", "buildid", "outputs",
		"networkmode", "ulimits", "cgroupparent", "securityopt*", "isolation"), body: bodyStream, checkQuery: checkBuildQuery},
	{method: "POST", pattern: "/build/prune", query: q("all", "filters", "keep-storage", "reserved-space", "max-used-space", "min-free-space")},
	{method: "POST", pattern: "/build/cancel", query: q("id")},
	{method: "POST", pattern: "/session", upgrade: true},
	{method: "POST", pattern: "/grpc", upgrade: true},

	// Networks.
	{method: "GET", pattern: "/networks", query: q("filters")},
	{method: "POST", pattern: "/networks/create", body: bodyJSON, validate: decodeNetworkCreate},
	{method: "POST", pattern: "/networks/prune", query: q("filters")},
	{method: "GET", pattern: "/networks/{id}", query: q("verbose", "scope")},
	{method: "POST", pattern: "/networks/{id}/connect", body: bodyJSON, validate: decodeNetworkConnect},
	{method: "POST", pattern: "/networks/{id}/disconnect", body: bodyJSON, validate: decodeNetworkDisconnect},
	{method: "DELETE", pattern: "/networks/{id}"},

	// Volumes.
	{method: "GET", pattern: "/volumes", query: q("filters")},
	{method: "POST", pattern: "/volumes/create", body: bodyJSON, validate: decodeVolumeCreate},
	{method: "POST", pattern: "/volumes/prune", query: q("filters")},
	{method: "GET", pattern: "/volumes/{name}"},
	{method: "DELETE", pattern: "/volumes/{name}", query: q("force")},
}

func init() {
	for _, e := range endpoints {
		e.segs = strings.Split(strings.TrimPrefix(e.pattern, "/"), "/")
	}
}

// checkBuildQuery refuses the classic builder's parameters that reach past
// the build's own sandbox. An empty value is what the client sends when
// the option is not used.
func checkBuildQuery(v url.Values) error {
	if err := oneOf("networkmode", v.Get("networkmode"), "", "default", "bridge", "none"); err != nil {
		return err
	}
	if v.Get("cgroupparent") != "" {
		return errors.New("cgroupparent is not allowed")
	}
	for _, s := range v["securityopt"] {
		if s != "" {
			return errors.New("securityopt is not allowed")
		}
	}
	return oneOf("isolation", v.Get("isolation"), "", "default")
}

var versionRe = regexp.MustCompile(`^/v[0-9]+\.[0-9]+(/|$)`)

// canonical checks a request path as received and splits it into the
// optional version prefix ("/v1.52", kept when the call is forwarded) and
// the rest, which is matched against the table.
//
// The rule for percent-escapes: the only escapes allowed are those of ':',
// '@' and space, which may appear in image references and never change
// how a path splits into segments. Any other escape (of '/', '.', a letter
// or anything else) is refused, so the path the filter matches and the
// path the daemon routes are the same string. Only the characters Docker
// object names and image references use are accepted at all.
func canonical(raw string) (prefix, rest string, err error) {
	if raw == "" || raw[0] != '/' {
		return "", "", errors.New("the path must start with /")
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c >= 0x80:
			return "", "", errors.New("the path has a non-ASCII byte")
		case c == '%':
			if i+2 >= len(raw) {
				return "", "", errors.New("the path has a broken percent-escape")
			}
			switch strings.ToUpper(raw[i+1 : i+3]) {
			case "3A", "40", "20":
			default:
				return "", "", fmt.Errorf("the path has the percent-escape %s, which the filter does not accept", raw[i:i+3])
			}
		case !pathChar(c):
			return "", "", fmt.Errorf("the path has the character %q", c)
		}
	}
	dec, err := url.PathUnescape(raw)
	if err != nil {
		return "", "", errors.New("the path has a broken percent-escape")
	}
	if strings.Contains(dec, "//") {
		return "", "", errors.New("the path has an empty segment")
	}
	if len(dec) > 1 && strings.HasSuffix(dec, "/") {
		return "", "", errors.New("the path ends with a slash")
	}
	for _, s := range strings.Split(dec, "/")[1:] {
		if s == "." || s == ".." {
			return "", "", errors.New("the path has a . or .. segment")
		}
	}
	if m := versionRe.FindString(dec); m != "" {
		prefix = strings.TrimSuffix(m, "/")
		dec = "/" + dec[len(m):]
	}
	return prefix, dec, nil
}

func pathChar(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	return strings.IndexByte("._~:@/+-", c) >= 0
}

// match finds the endpoint for method and the canonical path.
func match(method, p string) *endpoint {
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for _, e := range endpoints {
		if e.method == method && matchSegs(e.segs, segs) {
			return e
		}
	}
	return nil
}

func matchSegs(pat, segs []string) bool {
	for i, p := range pat {
		if p == "{name...}" {
			// One or more segments, then exactly the rest of the pattern.
			rest := pat[i+1:]
			n := len(segs) - i - len(rest)
			return n >= 1 && matchSegs(rest, segs[i+n:])
		}
		if i >= len(segs) {
			return false
		}
		if p == "{id}" || p == "{name}" {
			if segs[i] == "" {
				return false
			}
			continue
		}
		if p != segs[i] {
			return false
		}
	}
	return len(pat) == len(segs)
}

// checkQuery parses the raw query and refuses a parameter the endpoint
// does not take, or one repeated that may not be. It returns the values
// to forward, which are re-encoded from what was checked.
func (e *endpoint) checkQueryString(raw string) (url.Values, error) {
	v, err := url.ParseQuery(raw)
	if err != nil {
		return nil, fmt.Errorf("the query does not parse: %v", err)
	}
	for k, vals := range v {
		multi, ok := e.query[k]
		if !ok {
			return nil, fmt.Errorf("unknown query parameter %q", k)
		}
		if len(vals) > 1 && !multi {
			return nil, fmt.Errorf("the query parameter %q is repeated", k)
		}
	}
	if e.checkQuery != nil {
		if err := e.checkQuery(v); err != nil {
			return nil, err
		}
	}
	return v, nil
}

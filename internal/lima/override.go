package lima

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// proxyVars are the keys Lima itself derives from the host (limactl's
// environment or the macOS proxy settings) and drops when set to "" in env.
var proxyVars = []string{"http_proxy", "https_proxy", "ftp_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "NO_PROXY"}

// overrideProxyVars adds the names Lima never generates but copies verbatim
// from an override's env map. Setting them to "" in the template would not
// drop them, it would write an empty assignment, so they are only refused.
var overrideProxyVars = append([]string{"all_proxy", "ALL_PROXY"}, proxyVars...)

// trustVars are set by devkit in /etc/environment so non-login sessions use
// the system trust store. Lima's block comes after devkit's lines, so an
// override env entry with one of these names, even empty, would win.
var trustVars = []string{"SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "PIP_CERT", "NODE_OPTIONS"}

// CheckOverride refuses to continue when ~/.lima/_config/override.yaml would
// put a host proxy into the guest. That file takes precedence over the
// instance config devkit renders, so the template's own suppression cannot
// win against it; a proxy there would land in Lima's /etc/environment block,
// behind devkit's own settings, and change on every boot.
func CheckOverride() error {
	return CheckOverrideFile(filepath.Join(Home(), "_config", "override.yaml"))
}

// CheckOverrideFile is CheckOverride for a given file; a missing file is fine.
func CheckOverrideFile(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var doc struct {
		PropagateProxyEnv *bool             `yaml:"propagateProxyEnv"`
		Env               map[string]string `yaml:"env"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	var bad []string
	if doc.PropagateProxyEnv != nil && *doc.PropagateProxyEnv {
		bad = append(bad, "propagateProxyEnv: true")
	}
	for _, k := range overrideProxyVars {
		if v, ok := doc.Env[k]; ok && v != "" {
			bad = append(bad, "env."+k)
		}
	}
	for _, k := range trustVars {
		if _, ok := doc.Env[k]; ok {
			bad = append(bad, "env."+k)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("%s sets %s, which would override the sandbox's proxy or trust settings; devkit's proxy is the only egress and the system store is the only trust, so remove it from the override", path, strings.Join(bad, ", "))
}

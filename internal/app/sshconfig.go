package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/jurajpiar/devkit/internal/project"
)

func sshConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", "config")
}

func sshBlock(cfg *project.Config) string {
	return fmt.Sprintf(`# BEGIN devkit %[1]s (managed by devkit, do not edit)
Host %[2]s
  HostName 127.0.0.1
  Port %[3]d
  User %[4]s
  IdentityFile "%[5]s"
  IdentitiesOnly yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
  ForwardAgent no
# Reset the scope so settings that follow in this file stay global.
Host *
# END devkit %[1]s
`, cfg.Name, cfg.SSHHost(), cfg.SSHPort, hostUser(), filepath.Join(lima.Home(), "_config", "user"))
}

// writeSSHConfig adds or replaces the project's Host block in ~/.ssh/config.
// The block goes at the top: OpenSSH keeps the first value it sees for an
// option, so a later "Host *" with Port or User must not win over ours. The
// block ends with a bare "Host *" because comments do not close a Host
// section; without it, global options that used to sit at the top of the
// file would apply only to the devkit host. Agent forwarding is disabled
// explicitly so a global "ForwardAgent yes" never reaches the sandbox.
func writeSSHConfig(cfg *project.Config) error {
	path := sshConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	rest := strings.TrimLeft(removeSSHBlock(string(existing), cfg.Name), "\n")
	content := sshBlock(cfg)
	if rest != "" {
		content += "\n" + rest
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

// removeSSHConfig drops the project's Host block, if present.
func removeSSHConfig(name string) error {
	path := sshConfigPath()
	existing, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	updated := removeSSHBlock(string(existing), name)
	if updated == string(existing) {
		return nil
	}
	return os.WriteFile(path, []byte(updated), 0o600)
}

func removeSSHBlock(content, name string) string {
	begin := fmt.Sprintf("# BEGIN devkit %s ", name)
	end := fmt.Sprintf("# END devkit %s\n", name)
	for {
		i := strings.Index(content, begin)
		if i < 0 {
			return strings.TrimRight(content, "\n") + "\n"
		}
		j := strings.Index(content[i:], end)
		if j < 0 {
			return content
		}
		content = content[:i] + content[i+j+len(end):]
		content = strings.TrimRight(content, "\n")
		if content == "" {
			return ""
		}
		content += "\n"
	}
}

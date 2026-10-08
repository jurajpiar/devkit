package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jurajpiar/devkit/internal/project"
)

func sshConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", "config")
}

func sshBlock(cfg *project.Config) string {
	home, _ := os.UserHomeDir()
	return fmt.Sprintf(`# BEGIN devkit %[1]s (managed by devkit, do not edit)
Host %[2]s
  HostName 127.0.0.1
  Port %[3]d
  User %[4]s
  IdentityFile %[5]s
  IdentitiesOnly yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
# END devkit %[1]s
`, cfg.Name, cfg.SSHHost(), cfg.SSHPort, hostUser(), filepath.Join(home, ".lima", "_config", "user"))
}

// writeSSHConfig adds or replaces the project's Host block in ~/.ssh/config.
func writeSSHConfig(cfg *project.Config) error {
	path := sshConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	existing, _ := os.ReadFile(path)
	content := removeSSHBlock(string(existing), cfg.Name)
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if content != "" {
		content += "\n"
	}
	content += sshBlock(cfg)
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

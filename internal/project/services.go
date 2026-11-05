package project

import (
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Services are databases and the like that devkit runs inside the VM, so a
// project needs neither a container engine nor anything on the Mac. Each
// runs as the sandbox user and listens only on the VM's own 127.0.0.1.
//
// In devkit.yaml either a list, services: [postgres], which takes the
// defaults, or a map with settings per service.
type Services struct {
	Postgres *Postgres `yaml:"postgres,omitempty"`
}

// Postgres is Ubuntu's PostgreSQL 16 with one login role and database.
// The credentials are for development inside the VM, where nothing but the
// sandbox can reach the port.
type Postgres struct {
	Port     int    `yaml:"port,omitempty"`
	User     string `yaml:"user,omitempty"`
	Password string `yaml:"password,omitempty"`
	Database string `yaml:"database,omitempty"`
}

// PostgresPackage is the Ubuntu 24.04 package providing the server.
const PostgresPackage = "postgresql-16"

// Any returns whether a service is enabled.
func (s Services) Any() bool { return s.Postgres != nil }

// URL is the connection string for the app.
func (p *Postgres) URL() string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%d/%s", p.User, p.Password, p.Port, p.Database)
}

// UnmarshalYAML accepts the list form and the map form.
func (s *Services) UnmarshalYAML(n *yaml.Node) error {
	enable := func(name string, opts *yaml.Node) error {
		switch name {
		case "postgres":
			if s.Postgres != nil {
				return fmt.Errorf("services: postgres listed twice")
			}
			pg := &Postgres{}
			if opts != nil && opts.Kind == yaml.MappingNode {
				for i := 0; i+1 < len(opts.Content); i += 2 {
					switch k := opts.Content[i].Value; k {
					case "port", "user", "password", "database":
					default:
						return fmt.Errorf("services: postgres has no setting %q (port, user, password, database)", k)
					}
				}
				if err := opts.Decode(pg); err != nil {
					return fmt.Errorf("services: postgres: %w", err)
				}
			} else if opts != nil && !(opts.Kind == yaml.ScalarNode && opts.Tag == "!!null") {
				return fmt.Errorf("services: postgres takes a map of settings")
			}
			s.Postgres = pg
			return nil
		}
		return fmt.Errorf("services: unknown service %q (supported: postgres)", name)
	}
	switch n.Kind {
	case yaml.SequenceNode:
		for _, item := range n.Content {
			if item.Kind != yaml.ScalarNode {
				return fmt.Errorf("services: list entries are service names")
			}
			if err := enable(item.Value, nil); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if err := enable(n.Content[i].Value, n.Content[i+1]); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("services: a list such as [postgres], or a map of settings")
	}
	return nil
}

var (
	pgIdent    = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	pgPassword = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)
)

// applyDefaults fills unset settings.
func (s *Services) applyDefaults() {
	if p := s.Postgres; p != nil {
		if p.Port == 0 {
			p.Port = 5432
		}
		if p.User == "" {
			p.User = "dev"
		}
		if p.Password == "" {
			p.Password = "dev"
		}
		if p.Database == "" {
			p.Database = "dev"
		}
	}
}

// validate keeps every value safe to place in shell, SQL and a URL without
// quoting rules of its own.
func (s *Services) validate() error {
	p := s.Postgres
	if p == nil {
		return nil
	}
	if p.Port < 1024 || p.Port > 65535 {
		return fmt.Errorf("services: postgres port %d must be 1024-65535", p.Port)
	}
	if !pgIdent.MatchString(p.User) {
		return fmt.Errorf("services: postgres user %q must be lowercase letters, digits and underscores", p.User)
	}
	if !pgIdent.MatchString(p.Database) {
		return fmt.Errorf("services: postgres database %q must be lowercase letters, digits and underscores", p.Database)
	}
	if !pgPassword.MatchString(p.Password) {
		return fmt.Errorf("services: postgres password may use letters, digits and . _ ~ - only")
	}
	return nil
}

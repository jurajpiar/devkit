package app

import (
	"context"
	"fmt"

	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/jurajpiar/devkit/internal/project"
)

// pgBin is where Ubuntu 24.04's postgresql-16 package puts the server.
const pgBin = "/usr/lib/postgresql/16/bin"

// startServices runs the services script in the VM: it sets up and starts
// what devkit.yaml enables, and stops what it no longer does.
func startServices(ctx context.Context, cfg *project.Config) error {
	if cfg.Services.Postgres != nil {
		fmt.Println("Starting services")
	}
	if err := lima.ExecStream(ctx, cfg.VMName(), servicesScript(cfg)); err != nil {
		return fmt.Errorf("services: %w", err)
	}
	return nil
}

// servicesScript is what the sandbox user runs on every devkit up.
//
// postgres: a cluster the sandbox user owns, in its home, served by a
// systemd user unit (lingering starts it at boot) that listens only on the
// VM's 127.0.0.1, with its socket in the user's runtime directory. The
// sandbox user administers it as its superuser over that socket (peer
// authentication); the app connects over TCP as the configured role, with
// a password. Settings are validated by package project, so they need no
// quoting of their own in shell, SQL or the URL.
func servicesScript(cfg *project.Config) string {
	pg := cfg.Services.Postgres
	if pg == nil {
		return `unit="$HOME/.config/systemd/user/devkit-postgres.service"
if [ -f "$unit" ]; then
  systemctl --user disable --now devkit-postgres.service >/dev/null 2>&1 || true
  rm -f "$unit"
  systemctl --user daemon-reload
  echo "Stopped the postgres service (no longer in devkit.yaml); ~/.local/share/devkit/postgres keeps its data"
fi`
	}
	role := fmt.Sprintf(`DO $do$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '%[1]s') THEN
    CREATE ROLE "%[1]s" LOGIN PASSWORD '%[2]s';
  ELSE
    ALTER ROLE "%[1]s" LOGIN PASSWORD '%[2]s';
  END IF;
END $do$;`, pg.User, pg.Password)
	return fmt.Sprintf(`set -e
PG=%[1]s
DATA="$HOME/.local/share/devkit/postgres"
UNIT="$HOME/.config/systemd/user/devkit-postgres.service"
SOCK="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
PORT=%[2]d
[ -x "$PG/postgres" ] || { echo "PostgreSQL is not installed; provisioning installs it" >&2; exit 1; }
if [ ! -s "$DATA/PG_VERSION" ]; then
  mkdir -p "$DATA"
  chmod 700 "$DATA"
  "$PG/initdb" -D "$DATA" -U "$(id -un)" --auth-local=peer --auth-host=scram-sha-256 -E UTF8 >/dev/null
fi
mkdir -p "$(dirname "$UNIT")"
new="$(mktemp)"
cat > "$new" <<EOF
[Unit]
Description=devkit: PostgreSQL for the workspace (services: postgres)

[Service]
ExecStart=$PG/postgres -D $DATA -p $PORT -k %%t -c listen_addresses=127.0.0.1
Restart=on-failure

[Install]
WantedBy=default.target
EOF
changed=1
if cmp -s "$new" "$UNIT"; then changed=0; rm -f "$new"; else mv "$new" "$UNIT"; fi
systemctl --user daemon-reload
systemctl --user enable -q devkit-postgres.service
if [ "$changed" = 1 ]; then systemctl --user restart devkit-postgres.service; else systemctl --user start devkit-postgres.service; fi
for _ in $(seq 1 30); do
  "$PG/pg_isready" -q -h "$SOCK" -p "$PORT" && break
  sleep 1
done
if ! "$PG/pg_isready" -q -h "$SOCK" -p "$PORT"; then
  journalctl --user -u devkit-postgres.service -n 20 --no-pager >&2 || true
  echo "PostgreSQL did not start" >&2
  exit 1
fi
"$PG/psql" -h "$SOCK" -p "$PORT" -d postgres -v ON_ERROR_STOP=1 -q <<'SQL'
%[3]s
SQL
old="$("$PG/psql" -h "$SOCK" -p "$PORT" -d postgres -tAc "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '%[4]s'")"
if [ -z "$old" ]; then
  "$PG/createdb" -h "$SOCK" -p "$PORT" -O %[5]s %[4]s
elif [ "$old" != %[5]s ]; then
  # The configured user changed: the database and what is in it follow, or
  # migrations would fail against objects the new role does not own.
  "$PG/psql" -h "$SOCK" -p "$PORT" -d postgres -v ON_ERROR_STOP=1 -q <<EOF
ALTER DATABASE "%[4]s" OWNER TO "%[5]s";
EOF
  if [ "$old" != "$(id -un)" ]; then
    "$PG/psql" -h "$SOCK" -p "$PORT" -d %[4]s -v ON_ERROR_STOP=1 -q <<EOF
REASSIGN OWNED BY "$old" TO "%[5]s";
EOF
  fi
  echo "Database %[4]s now belongs to %[5]s (was $old)"
fi
echo "PostgreSQL 16 on 127.0.0.1:$PORT: %[6]s"
`, pgBin, pg.Port, role, pg.Database, pg.User, pg.URL())
}

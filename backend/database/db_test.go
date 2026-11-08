package database

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestPoolConfig checks that the database settings are used exactly as given, even with characters
// a connection string treats specially, and that every connection attempt goes to the given host
func TestPoolConfig(t *testing.T) {
	// pgx reads the TLS mode from the environment, so clear it to check the default
	t.Setenv("PGSSLMODE", "")

	for name, c := range map[string]struct{ username, password, host, port, name string }{
		"defaults":          {"postgres", "password", "localhost", "5432", "postgres"},
		"url characters":    {"user@x", "a/b#c%d?e@f:g", "db.example.com", "6543", "x/y"},
		"quotes and spaces": {"user name", `it's \ "x"`, `/tmp/it's a \ dir`, "5432", "my db"},
		"ipv6 host":         {"postgres", "password", "::1", "5432", "postgres"},
	} {
		t.Run(name, func(t *testing.T) {
			config, err := poolConfig(c.username, c.password, c.host, c.port, c.name)
			if err != nil {
				t.Fatalf("error making config: %v", err)
			}

			conn := config.ConnConfig
			got := []string{conn.User, conn.Password, conn.Host, strconv.Itoa(int(conn.Port)), conn.Database}
			want := []string{c.username, c.password, c.host, c.port, c.name}
			if !slices.Equal(got, want) {
				t.Errorf("got settings %q, want %q", got, want)
			}

			for _, fallback := range conn.Fallbacks {
				if fallback.Host != c.host {
					t.Errorf("falls back to host %q", fallback.Host)
				}
			}
			// TLS is tried first over TCP, as pgx does by default (sslmode=prefer), but never over a
			// Unix socket
			if isSocket := strings.HasPrefix(c.host, "/"); isSocket != (conn.TLSConfig == nil) {
				t.Errorf("TLS config is %v for host %q", conn.TLSConfig, c.host)
			}
		})
	}

	if _, err := poolConfig("postgres", "password", "localhost", "not a port", "postgres"); err == nil {
		t.Error("an invalid port was accepted")
	}
}

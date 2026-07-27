package config

import (
	"strings"
	"testing"
)

// RFC 5737 documentation addresses only.
func setGood(t *testing.T) {
	t.Setenv("PICKLE_RELAY_TARGET_CIDR", "192.0.2.0/24")
	t.Setenv("PICKLE_RELAY_PUBLIC_BAND", "10000-19999")
	t.Setenv("PICKLE_RELAY_PUBLIC_IFACE", "eth0")
	t.Setenv("STATE_DIRECTORY", t.TempDir())
}

func TestLoadGood(t *testing.T) {
	setGood(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Limits.BandMin != 10000 || c.Limits.BandMax != 19999 {
		t.Fatalf("band = %d-%d", c.Limits.BandMin, c.Limits.BandMax)
	}
	if c.SnapshotMaxAge.Hours() != 24 {
		t.Fatalf("default max age = %v", c.SnapshotMaxAge)
	}
	if !strings.HasSuffix(c.SnapshotPath(), "/snapshot.json") {
		t.Fatalf("snapshot path = %s", c.SnapshotPath())
	}
}

func TestLoadFailsClosed(t *testing.T) {
	// each required env missing → refuse to start (no in-code defaults for
	// firewall-shaping values)
	for _, missing := range []string{
		"PICKLE_RELAY_TARGET_CIDR",
		"PICKLE_RELAY_PUBLIC_BAND",
		"PICKLE_RELAY_PUBLIC_IFACE",
		"STATE_DIRECTORY",
	} {
		t.Run(missing, func(t *testing.T) {
			setGood(t)
			t.Setenv(missing, "")
			if _, err := Load(); err == nil {
				t.Fatalf("missing %s accepted", missing)
			}
		})
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	cases := map[string][2]string{
		"v6 cidr":       {"PICKLE_RELAY_TARGET_CIDR", "2001:db8::/32"},
		"cidr garbage":  {"PICKLE_RELAY_TARGET_CIDR", "not-a-cidr"},
		"band reversed": {"PICKLE_RELAY_PUBLIC_BAND", "19999-10000"},
		"band garbage":  {"PICKLE_RELAY_PUBLIC_BAND", "many"},
		"band zero":     {"PICKLE_RELAY_PUBLIC_BAND", "0-100"},
		"iface long":    {"PICKLE_RELAY_PUBLIC_IFACE", "waaaaaaaaaaaaaaaaytoolong"},
		"poll low":      {"PICKLE_RELAY_POLL_SECONDS", "1"},
		"age zero":      {"PICKLE_RELAY_SNAPSHOT_MAX_AGE_HOURS", "0"},
	}
	for name, kv := range cases {
		t.Run(name, func(t *testing.T) {
			setGood(t)
			t.Setenv(kv[0], kv[1])
			if _, err := Load(); err == nil {
				t.Fatalf("%s=%q accepted", kv[0], kv[1])
			}
		})
	}
}

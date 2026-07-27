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
	t.Setenv("PICKLE_RELAY_SNAPSHOT_MAX_AGE_HOURS", "24")
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
	// guard defaults (conservative, tighten-only)
	if c.Guards.MaxConn != 512 || c.Guards.NewConnRate != 200 || c.Guards.NewConnBurst != 400 {
		t.Fatalf("guard defaults = %+v, want 512/200/400", c.Guards)
	}
}

func TestGuardEnvOverridesAndDisable(t *testing.T) {
	setGood(t)
	t.Setenv("PICKLE_RELAY_CT_MAX_PER_MAPPING", "0") // disable connlimit
	t.Setenv("PICKLE_RELAY_NEW_CONN_RATE", "1000")   // override
	t.Setenv("PICKLE_RELAY_NEW_CONN_BURST", "0")     // strict rate, no burst
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Guards.MaxConn != 0 || c.Guards.NewConnRate != 1000 || c.Guards.NewConnBurst != 0 {
		t.Fatalf("guards = %+v, want 0/1000/0", c.Guards)
	}
}

func TestGuardEnvRejectsBad(t *testing.T) {
	for _, v := range []string{"abc", "-1", "4294967296"} { // non-int, negative, >uint32
		t.Run(v, func(t *testing.T) {
			setGood(t)
			t.Setenv("PICKLE_RELAY_CT_MAX_PER_MAPPING", v)
			if _, err := Load(); err == nil {
				t.Fatalf("ct max %q accepted", v)
			}
		})
	}
}

func TestLoadFailsClosed(t *testing.T) {
	// each required env missing → refuse to start (no in-code defaults for
	// firewall-shaping values)
	for _, missing := range []string{
		"PICKLE_RELAY_TARGET_CIDR",
		"PICKLE_RELAY_PUBLIC_BAND",
		"PICKLE_RELAY_PUBLIC_IFACE",
		"PICKLE_RELAY_SNAPSHOT_MAX_AGE_HOURS",
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
		"v6 cidr":                             {"PICKLE_RELAY_TARGET_CIDR", "2001:db8::/32"},
		"cidr garbage":                        {"PICKLE_RELAY_TARGET_CIDR", "not-a-cidr"},
		"band reversed":                       {"PICKLE_RELAY_PUBLIC_BAND", "19999-10000"},
		"band garbage":                        {"PICKLE_RELAY_PUBLIC_BAND", "many"},
		"band zero":                           {"PICKLE_RELAY_PUBLIC_BAND", "0-100"},
		"band below floor (would shadow SSH)": {"PICKLE_RELAY_PUBLIC_BAND", "22-19999"},
		"iface long":                          {"PICKLE_RELAY_PUBLIC_IFACE", "waaaaaaaaaaaaaaaaytoolong"},
		"poll low":                            {"PICKLE_RELAY_POLL_SECONDS", "1"},
		"age zero":                            {"PICKLE_RELAY_SNAPSHOT_MAX_AGE_HOURS", "0"},
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

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
		"band includes admin sshd 2222":       {"PICKLE_RELAY_PUBLIC_BAND", "2000-19999"},
		"band includes wireguard 51820":       {"PICKLE_RELAY_PUBLIC_BAND", "50000-59999"},
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

func TestPerSourceGuardDefaultsAndDisable(t *testing.T) {
	setGood(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Guards.PerSourceRate != 50 || c.Guards.PerSourceBurst != 100 {
		t.Fatalf("per-source defaults = %d/%d, want 50/100", c.Guards.PerSourceRate, c.Guards.PerSourceBurst)
	}

	t.Setenv("PICKLE_RELAY_PER_SOURCE_RATE", "0") // disable
	t.Setenv("PICKLE_RELAY_PER_SOURCE_BURST", "250")
	c, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Guards.PerSourceRate != 0 || c.Guards.PerSourceBurst != 250 {
		t.Fatalf("per-source guards = %d/%d, want 0/250", c.Guards.PerSourceRate, c.Guards.PerSourceBurst)
	}

	t.Setenv("PICKLE_RELAY_PER_SOURCE_RATE", "abc")
	if _, err := Load(); err == nil {
		t.Fatal("bad per-source rate accepted")
	}
}

func TestSyncEnvPairing(t *testing.T) {
	// URL + token together: valid, both http and https schemes
	for _, u := range []string{"https://api.example.test/internal/relays/1/sync", "http://192.0.2.10:8080/internal/relays/1/sync"} {
		setGood(t)
		t.Setenv("PICKLE_RELAY_SYNC_URL", u)
		t.Setenv("PICKLE_RELAY_SYNC_TOKEN", "aabbcc")
		c, err := Load()
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		if c.SyncURL != u || c.SyncToken != "aabbcc" {
			t.Fatalf("sync config = %q/%q", c.SyncURL, c.SyncToken)
		}
	}

	// URL without token: refuse
	setGood(t)
	t.Setenv("PICKLE_RELAY_SYNC_URL", "https://api.example.test/sync")
	t.Setenv("PICKLE_RELAY_SYNC_TOKEN", "")
	if _, err := Load(); err == nil {
		t.Fatal("URL without token accepted")
	}
	// token without URL: refuse (a token with nowhere to go is a config bug)
	setGood(t)
	t.Setenv("PICKLE_RELAY_SYNC_URL", "")
	t.Setenv("PICKLE_RELAY_SYNC_TOKEN", "aabbcc")
	if _, err := Load(); err == nil {
		t.Fatal("token without URL accepted")
	}
}

func TestSyncEnvRejectsBadValues(t *testing.T) {
	cases := map[string][2]string{
		"scheme ftp":     {"PICKLE_RELAY_SYNC_URL", "ftp://api.example.test/sync"},
		"scheme missing": {"PICKLE_RELAY_SYNC_URL", "api.example.test/sync"},
		"host missing":   {"PICKLE_RELAY_SYNC_URL", "https:///sync"},
		"url garbage":    {"PICKLE_RELAY_SYNC_URL", "http://exa mple/sync"},
		"token newline":  {"PICKLE_RELAY_SYNC_TOKEN", "aa\nbb"},
		"token escape":   {"PICKLE_RELAY_SYNC_TOKEN", "aa\x1bbb"},
		"token del char": {"PICKLE_RELAY_SYNC_TOKEN", "aa\x7fbb"},
	}
	for name, kv := range cases {
		t.Run(name, func(t *testing.T) {
			setGood(t)
			t.Setenv("PICKLE_RELAY_SYNC_URL", "https://api.example.test/sync")
			t.Setenv("PICKLE_RELAY_SYNC_TOKEN", "goodtoken")
			t.Setenv(kv[0], kv[1])
			if _, err := Load(); err == nil {
				t.Fatalf("%s=%q accepted", kv[0], kv[1])
			}
		})
	}
}

func TestSyncSourceFileExclusion(t *testing.T) {
	setGood(t)
	t.Setenv("PICKLE_RELAY_SYNC_URL", "https://api.example.test/sync")
	t.Setenv("PICKLE_RELAY_SYNC_TOKEN", "aabbcc")
	t.Setenv("PICKLE_RELAY_SOURCE_FILE", "/tmp/snapshot.json")
	if _, err := Load(); err == nil {
		t.Fatal("sync URL and source file together accepted")
	}
}

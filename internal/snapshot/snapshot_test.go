package snapshot

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// All fixture addresses are RFC 5737 documentation ranges.
func testLimits() Limits {
	return Limits{
		TargetCIDR: netip.MustParsePrefix("192.0.2.0/24"),
		BandMin:    10000,
		BandMax:    19999,
	}
}

const goodJSON = `{
  "generation": 7,
  "mappings": [
    {"id": 1, "proto": "tcp", "publicPort": 10080, "targetAddr": "192.0.2.23", "targetPort": 80},
    {"id": 2, "proto": "udp", "publicPort": 10080, "targetAddr": "192.0.2.23", "targetPort": 5353}
  ]
}`

func TestParseGood(t *testing.T) {
	s, err := Parse([]byte(goodJSON), testLimits())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Generation != 7 || len(s.Mappings) != 2 {
		t.Fatalf("unexpected snapshot: %+v", s)
	}
	if s.Mappings[0].Target() != netip.MustParseAddr("192.0.2.23") {
		t.Fatalf("target not parsed: %v", s.Mappings[0].Target())
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":     `{"generation":1,"mappings":[],"extra":true}`,
		"negative gen":      `{"generation":-1,"mappings":[]}`,
		"bad proto":         `{"generation":1,"mappings":[{"id":1,"proto":"sctp","publicPort":10000,"targetAddr":"192.0.2.1","targetPort":1}]}`,
		"port below band":   `{"generation":1,"mappings":[{"id":1,"proto":"tcp","publicPort":9999,"targetAddr":"192.0.2.1","targetPort":1}]}`,
		"port above band":   `{"generation":1,"mappings":[{"id":1,"proto":"tcp","publicPort":20000,"targetAddr":"192.0.2.1","targetPort":1}]}`,
		"target port zero":  `{"generation":1,"mappings":[{"id":1,"proto":"tcp","publicPort":10000,"targetAddr":"192.0.2.1","targetPort":0}]}`,
		"garbage addr":      `{"generation":1,"mappings":[{"id":1,"proto":"tcp","publicPort":10000,"targetAddr":"not-an-ip","targetPort":1}]}`,
		"ipv6 target":       `{"generation":1,"mappings":[{"id":1,"proto":"tcp","publicPort":10000,"targetAddr":"2001:db8::1","targetPort":1}]}`,
		"outside whitelist": `{"generation":1,"mappings":[{"id":1,"proto":"tcp","publicPort":10000,"targetAddr":"198.51.100.9","targetPort":1}]}`,
		"duplicate":         `{"generation":1,"mappings":[{"id":1,"proto":"tcp","publicPort":10000,"targetAddr":"192.0.2.1","targetPort":1},{"id":2,"proto":"tcp","publicPort":10000,"targetAddr":"192.0.2.2","targetPort":2}]}`,
	}
	for name, js := range cases {
		if _, err := Parse([]byte(js), testLimits()); err == nil {
			t.Errorf("%s: accepted, want error", name)
		}
	}
}

func TestPersistRoundTripAndAgeBound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.json")
	s, err := Parse([]byte(goodJSON), testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Persist(path); err != nil {
		t.Fatalf("persist: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, want 0640", fi.Mode().Perm())
	}

	got, err := LoadPersisted(path, testLimits(), 24*time.Hour, time.Now())
	if err != nil {
		t.Fatalf("load fresh: %v", err)
	}
	if got.Generation != 7 {
		t.Fatalf("generation = %d", got.Generation)
	}

	// beyond the window: must be rejected as stale (bounded fail-open)
	_, err = LoadPersisted(path, testLimits(), 24*time.Hour, time.Now().Add(25*time.Hour))
	if !errors.Is(err, ErrStale) {
		t.Fatalf("want ErrStale, got %v", err)
	}

	// future persistedAt (clock behind at boot): must fail closed, NOT pass as
	// fresh on a negative age.
	_, err = LoadPersisted(path, testLimits(), 24*time.Hour, time.Now().Add(-time.Hour))
	if err == nil || !strings.Contains(err.Error(), "future") {
		t.Fatalf("want future-timestamp rejection, got %v", err)
	}
}

func TestParseRejectsNullAndTrailing(t *testing.T) {
	for name, js := range map[string]string{
		"null body":     "null",
		"null spaced":   "  null\n",
		"trailing data": `{"generation":1,"mappings":[]}{"x":1}`,
	} {
		if _, err := Parse([]byte(js), testLimits()); err == nil {
			t.Errorf("%s: accepted, want error", name)
		}
	}
	// an explicit empty set stays valid
	if _, err := Parse([]byte(`{"generation":9,"mappings":[]}`), testLimits()); err != nil {
		t.Fatalf("explicit empty set rejected: %v", err)
	}
}

func TestLoadPersistedRevalidates(t *testing.T) {
	// a persisted file whose target fell outside the (changed) whitelist
	// must be rejected on load — the file is firewall config
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.json")
	s, err := Parse([]byte(goodJSON), testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Persist(path); err != nil {
		t.Fatal(err)
	}
	narrow := testLimits()
	narrow.TargetCIDR = netip.MustParsePrefix("203.0.113.0/24")
	if _, err := LoadPersisted(path, narrow, 24*time.Hour, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "outside allowed") {
		t.Fatalf("want whitelist rejection, got %v", err)
	}
}

func TestPersistMissingPersistedAt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(path, []byte(goodJSON), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPersisted(path, testLimits(), 24*time.Hour, time.Now()); err == nil {
		t.Fatal("accepted snapshot without persistedAt")
	}
}

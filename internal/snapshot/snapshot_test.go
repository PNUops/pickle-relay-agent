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
		"gen 0 non-empty":   `{"generation":0,"mappings":[{"id":1,"proto":"tcp","publicPort":10000,"targetAddr":"192.0.2.1","targetPort":1}]}`,
		"duplicate id":      `{"generation":1,"mappings":[{"id":1,"proto":"tcp","publicPort":10000,"targetAddr":"192.0.2.1","targetPort":1},{"id":1,"proto":"udp","publicPort":10001,"targetAddr":"192.0.2.2","targetPort":2}]}`,
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
		"null body":        "null",
		"null spaced":      "  null\n",
		"trailing data":    `{"generation":1,"mappings":[]}{"x":1}`,
		"mappings null":    `{"generation":4,"mappings":null}`,
		"mappings absent":  `{"generation":4}`,
		"generation alone": `{"generation":0}`,
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

func TestGuardOverrideRoundTrip(t *testing.T) {
	// omitted → nil, explicit 0 → disabled, value → override; and the
	// persisted copy must carry the overrides byte-identically through a
	// Persist/LoadPersisted round trip.
	js := `{
	  "generation": 3,
	  "mappings": [
	    {"id": 5, "proto": "tcp", "publicPort": 10443, "targetAddr": "192.0.2.40", "targetPort": 443,
	     "ctMax": 0, "newConnRate": 1000, "newConnBurst": 2000, "perSourceRate": 80, "perSourceBurst": 160},
	    {"id": 6, "proto": "udp", "publicPort": 10514, "targetAddr": "192.0.2.41", "targetPort": 514}
	  ]}`
	check := func(s *Snapshot) {
		t.Helper()
		m := s.Mappings[0]
		if m.CtMax == nil || *m.CtMax != 0 {
			t.Fatalf("ctMax = %v, want explicit 0", m.CtMax)
		}
		if m.NewConnRate == nil || *m.NewConnRate != 1000 || m.NewConnBurst == nil || *m.NewConnBurst != 2000 {
			t.Fatalf("newConn override = %v/%v, want 1000/2000", m.NewConnRate, m.NewConnBurst)
		}
		if m.PerSourceRate == nil || *m.PerSourceRate != 80 || m.PerSourceBurst == nil || *m.PerSourceBurst != 160 {
			t.Fatalf("perSource override = %v/%v, want 80/160", m.PerSourceRate, m.PerSourceBurst)
		}
		n := s.Mappings[1]
		if n.CtMax != nil || n.NewConnRate != nil || n.NewConnBurst != nil || n.PerSourceRate != nil || n.PerSourceBurst != nil {
			t.Fatalf("omitted overrides must stay nil: %+v", n)
		}
	}
	s, err := Parse([]byte(js), testLimits())
	if err != nil {
		t.Fatal(err)
	}
	check(s)

	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := s.Persist(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPersisted(path, testLimits(), 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	check(got)
}

func TestGuardOverrideRejects(t *testing.T) {
	head := `{"generation":1,"mappings":[{"id":9,"proto":"tcp","publicPort":10000,"targetAddr":"192.0.2.1","targetPort":1,`
	for name, tail := range map[string]string{
		"burst without rate":            `"newConnBurst":100}]}`,
		"burst with disabled rate":      `"newConnRate":0,"newConnBurst":100}]}`,
		"per-source burst without rate": `"perSourceBurst":100}]}`,
		"per-source burst zero rate":    `"perSourceRate":0,"perSourceBurst":100}]}`,
		"unknown guard field":           `"ctMaximum":1}]}`,
	} {
		if _, err := Parse([]byte(head+tail), testLimits()); err == nil {
			t.Errorf("%s: accepted, want error", name)
		}
	}
	// rate alone (no burst) stays valid, both families
	ok := head + `"newConnRate":500,"perSourceRate":25}]}`
	if _, err := Parse([]byte(ok), testLimits()); err != nil {
		t.Fatalf("rate-only override rejected: %v", err)
	}
}

func TestValidationErrorCarriesMappingID(t *testing.T) {
	js := `{"generation":1,"mappings":[
	  {"id":1,"proto":"tcp","publicPort":10000,"targetAddr":"192.0.2.1","targetPort":1},
	  {"id":77,"proto":"tcp","publicPort":10001,"targetAddr":"198.51.100.9","targetPort":1}]}`
	_, err := Parse([]byte(js), testLimits())
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationError, got %v", err)
	}
	if ve.MappingID != 77 {
		t.Fatalf("mapping id = %d, want 77", ve.MappingID)
	}
}

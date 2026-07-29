// Package snapshot defines the desired-state mapping snapshot: the sync
// response body, the applier input, and the persisted on-disk copy are all
// this one shape. The persisted file IS firewall configuration — everything
// is parsed into typed values and re-validated on every load, including
// before a boot-time re-apply.
package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// Proto is the transport protocol of a mapping.
type Proto string

const (
	ProtoTCP Proto = "tcp"
	ProtoUDP Proto = "udp"
)

// Mapping is one public-port → target DNAT entry.
type Mapping struct {
	ID         int64  `json:"id"`
	Proto      Proto  `json:"proto"`
	PublicPort uint16 `json:"publicPort"`
	TargetAddr string `json:"targetAddr"`
	TargetPort uint16 `json:"targetPort"`

	// Per-mapping guard overrides. nil (field omitted or null) keeps the
	// agent's env default; an explicit 0 disables that guard for this
	// mapping; any other value replaces the default. Overrides come from the
	// authenticated desired-state authority, so widening — including
	// disabling — is legitimate here: the tighten-only rule constrains the
	// agent-side DEFAULTS only (a default must never widen the surface).
	CtMax          *uint32 `json:"ctMax,omitempty"`
	NewConnRate    *uint64 `json:"newConnRate,omitempty"`
	NewConnBurst   *uint32 `json:"newConnBurst,omitempty"`
	PerSourceRate  *uint64 `json:"perSourceRate,omitempty"`
	PerSourceBurst *uint32 `json:"perSourceBurst,omitempty"`

	// target is the validated form of TargetAddr, set by Validate.
	target netip.Addr
}

// Target returns the validated target address. Only meaningful after
// Snapshot.Validate has succeeded.
func (m *Mapping) Target() netip.Addr { return m.target }

// Snapshot is the full desired mapping set at one generation.
type Snapshot struct {
	Generation int64     `json:"generation"`
	Mappings   []Mapping `json:"mappings"`

	// PersistedAt is set only on the on-disk copy (bounded fail-open check).
	PersistedAt time.Time `json:"persistedAt,omitzero"`
}

// Limits are the validation bounds. Both come from configuration — the agent
// refuses to run without them; there are no built-in defaults.
type Limits struct {
	// TargetCIDR is the only network mappings may point into.
	TargetCIDR netip.Prefix
	// BandMin/BandMax bound the public ports (inclusive).
	BandMin, BandMax uint16
}

// MaxMappings caps the snapshot size defensively; the band itself is the
// natural ceiling (one mapping per proto+port).
const MaxMappings = 65536

// ValidationError marks a validation failure attributable to one mapping, so
// callers can surface WHICH mapping was rejected (the sync report's error
// items carry a mappingId). Retrieve with errors.As.
type ValidationError struct {
	MappingID int64
	Err       error
}

func (e *ValidationError) Error() string { return fmt.Sprintf("mapping %d: %v", e.MappingID, e.Err) }
func (e *ValidationError) Unwrap() error { return e.Err }

// mappingErr wraps a per-mapping validation failure.
func mappingErr(id int64, format string, args ...any) error {
	return &ValidationError{MappingID: id, Err: fmt.Errorf(format, args...)}
}

// Validate checks every mapping against the limits and rejects duplicates.
// It mutates the receiver (fills the parsed target addresses).
func (s *Snapshot) Validate(lim Limits) error {
	if s.Generation < 0 {
		return fmt.Errorf("negative generation %d", s.Generation)
	}
	// Generation 0 is reserved for the empty/uninitialized set (the boot
	// converge-to-empty leaves appliedGeneration=0). A non-empty snapshot at
	// generation 0 would be silently skipped by the unchanged-generation
	// short-circuit — reject it so generations for real mappings start at 1.
	if s.Generation == 0 && len(s.Mappings) > 0 {
		return errors.New("generation 0 with non-empty mappings (real generations start at 1)")
	}
	// An empty desired set must be the EXPLICIT `"mappings": []` — an absent
	// or null mappings key decodes to the same nil slice a truncated or
	// mis-serialized body would, and applying it would flush every rule.
	// Reject so a serialization slip upstream cannot become a full outage.
	if s.Mappings == nil {
		return errors.New("mappings key absent or null (an empty set must be an explicit [])")
	}
	if len(s.Mappings) > MaxMappings {
		return fmt.Errorf("%d mappings exceeds cap %d", len(s.Mappings), MaxMappings)
	}
	seen := make(map[[2]any]struct{}, len(s.Mappings))
	for i := range s.Mappings {
		m := &s.Mappings[i]
		if m.Proto != ProtoTCP && m.Proto != ProtoUDP {
			return mappingErr(m.ID, "unknown proto %q", m.Proto)
		}
		if m.PublicPort < lim.BandMin || m.PublicPort > lim.BandMax {
			return mappingErr(m.ID, "public port %d outside band %d-%d",
				m.PublicPort, lim.BandMin, lim.BandMax)
		}
		if m.TargetPort == 0 {
			return mappingErr(m.ID, "target port 0")
		}
		addr, err := netip.ParseAddr(m.TargetAddr)
		if err != nil {
			return mappingErr(m.ID, "bad target address: %v", err)
		}
		if !addr.Is4() {
			return mappingErr(m.ID, "target %s is not IPv4", addr)
		}
		if !lim.TargetCIDR.Contains(addr) {
			return mappingErr(m.ID, "target %s outside allowed %s", addr, lim.TargetCIDR)
		}
		// A burst is meaningless without its rate: the guard is a token
		// bucket, so a burst override with the rate absent or explicitly
		// disabled (0) can only be a caller mistake — reject rather than
		// guess which limit was intended.
		if m.NewConnBurst != nil && (m.NewConnRate == nil || *m.NewConnRate == 0) {
			return mappingErr(m.ID, "newConnBurst requires a non-zero newConnRate")
		}
		if m.PerSourceBurst != nil && (m.PerSourceRate == nil || *m.PerSourceRate == 0) {
			return mappingErr(m.ID, "perSourceBurst requires a non-zero perSourceRate")
		}
		key := [2]any{m.Proto, m.PublicPort}
		if _, dup := seen[key]; dup {
			return mappingErr(m.ID, "duplicate %s public port %d", m.Proto, m.PublicPort)
		}
		seen[key] = struct{}{}
		m.target = addr
	}
	return nil
}

// Parse decodes and validates a snapshot from JSON bytes.
func Parse(data []byte, lim Limits) (*Snapshot, error) {
	// A bare `null` (or a truncated write) decodes to a zero-value Snapshot
	// without error — generation 0, no mappings — which would silently flush
	// every rule. Reject it outright; an empty desired set must be the
	// explicit `{"generation":N,"mappings":[]}` form.
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, errors.New("snapshot body is null")
	}
	var s Snapshot
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing data after snapshot JSON")
	}
	if err := s.Validate(lim); err != nil {
		return nil, err
	}
	return &s, nil
}

// Persist writes the snapshot to path atomically (temp file + rename, 0640
// under a 0750 state dir), stamping PersistedAt.
func (s *Snapshot) Persist(path string) error {
	cp := *s
	cp.PersistedAt = time.Now().UTC()
	data, err := json.Marshal(&cp)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".snapshot-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ErrStale marks a persisted snapshot older than the allowed window.
var ErrStale = errors.New("persisted snapshot older than the allowed window")

// LoadPersisted reads a persisted snapshot and enforces the bounded
// fail-open rule: a copy older than maxAge must NOT be re-applied (its
// targets may have been re-assigned to another tenant after quarantine) —
// callers converge to an empty set instead. Validation runs on every load.
func LoadPersisted(path string, lim Limits, maxAge time.Duration, now time.Time) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := Parse(data, lim)
	if err != nil {
		return nil, err
	}
	if s.PersistedAt.IsZero() {
		return nil, errors.New("persisted snapshot missing persistedAt")
	}
	// A future persistedAt would make now.Sub(persistedAt) negative and pass the
	// age check no matter how old the snapshot really is. Boot — before NTP
	// sync — is exactly when the clock is least trustworthy, so an impossible
	// (future) timestamp means the clock cannot be trusted to bound staleness:
	// fail closed rather than risk re-applying a beyond-quarantine snapshot
	// whose target IP may have been re-assigned to another tenant.
	if s.PersistedAt.After(now.Add(clockSkewTolerance)) {
		return nil, fmt.Errorf("persisted snapshot timestamp %s is in the future (clock untrusted)",
			s.PersistedAt.Format(time.RFC3339))
	}
	if now.Sub(s.PersistedAt) > maxAge {
		return nil, fmt.Errorf("%w (persisted %s, max age %s)", ErrStale,
			s.PersistedAt.Format(time.RFC3339), maxAge)
	}
	return s, nil
}

// clockSkewTolerance is the small grace allowed on a persisted timestamp before
// it is treated as impossible-future (and therefore clock-untrusted).
const clockSkewTolerance = 5 * time.Minute

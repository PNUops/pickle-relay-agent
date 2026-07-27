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

// Validate checks every mapping against the limits and rejects duplicates.
// It mutates the receiver (fills the parsed target addresses).
func (s *Snapshot) Validate(lim Limits) error {
	if s.Generation < 0 {
		return fmt.Errorf("negative generation %d", s.Generation)
	}
	if len(s.Mappings) > MaxMappings {
		return fmt.Errorf("%d mappings exceeds cap %d", len(s.Mappings), MaxMappings)
	}
	seen := make(map[[2]any]struct{}, len(s.Mappings))
	for i := range s.Mappings {
		m := &s.Mappings[i]
		if m.Proto != ProtoTCP && m.Proto != ProtoUDP {
			return fmt.Errorf("mapping %d: unknown proto %q", m.ID, m.Proto)
		}
		if m.PublicPort < lim.BandMin || m.PublicPort > lim.BandMax {
			return fmt.Errorf("mapping %d: public port %d outside band %d-%d",
				m.ID, m.PublicPort, lim.BandMin, lim.BandMax)
		}
		if m.TargetPort == 0 {
			return fmt.Errorf("mapping %d: target port 0", m.ID)
		}
		addr, err := netip.ParseAddr(m.TargetAddr)
		if err != nil {
			return fmt.Errorf("mapping %d: bad target address: %v", m.ID, err)
		}
		if !addr.Is4() {
			return fmt.Errorf("mapping %d: target %s is not IPv4", m.ID, addr)
		}
		if !lim.TargetCIDR.Contains(addr) {
			return fmt.Errorf("mapping %d: target %s outside allowed %s",
				m.ID, addr, lim.TargetCIDR)
		}
		key := [2]any{m.Proto, m.PublicPort}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("mapping %d: duplicate %s public port %d", m.ID, m.Proto, m.PublicPort)
		}
		seen[key] = struct{}{}
		m.target = addr
	}
	return nil
}

// Parse decodes and validates a snapshot from JSON bytes.
func Parse(data []byte, lim Limits) (*Snapshot, error) {
	var s Snapshot
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
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
	if now.Sub(s.PersistedAt) > maxAge {
		return nil, fmt.Errorf("%w (persisted %s, max age %s)", ErrStale,
			s.PersistedAt.Format(time.RFC3339), maxAge)
	}
	return s, nil
}

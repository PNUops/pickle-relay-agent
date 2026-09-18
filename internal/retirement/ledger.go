package retirement

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pnuops/pickle-relay-agent/internal/snapshot"
	"os"
	"path/filepath"
	"regexp"
)

const Capability = "mapping-retirement-v1"
const MaxOutstanding = 4096

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type Active struct {
	MappingID int64  `json:"mappingId"`
	FlowMark  uint32 `json:"flowMark"`
	TupleHash string `json:"tupleHash"`
}
type Entry struct {
	snapshot.Retirement
	Cleared bool `json:"cleared"`
}
type Ledger struct {
	Version                         int      `json:"version"`
	LedgerID                        string   `json:"retirementLedgerId"`
	Armed                           bool     `json:"armed"`
	MappingIDHighWater              int64    `json:"mappingIdHighWater"`
	FlowMarkHighWater               uint32   `json:"flowMarkHighWater"`
	RetirementHighWater             int64    `json:"retirementHighWater"`
	ManagedGenerationHighWater      int64    `json:"managedGenerationHighWater"`
	DesiredHash                     string   `json:"desiredHash"`
	AcknowledgedRetirementHighWater int64    `json:"acknowledgedRetirementHighWater"`
	Active                          []Active `json:"active"`
	Entries                         []Entry  `json:"entries"`
}

func New() (*Ledger, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return nil, e
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	h := hex.EncodeToString(b)
	return &Ledger{Version: 1, LedgerID: h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], Active: []Active{}, Entries: []Entry{}}, nil
}
func Load(p string) (*Ledger, error) {
	b, e := os.ReadFile(p)
	if e != nil {
		return nil, e
	}
	var l Ledger
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&l); e != nil {
		return nil, e
	}
	if e = l.Validate(); e != nil {
		return nil, e
	}
	return &l, nil
}
func (l *Ledger) Validate() error {
	if l.Version != 1 || !uuidPattern.MatchString(l.LedgerID) || l.Active == nil || l.Entries == nil {
		return errors.New("invalid retirement ledger identity")
	}
	if len(l.Entries) > MaxOutstanding {
		return fmt.Errorf("outstanding retirements exceed cap %d", MaxOutstanding)
	}
	ids := map[int64]bool{}
	marks := map[uint32]bool{}
	rids := map[string]bool{}
	for _, a := range l.Active {
		if a.MappingID <= 0 || a.MappingID > l.MappingIDHighWater || a.FlowMark == 0 || a.FlowMark > l.FlowMarkHighWater || len(a.TupleHash) != 64 || ids[a.MappingID] || marks[a.FlowMark] {
			return errors.New("invalid active epoch ledger")
		}
		ids[a.MappingID] = true
		marks[a.FlowMark] = true
	}
	for _, e := range l.Entries {
		r := e.Retirement
		if !uuidPattern.MatchString(r.RetirementID) || rids[r.RetirementID] || r.MappingID <= 0 || r.MappingID > l.MappingIDHighWater || r.FlowMark == 0 || r.FlowMark > l.FlowMarkHighWater || r.Generation > l.RetirementHighWater || snapshot.TupleHash(r.MappingID, r.Proto, r.PublicPort, r.TargetAddr, r.TargetPort, r.FlowMark) != r.TupleHash || ids[r.MappingID] || marks[r.FlowMark] {
			return errors.New("invalid outstanding retirement ledger")
		}
		rids[r.RetirementID] = true
		ids[r.MappingID] = true
		marks[r.FlowMark] = true
	}
	if l.AcknowledgedRetirementHighWater > l.RetirementHighWater {
		return errors.New("retirement acknowledgement exceeds high-water")
	}
	if l.Armed && (l.ManagedGenerationHighWater <= 0 || len(l.DesiredHash) != 64) {
		return errors.New("invalid managed generation identity")
	}
	return nil
}
func mappingHash(m snapshot.Mapping) string {
	return snapshot.TupleHash(m.ID, m.Proto, m.PublicPort, m.TargetAddr, m.TargetPort, *m.FlowMark)
}
func (l *Ledger) Prepare(s *snapshot.Snapshot) (*Ledger, error) {
	if s.Retirements == nil {
		if l.Armed {
			return nil, errors.New("armed retirement ledger received legacy snapshot")
		}
		return l, nil
	}
	b, _ := json.Marshal(l)
	var n Ledger
	_ = json.Unmarshal(b, &n)
	n.Armed = true
	hash := s.DesiredHash()
	if s.Generation < n.ManagedGenerationHighWater {
		return nil, errors.New("managed generation regressed")
	}
	if s.Generation == n.ManagedGenerationHighWater && n.DesiredHash != "" && n.DesiredHash != hash {
		return nil, errors.New("same managed generation changed content")
	}
	if s.Generation > n.ManagedGenerationHighWater {
		n.ManagedGenerationHighWater, n.DesiredHash = s.Generation, hash
	} else if n.DesiredHash == "" {
		n.DesiredHash = hash
	}
	ack := *s.AcknowledgedRetirementHighWater
	if ack < n.AcknowledgedRetirementHighWater || ack > n.RetirementHighWater {
		return nil, errors.New("retirement acknowledgement regressed or exceeded high-water")
	}
	kept := n.Entries[:0]
	for _, e := range n.Entries {
		if e.Generation <= ack {
			if !e.Cleared {
				return nil, errors.New("acknowledged retirement is not cleared")
			}
			continue
		}
		kept = append(kept, e)
	}
	n.Entries = kept
	n.AcknowledgedRetirementHighWater = ack
	old := map[int64]Active{}
	for _, a := range n.Active {
		old[a.MappingID] = a
	}
	next := []Active{}
	previousMappingHighWater, previousFlowHighWater := n.MappingIDHighWater, n.FlowMarkHighWater
	retired := map[int64]bool{}
	for _, e := range n.Entries {
		retired[e.MappingID] = true
	}
	for _, m := range s.Mappings {
		if m.FlowMark == nil {
			return nil, errors.New("managed mapping missing mark")
		}
		h := mappingHash(m)
		if a, ok := old[m.ID]; ok {
			if a.FlowMark != *m.FlowMark || a.TupleHash != h {
				return nil, fmt.Errorf("active epoch %d changed", m.ID)
			}
		} else {
			if m.ID <= previousMappingHighWater || *m.FlowMark <= previousFlowHighWater {
				return nil, fmt.Errorf("active epoch %d reuses high-water", m.ID)
			}
			if m.ID > n.MappingIDHighWater {
				n.MappingIDHighWater = m.ID
			}
			if *m.FlowMark > n.FlowMarkHighWater {
				n.FlowMarkHighWater = *m.FlowMark
			}
		}
		next = append(next, Active{m.ID, *m.FlowMark, h})
	}
	previous := n.RetirementHighWater
	for _, r := range *s.Retirements {
		found := false
		for _, e := range n.Entries {
			if e.RetirementID == r.RetirementID {
				found = true
				if e.Retirement != r {
					return nil, fmt.Errorf("retirement %s changed", r.RetirementID)
				}
			}
		}
		if found {
			continue
		}
		a, ok := old[r.MappingID]
		if !ok || a.FlowMark != r.FlowMark || a.TupleHash != r.TupleHash || r.Generation <= previous {
			return nil, fmt.Errorf("retirement %s has no exact active epoch", r.RetirementID)
		}
		n.Entries = append(n.Entries, Entry{Retirement: r})
		retired[r.MappingID] = true
		if r.Generation > n.RetirementHighWater {
			n.RetirementHighWater = r.Generation
		}
	}
	for id := range old {
		present := false
		for _, a := range next {
			if a.MappingID == id {
				present = true
			}
		}
		if !present && !retired[id] {
			return nil, fmt.Errorf("active epoch %d disappeared without retirement", id)
		}
	}
	filtered := next[:0]
	for _, a := range next {
		if !retired[a.MappingID] {
			filtered = append(filtered, a)
		}
	}
	n.Active = filtered
	if e := n.Validate(); e != nil {
		return nil, e
	}
	return &n, nil
}
func (l *Ledger) Retirements() []snapshot.Retirement {
	o := make([]snapshot.Retirement, len(l.Entries))
	for i := range l.Entries {
		o[i] = l.Entries[i].Retirement
	}
	return o
}
func (l *Ledger) Clear(ids map[string]bool) {
	for i := range l.Entries {
		if ids[l.Entries[i].RetirementID] {
			l.Entries[i].Cleared = true
		}
	}
}
func (l *Ledger) ClearedEntries() []Entry {
	o := []Entry{}
	for _, e := range l.Entries {
		if e.Cleared {
			o = append(o, e)
		}
	}
	return o
}
func (l *Ledger) Persist(p string) error {
	if e := l.Validate(); e != nil {
		return e
	}
	b, e := json.Marshal(l)
	if e != nil {
		return e
	}
	d := filepath.Dir(p)
	t, e := os.CreateTemp(d, ".retirement-ledger-*")
	if e != nil {
		return e
	}
	defer os.Remove(t.Name())
	if e = t.Chmod(0640); e == nil {
		_, e = t.Write(b)
	}
	if e == nil {
		e = t.Sync()
	}
	if ce := t.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(t.Name(), p); e != nil {
		return e
	}
	dir, e := os.Open(d)
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}

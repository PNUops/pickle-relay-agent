package retirement

import (
	"github.com/pnuops/pickle-relay-agent/internal/snapshot"
	"net/netip"
	"testing"
)

var limits = snapshot.Limits{TargetCIDR: netip.MustParsePrefix("192.0.2.0/24"), BandMin: 10000, BandMax: 19999}

func snap(t *testing.T, g, id int64, mark uint32, rs []snapshot.Retirement, ack int64) *snapshot.Snapshot {
	t.Helper()
	if rs == nil {
		rs = []snapshot.Retirement{}
	}
	s := &snapshot.Snapshot{Generation: g, Mappings: []snapshot.Mapping{{ID: id, Proto: snapshot.ProtoTCP, PublicPort: 10080, TargetAddr: "192.0.2.8", TargetPort: 80, FlowMark: &mark}}, Retirements: &rs, AcknowledgedRetirementHighWater: &ack}
	if e := s.Validate(limits); e != nil {
		t.Fatal(e)
	}
	return s
}
func TestEpochHighWaterAndAckCompaction(t *testing.T) {
	l, _ := New()
	l, e := l.Prepare(snap(t, 2, 7, 10, nil, 0))
	if e != nil {
		t.Fatal(e)
	}
	changed := snap(t, 2, 7, 10, nil, 0)
	changed.Mappings[0].TargetPort = 81
	if _, e = l.Prepare(changed); e == nil {
		t.Fatal("same generation changed content")
	}
	older := snap(t, 1, 7, 10, nil, 0)
	if _, e = l.Prepare(older); e == nil {
		t.Fatal("older managed generation accepted")
	}
	r := snapshot.Retirement{RetirementID: "11111111-2222-4333-8444-555555555555", MappingID: 7, Generation: 3, Proto: snapshot.ProtoTCP, PublicPort: 10080, TargetAddr: "192.0.2.8", TargetPort: 80, FlowMark: 10}
	r.TupleHash = snapshot.TupleHash(r.MappingID, r.Proto, r.PublicPort, r.TargetAddr, r.TargetPort, r.FlowMark)
	empty := []snapshot.Mapping{}
	rs := []snapshot.Retirement{r}
	s := &snapshot.Snapshot{Generation: 3, Mappings: empty, Retirements: &rs, AcknowledgedRetirementHighWater: new(int64)}
	if e = s.Validate(limits); e != nil {
		t.Fatal(e)
	}
	l, e = l.Prepare(s)
	if e != nil {
		t.Fatal(e)
	}
	l.Clear(map[string]bool{r.RetirementID: true})
	ack := int64(3)
	none := []snapshot.Retirement{}
	next := &snapshot.Snapshot{Generation: 4, Mappings: empty, Retirements: &none, AcknowledgedRetirementHighWater: &ack}
	l, e = l.Prepare(next)
	if e != nil {
		t.Fatal(e)
	}
	if len(l.Entries) != 0 || l.MappingIDHighWater != 7 || l.FlowMarkHighWater != 10 {
		t.Fatalf("ledger=%+v", l)
	}
	if _, e = l.Prepare(snap(t, 5, 7, 11, nil, 3)); e == nil {
		t.Fatal("restored epoch accepted")
	}
	if _, e = l.Prepare(snap(t, 5, 8, 10, nil, 3)); e == nil {
		t.Fatal("restored mark accepted")
	}
}

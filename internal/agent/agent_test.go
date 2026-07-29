package agent

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/pnuops/pickle-relay-agent/internal/config"
	"github.com/pnuops/pickle-relay-agent/internal/nftctl"
	"github.com/pnuops/pickle-relay-agent/internal/snapshot"
	"github.com/pnuops/pickle-relay-agent/internal/source"
)

// All fixture addresses are RFC 5737 documentation ranges.

func testConfig(t *testing.T) *config.Config {
	return &config.Config{
		Limits: snapshot.Limits{
			TargetCIDR: netip.MustParsePrefix("192.0.2.0/24"),
			BandMin:    10000, BandMax: 19999,
		},
		PublicIface: "eth0",
		StateDir:    t.TempDir(),
	}
}

// fakeSource replays scripted sync responses and records every report.
type fakeSource struct {
	responses []syncResp
	reports   []source.Report
}

type syncResp struct {
	body    []byte
	changed bool
	err     error
}

func (f *fakeSource) Sync(_ context.Context, r source.Report) ([]byte, bool, error) {
	f.reports = append(f.reports, r)
	if len(f.responses) == 0 {
		return nil, false, nil // default: unchanged heartbeat
	}
	resp := f.responses[0]
	f.responses = f.responses[1:]
	return resp.body, resp.changed, resp.err
}

// fakeKernel scripts counter readouts and apply outcomes, and records the
// event order (the fold-before-replace property is an ordering claim).
type fakeKernel struct {
	events         []string
	applyErrs      []error                     // popped per Apply call; empty → success
	reads          []map[int64]nftctl.Counters // popped per ReadCounters call
	presentResults []bool                      // popped per Present call; empty → true
	lastRules      []nftctl.Rule
	applyCalls     int
}

func (k *fakeKernel) Apply(_ string, rules []nftctl.Rule, _ nftctl.Guards) error {
	k.events = append(k.events, "apply")
	k.applyCalls++
	k.lastRules = rules
	if len(k.applyErrs) > 0 {
		err := k.applyErrs[0]
		k.applyErrs = k.applyErrs[1:]
		if err != nil {
			return err
		}
	}
	return nil
}

func (k *fakeKernel) Present() (bool, error) {
	k.events = append(k.events, "present")
	if len(k.presentResults) == 0 {
		return true, nil
	}
	p := k.presentResults[0]
	k.presentResults = k.presentResults[1:]
	return p, nil
}

func (k *fakeKernel) ReadCounters() (map[int64]nftctl.Counters, error) {
	k.events = append(k.events, "read")
	if len(k.reads) == 0 {
		return map[int64]nftctl.Counters{}, nil
	}
	r := k.reads[0]
	k.reads = k.reads[1:]
	return r, nil
}

func newTestAgent(t *testing.T, src *fakeSource, k *fakeKernel) *Agent {
	return New(testConfig(t), src, k, slog.New(slog.DiscardHandler))
}

const gen2Body = `{"generation":2,"mappings":[{"id":7,"proto":"tcp","publicPort":10080,"targetAddr":"192.0.2.8","targetPort":80}]}`

func TestUnchangedCycleReportsCounters(t *testing.T) {
	src := &fakeSource{responses: []syncResp{{changed: false}, {changed: false}}}
	k := &fakeKernel{reads: []map[int64]nftctl.Counters{
		{7: {NewConns: 5, InBytes: 100}},
		{7: {NewConns: 8, InBytes: 250}},
	}}
	a := newTestAgent(t, src, k)

	a.cycle(context.Background())
	a.cycle(context.Background())

	if len(src.reports) != 2 {
		t.Fatalf("reports = %d", len(src.reports))
	}
	c := src.reports[0].Counters
	if len(c) != 1 || c[0].MappingID != 7 || c[0].NewConns != 5 || c[0].InBytes != 100 {
		t.Fatalf("report 0 counters = %+v", c)
	}
	// second read is higher: deltas accumulate
	c = src.reports[1].Counters
	if c[0].NewConns != 8 || c[0].InBytes != 250 {
		t.Fatalf("report 1 counters = %+v", c)
	}
	if k.applyCalls != 0 {
		t.Fatalf("unchanged cycles must not apply (%d applies)", k.applyCalls)
	}
}

func TestCounterFoldAcrossReset(t *testing.T) {
	src := &fakeSource{responses: []syncResp{{changed: false}, {changed: false}}}
	k := &fakeKernel{reads: []map[int64]nftctl.Counters{
		{7: {NewConns: 100}},
		{7: {NewConns: 3}}, // below the last reading: a table replace reset it
	}}
	a := newTestAgent(t, src, k)

	a.cycle(context.Background())
	a.cycle(context.Background())

	if got := src.reports[1].Counters[0].NewConns; got != 103 {
		t.Fatalf("cumulative after reset = %d, want 103 (100 + 3)", got)
	}
}

func TestApplyFailureFreezesAndRetainsLastErr(t *testing.T) {
	src := &fakeSource{responses: []syncResp{
		{body: []byte(gen2Body), changed: true}, // apply will fail
		{changed: false},                        // heartbeat: must still carry the error
		{body: []byte(gen2Body), changed: true}, // retry succeeds
		{changed: false},                        // heartbeat: error cleared
	}}
	k := &fakeKernel{applyErrs: []error{context.DeadlineExceeded}}
	a := newTestAgent(t, src, k)

	if advanced := a.cycle(context.Background()); advanced {
		t.Fatal("failed apply must not report an advance")
	}
	if a.appliedGeneration != 0 {
		t.Fatalf("generation advanced to %d on failed apply", a.appliedGeneration)
	}
	a.cycle(context.Background())
	rep := src.reports[1]
	if rep.AppliedGeneration != 0 {
		t.Fatalf("reported generation = %d, want frozen 0", rep.AppliedGeneration)
	}
	if len(rep.LastError) != 1 || rep.LastError[0].Message == "" {
		t.Fatalf("lastError not retained: %+v", rep.LastError)
	}

	if advanced := a.cycle(context.Background()); !advanced {
		t.Fatal("successful apply of a new generation must report an advance")
	}
	a.cycle(context.Background())
	rep = src.reports[3]
	if rep.AppliedGeneration != 2 {
		t.Fatalf("reported generation = %d, want 2", rep.AppliedGeneration)
	}
	if len(rep.LastError) != 0 {
		t.Fatalf("lastError must clear on success: %+v", rep.LastError)
	}
}

func TestRejectedSnapshotCarriesMappingID(t *testing.T) {
	bad := `{"generation":2,"mappings":[{"id":31,"proto":"tcp","publicPort":10080,"targetAddr":"198.51.100.9","targetPort":80}]}`
	src := &fakeSource{responses: []syncResp{
		{body: []byte(bad), changed: true},
		{changed: false},
	}}
	k := &fakeKernel{}
	a := newTestAgent(t, src, k)

	a.cycle(context.Background())
	if k.applyCalls != 0 {
		t.Fatal("rejected snapshot must not be applied")
	}
	a.cycle(context.Background())
	items := src.reports[1].LastError
	if len(items) != 1 || items[0].MappingID == nil || *items[0].MappingID != 31 {
		t.Fatalf("lastError = %+v, want mappingId 31", items)
	}
}

func TestFoldBeforeReplaceOrdering(t *testing.T) {
	src := &fakeSource{responses: []syncResp{{body: []byte(gen2Body), changed: true}}}
	k := &fakeKernel{}
	a := newTestAgent(t, src, k)

	a.cycle(context.Background())

	// one read for the report, one read immediately before the replace
	want := []string{"read", "read", "apply"}
	if len(k.events) != len(want) {
		t.Fatalf("events = %v, want %v", k.events, want)
	}
	for i := range want {
		if k.events[i] != want[i] {
			t.Fatalf("events = %v, want %v", k.events, want)
		}
	}
}

func TestFollowUpFiresOnceOnAdvanceOnly(t *testing.T) {
	// advance: the follow-up cycle runs exactly once, even though it also
	// returns a changed snapshot (which advances again)
	src := &fakeSource{responses: []syncResp{
		{body: []byte(gen2Body), changed: true},
		{body: []byte(`{"generation":3,"mappings":[]}`), changed: true},
		{changed: false},
	}}
	a := newTestAgent(t, src, &fakeKernel{})
	a.runOnce(context.Background())
	if len(src.reports) != 2 {
		t.Fatalf("sync calls = %d, want 2 (cycle + one follow-up, no chain)", len(src.reports))
	}
	if src.reports[1].AppliedGeneration != 2 {
		t.Fatalf("follow-up reported %d, want 2", src.reports[1].AppliedGeneration)
	}

	// apply failure: no follow-up
	src = &fakeSource{responses: []syncResp{{body: []byte(gen2Body), changed: true}}}
	a = newTestAgent(t, src, &fakeKernel{applyErrs: []error{context.DeadlineExceeded}})
	a.runOnce(context.Background())
	if len(src.reports) != 1 {
		t.Fatalf("sync calls after failure = %d, want 1", len(src.reports))
	}

	// unchanged: no follow-up
	src = &fakeSource{responses: []syncResp{{changed: false}}}
	a = newTestAgent(t, src, &fakeKernel{})
	a.runOnce(context.Background())
	if len(src.reports) != 1 {
		t.Fatalf("sync calls when unchanged = %d, want 1", len(src.reports))
	}

	// same-generation self-heal (table present, nothing to do): no follow-up
	src = &fakeSource{responses: []syncResp{
		{body: []byte(gen2Body), changed: true},
		{changed: false},
		{body: []byte(gen2Body), changed: true}, // same generation again
	}}
	a = newTestAgent(t, src, &fakeKernel{})
	a.runOnce(context.Background()) // applies gen 2 (+ follow-up)
	a.runOnce(context.Background()) // same gen: present → no-op, no follow-up
	if len(src.reports) != 3 {
		t.Fatalf("sync calls = %d, want 3", len(src.reports))
	}
}

func TestSyncErrorAppliesNothing(t *testing.T) {
	src := &fakeSource{responses: []syncResp{{err: context.DeadlineExceeded}}}
	k := &fakeKernel{}
	a := newTestAgent(t, src, k)
	a.runOnce(context.Background())
	if k.applyCalls != 0 {
		t.Fatal("sync error must not trigger an apply")
	}
	if len(src.reports) != 1 {
		t.Fatalf("sync calls = %d, want 1 (no follow-up)", len(src.reports))
	}
}

func TestPruneRemovedMappings(t *testing.T) {
	src := &fakeSource{responses: []syncResp{
		{changed: false}, // pick up counters for mapping 7
		{body: []byte(`{"generation":3,"mappings":[{"id":9,"proto":"udp","publicPort":10053,"targetAddr":"192.0.2.9","targetPort":53}]}`), changed: true},
		{changed: false},
	}}
	k := &fakeKernel{reads: []map[int64]nftctl.Counters{
		{7: {NewConns: 4}},
	}}
	a := newTestAgent(t, src, k)
	a.cycle(context.Background())
	a.cycle(context.Background()) // applies a set WITHOUT mapping 7
	a.cycle(context.Background())
	last := src.reports[2].Counters
	for _, c := range last {
		if c.MappingID == 7 {
			t.Fatalf("pruned mapping still reported: %+v", last)
		}
	}
}

func TestBootReapplyFoldsBeforeApply(t *testing.T) {
	cfg := testConfig(t)
	s, err := snapshot.Parse([]byte(gen2Body), cfg.Limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Persist(cfg.SnapshotPath()); err != nil {
		t.Fatal(err)
	}
	cfg.SnapshotMaxAge = 24 * time.Hour
	k := &fakeKernel{reads: []map[int64]nftctl.Counters{{7: {NewConns: 42}}}}
	src := &fakeSource{responses: []syncResp{{changed: false}}}
	a := New(cfg, src, k, slog.New(slog.DiscardHandler))
	if err := a.BootReapply(); err != nil {
		t.Fatal(err)
	}
	if len(k.events) < 2 || k.events[0] != "read" || k.events[1] != "apply" {
		t.Fatalf("events = %v, want read before apply", k.events)
	}
	if a.appliedGeneration != 2 {
		t.Fatalf("boot generation = %d, want 2", a.appliedGeneration)
	}
	// the pre-replace values survived into the report
	a.cycle(context.Background())
	c := src.reports[0].Counters
	if len(c) != 1 || c[0].NewConns != 42 {
		t.Fatalf("boot-folded counters = %+v, want NewConns 42", c)
	}
}

func TestUnchangedCycleRepairsWipedTable(t *testing.T) {
	src := &fakeSource{responses: []syncResp{
		{body: []byte(gen2Body), changed: true}, // steady state: gen 2 applied
		{changed: false},                        // table wiped out of band
		{changed: false},                        // table back: no extra apply
	}}
	k := &fakeKernel{presentResults: []bool{false, true}}
	a := newTestAgent(t, src, k)

	a.cycle(context.Background())
	if k.applyCalls != 1 {
		t.Fatalf("applies after steady state = %d", k.applyCalls)
	}
	if advanced := a.cycle(context.Background()); advanced {
		t.Fatal("re-assert must not report an advance")
	}
	if k.applyCalls != 2 {
		t.Fatalf("wiped table not re-applied (applies = %d)", k.applyCalls)
	}
	if len(k.lastRules) != 1 || k.lastRules[0].MappingID != 7 {
		t.Fatalf("re-assert applied wrong rules: %+v", k.lastRules)
	}
	if a.appliedGeneration != 2 {
		t.Fatalf("generation = %d, want 2 (unchanged by re-assert)", a.appliedGeneration)
	}
	a.cycle(context.Background())
	if k.applyCalls != 2 {
		t.Fatalf("healthy table must not be re-applied (applies = %d)", k.applyCalls)
	}
}

func TestUnchangedCycleRepairFailureReportsError(t *testing.T) {
	src := &fakeSource{responses: []syncResp{
		{body: []byte(gen2Body), changed: true},
		{changed: false}, // wipe detected, re-assert fails
		{changed: false},
	}}
	k := &fakeKernel{
		presentResults: []bool{false},
		applyErrs:      []error{nil, context.DeadlineExceeded},
	}
	a := newTestAgent(t, src, k)
	a.cycle(context.Background())
	a.cycle(context.Background())
	a.cycle(context.Background())
	rep := src.reports[2]
	if len(rep.LastError) != 1 {
		t.Fatalf("failed re-assert not reported: %+v", rep.LastError)
	}
	if rep.AppliedGeneration != 2 {
		t.Fatalf("reported generation = %d, want 2", rep.AppliedGeneration)
	}
}

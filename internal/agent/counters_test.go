package agent

import (
	"testing"

	"github.com/pnuops/pickle-relay-agent/internal/nftctl"
)

// TestMarkResetPreventsUndercount pins the reason MarkReset exists: after a
// table replace the kernel counter restarts at zero, and if it climbs PAST
// the stale baseline before the next read, delta folding alone would report
// only the excess. With the baseline zeroed the full fresh count is added.
func TestMarkResetPreventsUndercount(t *testing.T) {
	cs := newCounterState()
	cs.Fold(map[int64]nftctl.Counters{7: {NewConns: 5, InBytes: 500}})
	cs.MarkReset() // table replaced: kernel counters are zero again
	// fresh counter already climbed past the old baseline of 5
	cs.Fold(map[int64]nftctl.Counters{7: {NewConns: 7, InBytes: 700}})

	got := cs.Snapshot()
	if len(got) != 1 || got[0].NewConns != 12 || got[0].InBytes != 1200 {
		t.Fatalf("cumulative = %+v, want NewConns 12 / InBytes 1200", got)
	}
}

func TestMarkResetKeepsCumulative(t *testing.T) {
	cs := newCounterState()
	cs.Fold(map[int64]nftctl.Counters{7: {NewConns: 5}})
	cs.MarkReset()
	if got := cs.Snapshot(); got[0].NewConns != 5 {
		t.Fatalf("cumulative changed by MarkReset: %+v", got)
	}
}

// stateWithMappings builds a counter state holding n mappings with ids
// 1..n, each carrying one new connection.
func stateWithMappings(n int) *counterState {
	cs := newCounterState()
	read := make(map[int64]nftctl.Counters, n)
	for i := 1; i <= n; i++ {
		read[int64(i)] = nftctl.Counters{NewConns: 1}
	}
	cs.Fold(read)
	return cs
}

func TestSnapshotBelowCapReportsEverything(t *testing.T) {
	cs := stateWithMappings(maxReportedCounters)
	for round := range 3 {
		got := cs.Snapshot()
		if len(got) != maxReportedCounters {
			t.Fatalf("round %d: %d rows, want %d", round, len(got), maxReportedCounters)
		}
		for i, c := range got {
			if c.MappingID != int64(i+1) {
				t.Fatalf("round %d: row %d is mapping %d", round, i, c.MappingID)
			}
		}
	}
}

func TestSnapshotRotatesAboveCap(t *testing.T) {
	const extra = 350
	cs := stateWithMappings(maxReportedCounters + extra)

	rounds := make([][]int64, 0, 3)
	seen := make(map[int64]struct{})
	for round := range 3 {
		got := cs.Snapshot()
		if len(got) != maxReportedCounters {
			t.Fatalf("round %d: %d rows, want the cap %d", round, len(got), maxReportedCounters)
		}
		ids := make([]int64, 0, len(got))
		for i, c := range got {
			if i > 0 && c.MappingID <= got[i-1].MappingID {
				t.Fatalf("round %d: rows not ascending at %d", round, i)
			}
			ids = append(ids, c.MappingID)
			seen[c.MappingID] = struct{}{}
		}
		rounds = append(rounds, ids)
	}

	// the first report is the lowest ids; the tail is what rotation must
	// deliver next
	if rounds[0][0] != 1 || rounds[0][len(rounds[0])-1] != int64(maxReportedCounters) {
		t.Fatalf("first report is not the lowest ids: %d..%d",
			rounds[0][0], rounds[0][len(rounds[0])-1])
	}
	// the second report continues after the first and wraps: it holds the
	// highest id and, having wrapped, the lowest one too
	second := make(map[int64]struct{}, len(rounds[1]))
	for _, id := range rounds[1] {
		second[id] = struct{}{}
	}
	for _, id := range []int64{maxReportedCounters + 1, maxReportedCounters + extra, 1} {
		if _, ok := second[id]; !ok {
			t.Fatalf("second report is missing mapping %d (no rotation or no wrap)", id)
		}
	}
	// no starvation: two reports already cover every live mapping
	for i := 1; i <= maxReportedCounters+extra; i++ {
		if _, ok := seen[int64(i)]; !ok {
			t.Fatalf("mapping %d never reported", i)
		}
	}
	// and the window keeps moving after the wrap instead of pinning to one
	// offset: the third report must carry an id the second one skipped
	moved := false
	for _, id := range rounds[2] {
		if _, ok := second[id]; !ok {
			moved = true
			break
		}
	}
	if !moved {
		t.Fatal("window stopped advancing after the wrap")
	}
}

// TestRotationKeepsCumulativeTotals pins the property rotation depends on:
// values are cumulative, so a mapping skipped by one report carries the whole
// total (including what it counted while skipped) on its next appearance.
func TestRotationKeepsCumulativeTotals(t *testing.T) {
	const n = maxReportedCounters + 1
	cs := stateWithMappings(n) // every mapping at 1 new connection

	first := cs.Snapshot()
	if len(first) != maxReportedCounters {
		t.Fatalf("first report has %d rows", len(first))
	}
	// mapping n was left out; it keeps counting while skipped
	cs.Fold(map[int64]nftctl.Counters{n: {NewConns: 9}})

	second := cs.Snapshot()
	var got *uint64
	for i := range second {
		if second[i].MappingID == n {
			got = &second[i].NewConns
		}
	}
	if got == nil {
		t.Fatalf("skipped mapping %d not reported on the next round", n)
	}
	if *got != 9 {
		t.Fatalf("cumulative for the skipped mapping = %d, want the full 9", *got)
	}
}

func TestSnapshotCursorSurvivesPrune(t *testing.T) {
	cs := stateWithMappings(maxReportedCounters + 10)
	cs.Snapshot() // cursor now sits on an id in the tail
	keep := make(map[int64]struct{}, 5)
	for i := int64(1); i <= 5; i++ {
		keep[i] = struct{}{}
	}
	cs.Prune(keep)
	got := cs.Snapshot()
	if len(got) != 5 || got[0].MappingID != 1 {
		t.Fatalf("after prune the report must cover the survivors: %+v", got)
	}
}

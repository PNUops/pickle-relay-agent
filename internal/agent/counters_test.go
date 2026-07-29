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

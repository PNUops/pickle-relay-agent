package agent

import (
	"sort"

	"github.com/pnuops/pickle-relay-agent/internal/nftctl"
	"github.com/pnuops/pickle-relay-agent/internal/source"
)

// counterState folds periodic kernel counter reads into per-mapping
// cumulative totals. Kernel counters are NOT monotonic: every whole-table
// replace zeroes them (the atomic apply recreates the counter objects), so
// the raw readings cannot be reported as-is. The agent instead keeps, per
// mapping, the cumulative total plus the last raw reading; each fold adds
// the delta, and a reading BELOW the previous one means the counter was
// reset — the raw value is then the whole delta. Reported values are
// therefore cumulative since agent start, which is what the sync contract
// promises (the server treats any decrease as an agent restart).
type counterState struct {
	m map[int64]*mappingCounter
}

type mappingCounter struct {
	cum  nftctl.Counters // reported value (monotonic within this process)
	last nftctl.Counters // previous raw kernel reading (reset detection)
}

func newCounterState() *counterState {
	return &counterState{m: make(map[int64]*mappingCounter)}
}

// Fold merges one kernel readout into the cumulative totals.
func (cs *counterState) Fold(read map[int64]nftctl.Counters) {
	for id, k := range read {
		mc := cs.m[id]
		if mc == nil {
			mc = &mappingCounter{}
			cs.m[id] = mc
		}
		foldField(&mc.cum.NewConns, &mc.last.NewConns, k.NewConns)
		foldField(&mc.cum.InPackets, &mc.last.InPackets, k.InPackets)
		foldField(&mc.cum.InBytes, &mc.last.InBytes, k.InBytes)
		foldField(&mc.cum.OutPackets, &mc.last.OutPackets, k.OutPackets)
		foldField(&mc.cum.OutBytes, &mc.last.OutBytes, k.OutBytes)
		foldField(&mc.cum.RateDropped, &mc.last.RateDropped, k.RateDropped)
		foldField(&mc.cum.ConnDropped, &mc.last.ConnDropped, k.ConnDropped)
		foldField(&mc.cum.PerSourceDropped, &mc.last.PerSourceDropped, k.PerSourceDropped)
	}
}

func foldField(cum, last *uint64, k uint64) {
	if k >= *last {
		*cum += k - *last
	} else {
		// counter went backwards: a table replace reset it to zero and it
		// has counted k since — the raw reading IS the delta
		*cum += k
	}
	*last = k
}

// MarkReset zeroes every retained kernel baseline. Call immediately after a
// successful table replace: the replace recreates all counter objects at
// zero, and a stale baseline would make the next fold report only the part
// of a reading that exceeds the OLD baseline (an undercount) whenever the
// fresh counter happens to climb past it before the next read.
func (cs *counterState) MarkReset() {
	for _, mc := range cs.m {
		mc.last = nftctl.Counters{}
	}
}

// Prune drops state for mappings absent from the applied set — a deleted
// mapping must stop appearing in reports (its id may eventually be reused by
// an unrelated tenant's row only in a different generation history, and a
// ghost entry would misattribute traffic).
//
// Accepted loss: the fold that runs immediately before the replace folds the
// deleted mapping's final increment into its cumulative total, but the total
// dies here before the next report can deliver it — the tail increment
// between the last delivered report and deletion goes unreported. Accepted:
// a deleted mapping has no row to account to, and the window is one poll
// interval at most.
func (cs *counterState) Prune(keep map[int64]struct{}) {
	for id := range cs.m {
		if _, ok := keep[id]; !ok {
			delete(cs.m, id)
		}
	}
}

// Snapshot renders the cumulative totals for the sync report, sorted by
// mapping id so report payloads are deterministic.
func (cs *counterState) Snapshot() []source.MappingCounters {
	if len(cs.m) == 0 {
		return nil
	}
	out := make([]source.MappingCounters, 0, len(cs.m))
	for id, mc := range cs.m {
		out = append(out, source.MappingCounters{
			MappingID:        id,
			NewConns:         mc.cum.NewConns,
			InPackets:        mc.cum.InPackets,
			InBytes:          mc.cum.InBytes,
			OutPackets:       mc.cum.OutPackets,
			OutBytes:         mc.cum.OutBytes,
			RateDropped:      mc.cum.RateDropped,
			ConnDropped:      mc.cum.ConnDropped,
			PerSourceDropped: mc.cum.PerSourceDropped,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MappingID < out[j].MappingID })
	return out
}

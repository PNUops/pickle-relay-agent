// Package source abstracts where desired-state snapshots come from. The
// production source POSTs the agent's report to the platform sync endpoint
// and receives the snapshot in the response; FileSource feeds a local file
// for bootstrap and testing. Both return raw bytes — parsing/validation is
// the caller's job so the firewall-config validation path is identical for
// every source.
package source

import (
	"context"
	"os"
)

// Report is the agent's side of a sync exchange: what the kernel currently
// holds and what it has seen. It doubles as the heartbeat — every sync
// carries it, whether or not the desired state changed.
type Report struct {
	// AppliedGeneration is the last generation the kernel is KNOWN to hold
	// (never advanced on a failed apply).
	AppliedGeneration int64 `json:"appliedGeneration"`
	// AgentVersion identifies the running binary (build-stamped).
	AgentVersion string `json:"agentVersion"`
	// LastError reports why the latest snapshot could not be applied; empty
	// when the agent is converged.
	LastError []ErrItem `json:"lastError,omitempty"`
	// Counters are the per-mapping traffic/drop totals, cumulative since
	// agent start (the server treats any decrease as an agent restart).
	Counters []MappingCounters `json:"counters,omitempty"`
}

// ErrItem is one apply/validation failure. MappingID is set when the failure
// is attributable to a single mapping.
type ErrItem struct {
	MappingID *int64 `json:"mappingId,omitempty"`
	Message   string `json:"message"`
}

// MappingCounters is one mapping's cumulative counter readout.
type MappingCounters struct {
	MappingID        int64  `json:"mappingId"`
	NewConns         uint64 `json:"newConns"`
	InPackets        uint64 `json:"inPackets"`
	InBytes          uint64 `json:"inBytes"`
	OutPackets       uint64 `json:"outPackets"`
	OutBytes         uint64 `json:"outBytes"`
	RateDropped      uint64 `json:"rateDropped"`
	ConnDropped      uint64 `json:"connDropped"`
	PerSourceDropped uint64 `json:"perSourceDropped"`
}

// Source is one sync exchange: deliver the report upstream, get the desired
// state back.
type Source interface {
	// Sync sends r and returns the current desired-state snapshot body.
	// changed=false means the desired generation equals r.AppliedGeneration
	// and there is nothing to apply (body is then nil). The report always
	// goes with the exchange — there is no separate result-delivery call.
	Sync(ctx context.Context, r Report) (body []byte, changed bool, err error)
}

// FileSource reads snapshots from a local JSON file. The report is ignored —
// a file has no upstream to tell.
type FileSource struct{ Path string }

// Sync implements Source. It always returns changed=true; the caller's
// generation comparison makes re-applies idempotent and cheap.
func (f FileSource) Sync(_ context.Context, _ Report) ([]byte, bool, error) {
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

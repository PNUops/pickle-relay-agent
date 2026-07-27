// Package source abstracts where desired-state snapshots come from. The
// production source polls the platform sync endpoint (arrives with the
// transport milestone); FileSource feeds a local file for bootstrap and
// testing. Both return raw bytes — parsing/validation is the caller's job so
// the firewall-config validation path is identical for every source.
package source

import (
	"context"
	"os"
)

// Source yields the current desired-state snapshot bytes.
type Source interface {
	// Fetch returns the snapshot body. Implementations may use
	// lastGeneration to skip unchanged payloads by returning changed=false
	// (body is then ignored).
	Fetch(ctx context.Context, lastGeneration int64) (body []byte, changed bool, err error)
	// Report delivers apply results upstream (applied generation + errors).
	// The file source ignores it; the sync source will carry it in the poll
	// request body.
	Report(ctx context.Context, appliedGeneration int64, applyErr error)
}

// FileSource reads snapshots from a local JSON file.
type FileSource struct{ Path string }

// Fetch implements Source. It always returns changed=true; the caller's
// generation comparison makes re-applies idempotent and cheap.
func (f FileSource) Fetch(_ context.Context, _ int64) ([]byte, bool, error) {
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

// Report implements Source (no-op for files).
func (FileSource) Report(context.Context, int64, error) {}

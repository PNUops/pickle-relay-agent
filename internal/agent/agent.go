// Package agent is the convergence loop: (re)apply persisted state at boot
// within the allowed window, then poll the source and converge the kernel to
// each new generation.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/pnuops/pickle-relay-agent/internal/config"
	"github.com/pnuops/pickle-relay-agent/internal/nftctl"
	"github.com/pnuops/pickle-relay-agent/internal/snapshot"
	"github.com/pnuops/pickle-relay-agent/internal/source"
)

// Agent converges nftables to the desired mapping set.
type Agent struct {
	cfg *config.Config
	src source.Source
	log *slog.Logger

	// appliedGeneration is the last generation the kernel is KNOWN to hold.
	// It never advances on a failed apply — that is the frozen-generation
	// rule: reality and the reported generation must not diverge.
	appliedGeneration int64
	applied           bool
}

// New builds an agent.
func New(cfg *config.Config, src source.Source, log *slog.Logger) *Agent {
	return &Agent{cfg: cfg, src: src, log: log}
}

// BootReapply restores the persisted snapshot iff it is younger than the
// configured window (bounded fail-open). An older or invalid snapshot
// converges the table to EMPTY instead (fail-closed): a released IP may have
// been re-assigned to another tenant after quarantine, and a stale DNAT
// would hand public traffic to the wrong VM.
func (a *Agent) BootReapply() error {
	path := a.cfg.SnapshotPath()
	s, err := snapshot.LoadPersisted(path, a.cfg.Limits, a.cfg.SnapshotMaxAge, time.Now())
	switch {
	case err == nil:
		if err := nftctl.Apply(a.cfg.PublicIface, nftctl.Plan(s), a.cfg.Guards); err != nil {
			return fmt.Errorf("boot re-apply: %w", err)
		}
		a.appliedGeneration, a.applied = s.Generation, true
		a.log.Info("boot re-apply", "generation", s.Generation, "mappings", len(s.Mappings))
		return nil
	case errors.Is(err, os.ErrNotExist):
		a.log.Info("no persisted snapshot; converging to empty set")
	default:
		// stale or invalid: converge to empty and drop the file so the next
		// boot does not re-litigate it
		a.log.Warn("persisted snapshot rejected; converging to empty set", "reason", err)
		_ = os.Remove(path)
	}
	if err := nftctl.Apply(a.cfg.PublicIface, nil, a.cfg.Guards); err != nil {
		return fmt.Errorf("boot empty apply: %w", err)
	}
	a.appliedGeneration, a.applied = 0, true
	return nil
}

// Run polls the source until ctx ends. Apply failures freeze the reported
// generation and are retried on the next cycle.
func (a *Agent) Run(ctx context.Context) error {
	tick := time.NewTicker(a.cfg.PollInterval)
	defer tick.Stop()
	for {
		a.cycle(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func (a *Agent) cycle(ctx context.Context) {
	body, changed, err := a.src.Fetch(ctx, a.appliedGeneration)
	if err != nil {
		a.log.Warn("fetch failed", "error", err)
		return
	}
	if !changed {
		return
	}
	s, err := snapshot.Parse(body, a.cfg.Limits)
	if err != nil {
		// a snapshot that fails validation is NOT applied and does not
		// advance the generation — report and keep the last good rule set
		a.log.Error("snapshot rejected", "error", err)
		a.src.Report(ctx, a.appliedGeneration, err)
		return
	}
	if a.applied && s.Generation == a.appliedGeneration {
		return
	}
	if err := nftctl.Apply(a.cfg.PublicIface, nftctl.Plan(s), a.cfg.Guards); err != nil {
		a.log.Error("apply failed; generation frozen", "generation", s.Generation, "error", err)
		a.src.Report(ctx, a.appliedGeneration, err)
		return
	}
	if err := s.Persist(a.cfg.SnapshotPath()); err != nil {
		a.log.Warn("persist failed (kernel state is applied)", "error", err)
	}
	a.appliedGeneration, a.applied = s.Generation, true
	a.log.Info("applied", "generation", s.Generation, "mappings", len(s.Mappings))
	a.src.Report(ctx, a.appliedGeneration, nil)
}

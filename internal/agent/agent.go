// Package agent is the convergence loop: (re)apply persisted state at boot
// within the allowed window, then poll the source and converge the kernel to
// each new generation, reporting applied state and traffic counters upstream
// with every sync.
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
	"github.com/pnuops/pickle-relay-agent/internal/version"
)

// Kernel is the nftables surface the agent drives, injected so the
// convergence logic is testable without CAP_NET_ADMIN or a kernel.
type Kernel interface {
	Apply(iface string, rules []nftctl.Rule, g nftctl.Guards) error
	Present() (bool, error)
	ReadCounters() (map[int64]nftctl.Counters, error)
}

// NFTKernel is the production Kernel, backed by the nftctl netlink calls.
type NFTKernel struct{}

// Apply implements Kernel.
func (NFTKernel) Apply(iface string, rules []nftctl.Rule, g nftctl.Guards) error {
	return nftctl.Apply(iface, rules, g)
}

// Present implements Kernel.
func (NFTKernel) Present() (bool, error) { return nftctl.Present() }

// ReadCounters implements Kernel.
func (NFTKernel) ReadCounters() (map[int64]nftctl.Counters, error) { return nftctl.ReadCounters() }

// Agent converges nftables to the desired mapping set.
type Agent struct {
	cfg    *config.Config
	src    source.Source
	kernel Kernel
	log    *slog.Logger

	// appliedGeneration is the last generation the kernel is KNOWN to hold.
	// It never advances on a failed apply — that is the frozen-generation
	// rule: reality and the reported generation must not diverge.
	appliedGeneration int64
	applied           bool

	// lastErr is what the next sync report carries in lastError: why the
	// latest snapshot was rejected or failed to apply. Retained across
	// cycles until an apply succeeds.
	lastErr []source.ErrItem

	// counters folds kernel counter reads into cumulative per-mapping
	// totals (kernel counters reset on every table replace).
	counters *counterState

	// lastApplied is the snapshot the kernel currently holds (nil = the
	// empty set), kept so an out-of-band table wipe can be repaired even on
	// cycles where the source reports no change.
	lastApplied *snapshot.Snapshot
}

// New builds an agent.
func New(cfg *config.Config, src source.Source, k Kernel, log *slog.Logger) *Agent {
	return &Agent{cfg: cfg, src: src, kernel: k, log: log, counters: newCounterState()}
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
		// fold whatever a previous run's table counted before the replace
		// zeroes it (traffic that happened is traffic to report)
		a.foldCounters()
		if err := a.kernel.Apply(a.cfg.PublicIface, nftctl.Plan(s), a.cfg.Guards); err != nil {
			return fmt.Errorf("boot re-apply: %w", err)
		}
		a.appliedGeneration, a.applied, a.lastApplied = s.Generation, true, s
		// "boot re-apply" and "no persisted snapshot" below are stable
		// message names at INFO: operational tooling matches these
		// success-path lines. Do not rename or demote them without
		// coordinating that tooling.
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
	a.foldCounters()
	if err := a.kernel.Apply(a.cfg.PublicIface, nil, a.cfg.Guards); err != nil {
		return fmt.Errorf("boot empty apply: %w", err)
	}
	a.appliedGeneration, a.applied, a.lastApplied = 0, true, nil
	return nil
}

// Run polls the source until ctx ends. Apply failures freeze the reported
// generation and are retried on the next cycle.
func (a *Agent) Run(ctx context.Context) error {
	tick := time.NewTicker(a.cfg.PollInterval)
	defer tick.Stop()
	for {
		a.runOnce(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// runOnce is one poll iteration: a cycle plus, iff that cycle advanced the
// generation, ONE immediate follow-up cycle — the follow-up's report is what
// tells the server the new generation is applied, without waiting a full
// tick. The follow-up's own outcome never triggers another one, and failures
// never trigger any: only the timer re-enters, so nothing can tight-loop.
func (a *Agent) runOnce(ctx context.Context) {
	if a.cycle(ctx) {
		a.cycle(ctx)
	}
}

// cycle performs one sync exchange and converges the kernel if the desired
// state changed. It returns true iff the applied generation ADVANCED (the
// signal for the one-shot follow-up); failures, unchanged cycles and
// same-generation self-heals return false.
func (a *Agent) cycle(ctx context.Context) bool {
	// read kernel counters first so even a no-change heartbeat reports
	// fresh values
	a.foldCounters()
	rep := source.Report{
		AppliedGeneration: a.appliedGeneration,
		AgentVersion:      version.Version,
		LastError:         a.lastErr,
		Counters:          a.counters.Snapshot(),
	}
	body, changed, err := a.src.Sync(ctx, rep)
	if err != nil {
		// the POST itself was the report; nothing else to do until next tick
		a.log.Warn("sync failed", "error", err)
		return false
	}
	if !changed {
		// The desired state did not change, but the kernel may have — an
		// out-of-band wipe (`nft flush ruleset`, an nftables restart without
		// the ExecStop drop-in) would otherwise persist until the next
		// mapping change, since only changed cycles used to look at the
		// kernel at all.
		a.ensureAsserted()
		return false
	}
	s, err := snapshot.Parse(body, a.cfg.Limits)
	if err != nil {
		// a snapshot that fails validation is NOT applied and does not
		// advance the generation — the next report carries the error and
		// the last good rule set stays
		a.log.Error("snapshot rejected", "error", err)
		a.setLastErr(err)
		return false
	}
	if a.applied && s.Generation == a.appliedGeneration {
		// Generation unchanged — normally a no-op, but re-assert if the kernel
		// table was wiped out of band (e.g. an `nft flush ruleset` or an
		// nftables restart without the ExecStop drop-in): otherwise the
		// mappings would stay gone until the next mapping change.
		if present, perr := a.kernel.Present(); perr == nil && present {
			return false
		} else if perr != nil {
			a.log.Warn("table presence check failed; re-applying", "error", perr)
		} else {
			a.log.Warn("kernel table missing at unchanged generation; re-applying", "generation", s.Generation)
		}
	}
	// fold again IMMEDIATELY before the replace: the atomic apply recreates
	// every counter object at zero, so anything counted since the fold at
	// the top of this cycle would otherwise be lost
	a.foldCounters()
	if err := a.kernel.Apply(a.cfg.PublicIface, nftctl.Plan(s), a.cfg.Guards); err != nil {
		a.log.Error("apply failed; generation frozen", "generation", s.Generation, "error", err)
		a.setLastErr(err)
		return false
	}
	if err := s.Persist(a.cfg.SnapshotPath()); err != nil {
		a.log.Warn("persist failed (kernel state is applied)", "error", err)
	}
	advanced := !a.applied || s.Generation != a.appliedGeneration
	a.appliedGeneration, a.applied, a.lastApplied = s.Generation, true, s
	a.lastErr = nil
	keep := make(map[int64]struct{}, len(s.Mappings))
	for i := range s.Mappings {
		keep[s.Mappings[i].ID] = struct{}{}
	}
	a.counters.Prune(keep)
	// "applied" is a stable message name at INFO: operational tooling
	// matches this success-path line. Do not rename or demote it without
	// coordinating that tooling.
	a.log.Info("applied", "generation", s.Generation, "mappings", len(s.Mappings))
	return advanced
}

// ensureAsserted repairs an out-of-band kernel table wipe: when the table is
// missing (or its presence cannot be determined), the last applied snapshot
// is re-applied at the SAME generation — no advance, no follow-up. A failed
// re-apply is reported through lastError like any other apply failure.
func (a *Agent) ensureAsserted() {
	if !a.applied {
		return
	}
	present, err := a.kernel.Present()
	if err == nil && present {
		return
	}
	if err != nil {
		a.log.Warn("table presence check failed; re-asserting", "error", err)
	} else {
		a.log.Warn("kernel table missing; re-asserting", "generation", a.appliedGeneration)
	}
	var (
		rules []nftctl.Rule
		n     int
	)
	if a.lastApplied != nil {
		rules, n = nftctl.Plan(a.lastApplied), len(a.lastApplied.Mappings)
	}
	if err := a.kernel.Apply(a.cfg.PublicIface, rules, a.cfg.Guards); err != nil {
		a.log.Error("re-assert failed", "generation", a.appliedGeneration, "error", err)
		a.setLastErr(err)
		return
	}
	a.log.Info("re-asserted", "generation", a.appliedGeneration, "mappings", n)
}

// foldCounters merges the current kernel counter values into the cumulative
// totals. A failed read (no table yet, transient netlink error) just means
// the totals do not advance this round — never treated as zeros.
func (a *Agent) foldCounters() {
	read, err := a.kernel.ReadCounters()
	if err != nil {
		a.log.Debug("counter read failed", "error", err)
		return
	}
	a.counters.Fold(read)
}

// setLastErr shapes err into the next report's error items. A per-mapping
// validation failure carries its mapping id (snapshot.ValidationError);
// anything else becomes one unattributed item.
func (a *Agent) setLastErr(err error) {
	item := source.ErrItem{Message: err.Error()}
	var ve *snapshot.ValidationError
	if errors.As(err, &ve) {
		id := ve.MappingID
		item.MappingID = &id
	}
	a.lastErr = []source.ErrItem{item}
}

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
	"github.com/pnuops/pickle-relay-agent/internal/conntrackctl"
	"github.com/pnuops/pickle-relay-agent/internal/nftctl"
	"github.com/pnuops/pickle-relay-agent/internal/retirement"
	"github.com/pnuops/pickle-relay-agent/internal/snapshot"
	"github.com/pnuops/pickle-relay-agent/internal/source"
	"github.com/pnuops/pickle-relay-agent/internal/sourcepolicy"
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

func (NFTKernel) ApplyManaged(iface string, rules []nftctl.Rule, retirements []snapshot.Retirement, g nftctl.Guards) error {
	return nftctl.ApplyManaged(iface, rules, retirements, g)
}

func (NFTKernel) VerifyManaged(iface string, rules []nftctl.Rule, retirements []snapshot.Retirement, g nftctl.Guards) error {
	return nftctl.VerifyManaged(iface, rules, retirements, g)
}
func (NFTKernel) Quarantine(iface string) error  { return nftctl.ApplyQuarantine(iface) }
func (NFTKernel) HasManagedState() (bool, error) { return nftctl.HasManagedState() }

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

	// bootFailed marks a boot-time apply that did not take. Kernel state is
	// then UNKNOWN (a previous run's table may still be live) and no
	// desired-state change is guaranteed to come along and retry it, so the
	// poll loop keeps re-attempting the boot converge until it succeeds.
	bootFailed bool
	ledger     *retirement.Ledger
	conntrack  conntrackctl.Controller
	ledgerLost bool
}

type managedKernel interface {
	ApplyManaged(iface string, rules []nftctl.Rule, retirements []snapshot.Retirement, g nftctl.Guards) error
	VerifyManaged(iface string, rules []nftctl.Rule, retirements []snapshot.Retirement, g nftctl.Guards) error
	Quarantine(iface string) error
	HasManagedState() (bool, error)
}

// New builds an agent.
func New(cfg *config.Config, src source.Source, k Kernel, log *slog.Logger) *Agent {
	ledger, _ := retirement.New()
	return &Agent{cfg: cfg, src: src, kernel: k, log: log, counters: newCounterState(), ledger: ledger, conntrack: conntrackctl.Netlink{}}
}

// BootReapply restores the persisted snapshot iff it is younger than the
// configured window (bounded fail-open). An older or invalid snapshot
// converges the table to EMPTY instead (fail-closed): a released IP may have
// been re-assigned to another tenant after quarantine, and a stale DNAT
// would hand public traffic to the wrong VM.
//
// A failed apply is returned AND retained: the agent keeps no applied
// generation (it must never claim state it did not establish), carries the
// failure into the next sync report, and re-attempts the converge on the
// poll loop. Callers are meant to log the error and run anyway — exiting
// would restart-loop the service and hide the reason, which travels
// upstream through the sync report.
func (a *Agent) BootReapply() error {
	path := a.cfg.SnapshotPath()
	s, err := snapshot.LoadPersisted(path, a.cfg.Limits, a.cfg.SnapshotMaxAge, time.Now())
	if ledgerErr := a.loadLedger(s); ledgerErr != nil {
		if a.ledgerLost {
			a.ensureQuarantine()
		} else if a.ledger != nil && a.ledger.Armed {
			if applyErr := a.apply(nil); applyErr != nil {
				ledgerErr = fmt.Errorf("%v; fail-closed ledger apply: %w", ledgerErr, applyErr)
			}
		}
		return a.noteBootFailure(ledgerErr)
	}
	switch {
	case err == nil:
		// fold whatever a previous run's table counted before the replace
		// zeroes it (traffic that happened is traffic to report)
		a.foldCounters()
		if err := a.apply(s); err != nil {
			return a.noteBootFailure(fmt.Errorf("boot re-apply: %w", err))
		}
		a.counters.MarkReset()
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
	if err := a.apply(nil); err != nil {
		return a.noteBootFailure(fmt.Errorf("boot empty apply: %w", err))
	}
	a.counters.MarkReset()
	a.appliedGeneration, a.applied, a.lastApplied = 0, true, nil
	return nil
}

func (a *Agent) loadLedger(persisted *snapshot.Snapshot) error {
	ledger, err := retirement.Load(a.cfg.RetirementLedgerPath())
	if errors.Is(err, os.ErrNotExist) {
		if persisted != nil && persisted.Retirements != nil {
			a.ledger = nil
			a.ledgerLost = true
			return errors.New("managed snapshot exists without retirement ledger")
		}
		if _, statErr := os.Stat(a.cfg.SnapshotPath()); statErr == nil {
			data, readErr := os.ReadFile(a.cfg.SnapshotPath())
			if readErr != nil {
				a.ledger = nil
				a.ledgerLost = true
				return errors.New("persisted snapshot cannot prove legacy state")
			}
			raw, parseErr := snapshot.Parse(data, a.cfg.Limits)
			if parseErr != nil || raw.Retirements != nil {
				a.ledger = nil
				a.ledgerLost = true
				return errors.New("persisted snapshot cannot prove legacy state without ledger")
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			a.ledger = nil
			a.ledgerLost = true
			return errors.New("persisted snapshot state cannot be inspected")
		}
		k, ok := a.kernel.(managedKernel)
		if !ok {
			a.ledger = nil
			a.ledgerLost = true
			return errors.New("kernel cannot inspect managed state")
		}
		managed, inspectErr := k.HasManagedState()
		if inspectErr != nil || managed {
			a.ledger = nil
			a.ledgerLost = true
			return errors.New("kernel managed state exists or cannot be inspected without ledger")
		}
		ledger, err = retirement.New()
		if err == nil {
			err = ledger.Persist(a.cfg.RetirementLedgerPath())
		}
	}
	if err != nil {
		a.ledger = nil
		a.ledgerLost = true
		return fmt.Errorf("load retirement ledger: %w", err)
	}
	a.ledger = ledger
	if persisted != nil {
		if persisted.Retirements != nil && *persisted.AcknowledgedRetirementHighWater != ledger.AcknowledgedRetirementHighWater {
			a.ledgerLost = true
			return errors.New("persisted snapshot would compact retirement during boot")
		}
		next, prepErr := ledger.Prepare(persisted)
		if prepErr != nil {
			a.ledgerLost = true
			return prepErr
		}
		a.ledger = next
	}
	return nil
}

func (a *Agent) ensureQuarantine() {
	k, ok := a.kernel.(managedKernel)
	if !ok {
		a.log.Error("ledger-loss quarantine unavailable")
		return
	}
	if err := k.Quarantine(a.cfg.PublicIface); err != nil {
		a.log.Error("ledger-loss quarantine failed", "error", err)
	}
}

func (a *Agent) apply(s *snapshot.Snapshot) error {
	var rules []nftctl.Rule
	if s != nil {
		rules = nftctl.Plan(s)
	}
	retirements := a.ledger.Retirements()
	if !a.ledger.Armed && len(retirements) == 0 {
		return a.kernel.Apply(a.cfg.PublicIface, rules, a.cfg.Guards)
	}
	k, ok := a.kernel.(managedKernel)
	if !ok {
		return errors.New("kernel lacks mapping-retirement-v1")
	}
	if err := k.ApplyManaged(a.cfg.PublicIface, rules, retirements, a.cfg.Guards); err != nil {
		return err
	}
	if err := k.VerifyManaged(a.cfg.PublicIface, rules, retirements, a.cfg.Guards); err != nil {
		return fmt.Errorf("managed readback: %w", err)
	}
	cleared := map[string]bool{}
	for _, entry := range a.ledger.Entries {
		if entry.Cleared {
			continue
		}
		if err := a.conntrack.Clear(entry.Retirement); err != nil {
			return fmt.Errorf("conntrack retirement: %w", err)
		}
		cleared[entry.RetirementID] = true
	}
	a.ledger.Clear(cleared)
	if err := a.ledger.Persist(a.cfg.RetirementLedgerPath()); err != nil {
		for i := range a.ledger.Entries {
			if cleared[a.ledger.Entries[i].RetirementID] {
				a.ledger.Entries[i].Cleared = false
			}
		}
		return err
	}
	return nil
}

// noteBootFailure retains a failed boot apply so the poll loop can report and
// retry it, and returns it unchanged for the caller to log. Nothing about the
// applied state is touched: with no successful apply the agent holds no known
// kernel state and keeps reporting generation 0.
func (a *Agent) noteBootFailure(err error) error {
	a.bootFailed = true
	a.setLastErr(err)
	return err
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
	capabilities := []string{sourcepolicy.Capability}
	if !a.ledgerLost && a.ledger != nil {
		capabilities = append(capabilities, retirement.Capability)
	}
	rep := source.Report{
		Capabilities:      capabilities,
		AppliedGeneration: a.appliedGeneration,
		AgentVersion:      version.Version,
		LastError:         a.lastErr,
		Counters:          a.counters.Snapshot(),
	}
	if a.ledger != nil {
		rep.RetirementLedgerID = a.ledger.LedgerID
		rep.MappingIDHighWater = a.ledger.MappingIDHighWater
		rep.FlowMarkHighWater = a.ledger.FlowMarkHighWater
		rep.RetirementHighWater = a.ledger.RetirementHighWater
		rep.ManagedGenerationHighWater = a.ledger.ManagedGenerationHighWater
		rep.RetirementReceipts = []source.RetirementReceipt{}
		for _, entry := range a.ledger.ClearedEntries() {
			rep.RetirementReceipts = append(rep.RetirementReceipts, source.RetirementReceipt{RetirementID: entry.RetirementID, Generation: entry.Generation, MappingID: entry.MappingID, FlowMark: entry.FlowMark, TupleHash: entry.TupleHash, State: "CLEARED"})
		}
	}
	body, changed, err := a.src.Sync(ctx, rep)
	if a.ledgerLost {
		a.ensureQuarantine()
		if err != nil {
			a.log.Warn("sync failed during ledger-loss quarantine", "error", err)
		}
		return false
	}
	if err != nil {
		// the POST itself was the report; nothing else to do until next tick
		a.log.Warn("sync failed", "error", err)
		return false
	}
	if !changed {
		// An unchanged answer means the server compared the desired
		// generation against the applied one we just reported and they are
		// EQUAL — so a retained error describes a snapshot the platform no
		// longer desires (e.g. the operator reverted the offending mapping).
		// Clear it, or the console would show a stale 적용 실패 forever.
		// Cleared before the re-assert below so a re-assert failure still
		// surfaces.
		a.lastErr = nil
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
	nextLedger, err := a.ledger.Prepare(s)
	if err != nil {
		a.log.Error("retirement snapshot rejected", "error", err)
		a.setLastErr(err)
		return false
	}
	for _, old := range a.ledger.Entries {
		still := false
		for _, entry := range nextLedger.Entries {
			if entry.RetirementID == old.RetirementID {
				still = true
			}
		}
		if !still {
			if err := a.conntrack.Zero(old.Retirement); err != nil {
				a.setLastErr(err)
				return false
			}
		}
	}
	ledgerChanged := nextLedger.DesiredHash != a.ledger.DesiredHash || nextLedger.ManagedGenerationHighWater != a.ledger.ManagedGenerationHighWater || nextLedger.Armed != a.ledger.Armed || nextLedger.MappingIDHighWater != a.ledger.MappingIDHighWater || nextLedger.FlowMarkHighWater != a.ledger.FlowMarkHighWater || nextLedger.RetirementHighWater != a.ledger.RetirementHighWater || nextLedger.AcknowledgedRetirementHighWater != a.ledger.AcknowledgedRetirementHighWater || len(nextLedger.Active) != len(a.ledger.Active) || len(nextLedger.Entries) != len(a.ledger.Entries)
	if a.applied && s.Generation == a.appliedGeneration && !ledgerChanged {
		// Generation unchanged — normally a no-op, but re-assert if the kernel
		// table was wiped out of band (e.g. an `nft flush ruleset` or an
		// nftables restart without the ExecStop drop-in): otherwise the
		// mappings would stay gone until the next mapping change.
		if present, perr := a.kernel.Present(); perr == nil && present {
			// converged at this generation with the table intact: any
			// retained error is stale (same reasoning as the unchanged path)
			a.lastErr = nil
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
	if nextLedger.Armed {
		if err := nextLedger.Persist(a.cfg.RetirementLedgerPath()); err != nil {
			a.setLastErr(err)
			return false
		}
		a.ledger = nextLedger
		if err := s.Persist(a.cfg.SnapshotPath()); err != nil {
			a.setLastErr(err)
			return false
		}
	}
	if !nextLedger.Armed {
		a.ledger = nextLedger
	}
	if err := a.apply(s); err != nil {
		a.log.Error("apply failed; generation frozen", "generation", s.Generation, "error", err)
		a.setLastErr(err)
		return false
	}
	if !nextLedger.Armed {
		if err := s.Persist(a.cfg.SnapshotPath()); err != nil {
			a.log.Warn("persist failed (kernel state is applied)", "error", err)
		}
	}
	a.counters.MarkReset()
	advanced := !a.applied || s.Generation != a.appliedGeneration
	a.appliedGeneration, a.applied, a.lastApplied = s.Generation, true, s
	a.bootFailed, a.lastErr = false, nil
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
	if a.ledgerLost {
		a.ensureQuarantine()
		return
	}
	if !a.applied {
		if a.bootFailed {
			a.retryBootConverge()
		}
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
	n := 0
	if a.lastApplied != nil {
		n = len(a.lastApplied.Mappings)
	}
	var current *snapshot.Snapshot
	if a.lastApplied != nil {
		current = a.lastApplied
	}
	if err := a.apply(current); err != nil {
		a.log.Error("re-assert failed", "generation", a.appliedGeneration, "error", err)
		a.setLastErr(err)
		return
	}
	a.counters.MarkReset()
	a.log.Info("re-asserted", "generation", a.appliedGeneration, "mappings", n)
}

// retryBootConverge re-attempts the boot-time converge to the empty set after
// a failed boot apply. It runs on unchanged cycles, which is exactly when
// nothing else would: an unchanged answer means the platform desires
// generation 0, so no snapshot is coming to carry the retry. The table is
// re-applied WITHOUT a presence check, because a leftover table from the
// previous run is present yet wrong. Until this succeeds the agent keeps
// reporting generation 0 and the retained error.
func (a *Agent) retryBootConverge() {
	a.foldCounters()
	if err := a.apply(nil); err != nil {
		a.log.Error("boot converge retry failed", "error", err)
		a.setLastErr(err)
		return
	}
	a.counters.MarkReset()
	a.appliedGeneration, a.applied, a.lastApplied = 0, true, nil
	a.bootFailed = false
	a.log.Info("boot converge retry succeeded")
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

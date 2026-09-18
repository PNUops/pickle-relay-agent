// Package nftctl converges the kernel's DNAT rules to a mapping snapshot.
//
// Ownership contract: this agent owns EXACTLY ONE nftables table
// (ip pickle_relay_dnat) and never touches anything else — flushing the
// ruleset is structurally impossible here (no such call exists in this
// package). Static plumbing (masquerade, MSS clamp) lives in a separate
// table owned by the host's boot configuration.
//
// Atomicity contract: every apply replaces the whole table in ONE netlink
// batch (delete + re-create + counters + sets + all rules). The kernel
// commits or rejects the batch as a unit, so partial application cannot
// exist: either the previous rule set stays or the new one is live.
// Corollary, accepted and documented: a replace resets every counter and
// empties every per-source set — counters are therefore NOT monotonic in the
// kernel (the agent folds reads into cumulative values), and across a
// generation bump the guard state starts cold for a moment.
//
// Netlink is used directly (google/nftables), not an exec of nft(8): no
// child processes means the systemd unit can keep SystemCallFilter and
// MemoryDenyWriteExecute, and there is no rule-string assembly surface.
package nftctl

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/pnuops/pickle-relay-agent/internal/snapshot"
	"github.com/pnuops/pickle-relay-agent/internal/sourcepolicy"
)

// TableName is the one table this agent owns.
const TableName = "pickle_relay_dnat"

const (
	chainName    = "prerouting"
	fwdChainName = "forward"
)

// protocol numbers (avoid a unix dependency for two constants)
const (
	protoTCP = 6
	protoUDP = 17
)

// Rule is the typed plan for one DNAT rule. Building the plan is separated
// from the netlink assembly so validation logic stays unit-testable without
// a kernel.
type Rule struct {
	MappingID    int64
	Proto        snapshot.Proto
	PublicPort   uint16
	Target       [4]byte
	TargetPort   uint16
	SourcePolicy *sourcepolicy.Policy
	FlowMark     uint32

	// Per-mapping guard overrides carried from the snapshot (nil keeps the
	// agent default, explicit 0 disables — see effectiveGuards).
	CtMax          *uint32
	NewConnRate    *uint64
	NewConnBurst   *uint32
	PerSourceRate  *uint64
	PerSourceBurst *uint32
}

// Guards are the per-mapping abuse limits placed AHEAD of the DNAT rule.
// Zero fields disable the corresponding guard. Because the nat chain sees only
// the first packet of each flow, these bound new-connection establishment —
// exactly the conntrack-exhaustion vector that shares fate with user SSH. A
// packet dropped at the dstnat hook leaves its conntrack entry unconfirmed, so
// the drop does NOT consume a state-table slot.
type Guards struct {
	MaxConn        uint32 // `ct count over N drop` — per-mapping concurrent conns; 0 disables
	NewConnRate    uint64 // `limit rate over R/second drop` — new-conn packets/sec; 0 disables
	NewConnBurst   uint32 // burst allowance for the rate guard
	PerSourceRate  uint64 // per SOURCE ADDRESS new-conn packets/sec; 0 disables
	PerSourceBurst uint32 // burst allowance for the per-source guard
}

// effectiveGuards resolves one mapping's guard values: a nil override keeps
// the agent default, an explicit value replaces it — including 0, which
// disables that guard for the mapping. Overrides come from the authenticated
// desired-state authority (the platform), so widening — including disabling —
// is legitimate here; the tighten-only rule constrains the agent-side
// DEFAULTS only (a default must never widen the surface).
func effectiveGuards(r *Rule, g Guards) Guards {
	if r.CtMax != nil {
		g.MaxConn = *r.CtMax
	}
	if r.NewConnRate != nil {
		g.NewConnRate = *r.NewConnRate
	}
	if r.NewConnBurst != nil {
		g.NewConnBurst = *r.NewConnBurst
	}
	if r.PerSourceRate != nil {
		g.PerSourceRate = *r.PerSourceRate
	}
	if r.PerSourceBurst != nil {
		g.PerSourceBurst = *r.PerSourceBurst
	}
	return g
}

// Plan converts a validated snapshot into the ordered rule list.
func Plan(s *snapshot.Snapshot) []Rule {
	rules := make([]Rule, 0, len(s.Mappings))
	for i := range s.Mappings {
		m := &s.Mappings[i]
		rules = append(rules, Rule{
			MappingID:      m.ID,
			Proto:          m.Proto,
			PublicPort:     m.PublicPort,
			Target:         m.Target().As4(),
			TargetPort:     m.TargetPort,
			FlowMark:       valueOrZero(m.FlowMark),
			SourcePolicy:   m.SourcePolicy.Value(),
			CtMax:          m.CtMax,
			NewConnRate:    m.NewConnRate,
			NewConnBurst:   m.NewConnBurst,
			PerSourceRate:  m.PerSourceRate,
			PerSourceBurst: m.PerSourceBurst,
		})
	}
	return rules
}

func valueOrZero(value *uint32) uint32 {
	if value == nil {
		return 0
	}
	return *value
}

// Counters is one mapping's kernel counter readout, keyed by the six named
// counter objects the apply creates per mapping.
type Counters struct {
	NewConns         uint64 // m<id>_new packets (nat chain: first packet per flow)
	InPackets        uint64 // m<id>_in (forward chain, public → VM)
	InBytes          uint64
	OutPackets       uint64 // m<id>_out (forward chain, VM → public)
	OutBytes         uint64
	RateDropped      uint64 // m<id>_rd packets (aggregate rate guard drops)
	ConnDropped      uint64 // m<id>_cd packets (connlimit guard drops)
	PerSourceDropped uint64 // m<id>_pd packets (per-source guard drops)
}

// counterSuffixes are the six per-mapping named counters, in creation order.
var counterSuffixes = []string{"new", "in", "out", "rd", "cd", "pd"}

// counterName renders a per-mapping counter object name, e.g. m101_in.
func counterName(id int64, suffix string) string {
	return fmt.Sprintf("m%d_%s", id, suffix)
}

// parseCounterName inverts counterName. ok=false for anything malformed —
// ReadCounters skips such objects instead of failing the whole read.
func parseCounterName(name string) (id int64, suffix string, ok bool) {
	rest, found := strings.CutPrefix(name, "m")
	if !found {
		return 0, "", false
	}
	num, suffix, found := strings.Cut(rest, "_")
	if !found {
		return 0, "", false
	}
	id, err := strconv.ParseInt(num, 10, 64)
	if err != nil || id < 0 {
		return 0, "", false
	}
	for _, s := range counterSuffixes {
		if suffix == s {
			return id, suffix, true
		}
	}
	return 0, "", false
}

// setName renders a mapping's per-source dynamic set name, e.g. ps101.
func setName(id int64) string { return fmt.Sprintf("ps%d", id) }

// Per-source set sizing: entries expire 60s after the last packet refreshed
// them, and the set holds at most 4096 distinct sources per mapping. When the
// set is FULL the dynset update fails, the guard rule does not match, and the
// packet falls through to the aggregate rate guard — so overflow degrades to
// the coarser limit instead of either failing open or dropping everyone.
const (
	perSourceTimeout = 60 * time.Second
	perSourceSetSize = 4096
)

// perSourceSet is the dynamic set spec backing one mapping's per-source
// guard. Kept as a constructor so its load-bearing fields are testable
// without a kernel.
func perSourceSet(table *nftables.Table, id int64) *nftables.Set {
	return &nftables.Set{
		Table:      table,
		Name:       setName(id),
		KeyType:    nftables.TypeIPAddr,
		Dynamic:    true,
		HasTimeout: true,
		Timeout:    perSourceTimeout,
		Size:       perSourceSetSize,
	}
}

// Present reports whether the agent's own table currently exists in the
// kernel. Used to detect an out-of-band wipe (e.g. someone ran
// `nft flush ruleset` or restarted nftables without the ExecStop drop-in) so
// the agent can re-assert even when the desired generation is unchanged.
func Present() (bool, error) {
	conn, err := nftables.New()
	if err != nil {
		return false, fmt.Errorf("open netlink: %w", err)
	}
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return false, fmt.Errorf("list tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == TableName {
			return true, nil
		}
	}
	return false, nil
}

// Apply replaces the agent's table with the planned rules in one atomic
// netlink batch. iface is the public interface DNAT binds to; g holds the
// default guard values (per-mapping overrides in rules take precedence).
func Apply(iface string, rules []Rule, g Guards) error {
	return ApplyManaged(iface, rules, nil, g)
}

// ApplyManaged atomically replaces active mappings and durable retirement drops.
func ApplyManaged(iface string, rules []Rule, retirements []snapshot.Retirement, g Guards) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("open netlink: %w", err)
	}

	// add-then-delete-then-add: the leading add guarantees the delete has a
	// target inside the same batch even when the table does not exist yet,
	// which is what makes the whole-table replace idempotent AND atomic.
	table := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: TableName}
	conn.AddTable(table)
	conn.DelTable(table)
	conn.AddTable(table)

	accept := nftables.ChainPolicyAccept
	nat := conn.AddChain(&nftables.Chain{
		Name:     chainName,
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Policy:   &accept,
	})
	// The forward chain exists for COUNTING only (policy accept, no verdicts):
	// per-mapping traffic volume is invisible to the nat chain (it sees each
	// flow's first packet), so byte/packet meters live here. New-flow source
	// restrictions and guards remain in prerouting; the host owns other filtering.
	fwd := conn.AddChain(&nftables.Chain{
		Name:     fwdChainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &accept,
	})

	for i := range rules {
		r := &rules[i]
		// All six counters are created for every mapping, even when the guard
		// that would feed one is disabled: a stable name set keeps ReadCounters
		// and the report shape independent of guard configuration.
		for _, sfx := range counterSuffixes {
			conn.AddObj(&nftables.CounterObj{Table: table, Name: counterName(r.MappingID, sfx)})
		}
		if effectiveGuards(r, g).PerSourceRate > 0 {
			if err := conn.AddSet(perSourceSet(table, r.MappingID), nil); err != nil {
				return fmt.Errorf("add set %s: %w", setName(r.MappingID), err)
			}
		}
	}
	activeIndex := 0
	for _, exprs := range renderRules(iface, rules, g) {
		rule := &nftables.Rule{Table: table, Chain: nat, Exprs: exprs}
		if _, ok := exprs[len(exprs)-1].(*expr.NAT); ok {
			rule.UserData = []byte(activeTag(&rules[activeIndex]))
			activeIndex++
		}
		conn.AddRule(rule)
	}
	for _, exprs := range renderForwardRules(iface, rules) {
		conn.AddRule(&nftables.Rule{Table: table, Chain: fwd, Exprs: exprs})
	}
	for i := range retirements {
		for _, direction := range []expr.MetaKey{expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME} {
			conn.AddRule(&nftables.Rule{Table: table, Chain: fwd,
				Exprs:    retirementDropExprs(iface, &retirements[i], direction),
				UserData: []byte(retirementTag(&retirements[i], direction))})
		}
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("apply %d rules: %w", len(rules), err)
	}
	return nil
}

func ApplyQuarantine(iface string) error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	table := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: TableName}
	conn.AddTable(table)
	conn.DelTable(table)
	conn.AddTable(table)
	accept := nftables.ChainPolicyAccept
	conn.AddChain(&nftables.Chain{Name: chainName, Table: table, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest, Policy: &accept})
	fwd := conn.AddChain(&nftables.Chain{Name: fwdChainName, Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &accept})
	for _, d := range []expr.MetaKey{expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME} {
		conn.AddRule(&nftables.Rule{Table: table, Chain: fwd, Exprs: quarantineDropExprs(iface, d), UserData: []byte(fmt.Sprintf("pickle-quarantine:%d", d))})
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("apply quarantine: %w", err)
	}
	return VerifyQuarantine(iface)
}

func quarantineDropExprs(iface string, ifKey expr.MetaKey) []expr.Any {
	mask := make([]byte, 4)
	binary.NativeEndian.PutUint32(mask, ctStatusDNAT)
	return []expr.Any{&expr.Meta{Key: ifKey, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(iface)}, &expr.Ct{Register: 1, Key: expr.CtKeySTATUS}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: make([]byte, 4)}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)}, &expr.Verdict{Kind: expr.VerdictDrop}}
}

func VerifyQuarantine(iface string) error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	table := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: TableName}
	chains, err := conn.ListChains()
	if err != nil {
		return err
	}
	nat, err := conn.GetRules(table, &nftables.Chain{Name: chainName, Table: table})
	if err != nil {
		return err
	}
	fwd, err := conn.GetRules(table, &nftables.Chain{Name: fwdChainName, Table: table})
	if err != nil {
		return err
	}
	sets, err := conn.GetSets(table)
	if err != nil {
		return err
	}
	if len(nat) != 0 || len(fwd) != 2 || len(sets) != 0 {
		return errors.New("quarantine rule count differs")
	}
	if err := validateOwnedChains(chains); err != nil {
		return err
	}
	for i, d := range []expr.MetaKey{expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME} {
		tag := fmt.Sprintf("pickle-quarantine:%d", d)
		if string(fwd[i].UserData) != tag || !managedExprsEqual(fwd[i].Exprs, quarantineDropExprs(iface, d)) {
			return errors.New("quarantine semantic readback differs")
		}
	}
	return nil
}

func HasManagedState() (bool, error) {
	present, err := Present()
	if err != nil || !present {
		return false, err
	}
	conn, err := nftables.New()
	if err != nil {
		return false, err
	}
	table := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: TableName}
	for _, chain := range []string{chainName, fwdChainName} {
		rules, err := conn.GetRules(table, &nftables.Chain{Name: chain, Table: table})
		if err != nil {
			return false, err
		}
		for _, rule := range rules {
			tag := string(rule.UserData)
			if strings.HasPrefix(tag, "pickle-active:") || strings.HasPrefix(tag, "pickle-retired:") || strings.HasPrefix(tag, "pickle-quarantine:") {
				return true, nil
			}
		}
	}
	return false, nil
}

func activeTag(rule *Rule) string {
	hash := snapshot.TupleHash(rule.MappingID, rule.Proto, rule.PublicPort, netip.AddrFrom4(rule.Target).String(), rule.TargetPort, rule.FlowMark)
	return fmt.Sprintf("pickle-active:%d:%s", rule.MappingID, hash)
}
func retirementTag(r *snapshot.Retirement, direction expr.MetaKey) string {
	return fmt.Sprintf("pickle-retired:%s:%d", r.RetirementID, direction)
}

// VerifyManaged reads kernel rule metadata after apply and requires every managed rule.
func VerifyManaged(iface string, rules []Rule, retirements []snapshot.Retirement, guards Guards) error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	table := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: TableName}
	chains, err := conn.ListChains()
	if err != nil {
		return fmt.Errorf("read back chains: %w", err)
	}
	natRules, err := conn.GetRules(table, &nftables.Chain{Name: chainName, Table: table})
	if err != nil {
		return fmt.Errorf("read back active rules: %w", err)
	}
	fwdRules, err := conn.GetRules(table, &nftables.Chain{Name: fwdChainName, Table: table})
	if err != nil {
		return fmt.Errorf("read back retirement rules: %w", err)
	}
	sets, err := conn.GetSets(table)
	if err != nil {
		return fmt.Errorf("read back managed sets: %w", err)
	}
	if err := validateManagedReadback(iface, rules, retirements, guards, chains, natRules, fwdRules, sets); err != nil {
		return err
	}
	actual := map[string]bool{}
	for _, rule := range append(natRules, fwdRules...) {
		if len(rule.UserData) > 0 {
			actual[string(rule.UserData)] = true
		}
	}
	expected := map[string]bool{}
	for i := range rules {
		expected[activeTag(&rules[i])] = true
		if !actual[activeTag(&rules[i])] {
			return fmt.Errorf("active mapping %d missing from readback", rules[i].MappingID)
		}
	}
	for i := range retirements {
		for _, d := range []expr.MetaKey{expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME} {
			tag := retirementTag(&retirements[i], d)
			expected[tag] = true
			if !actual[tag] {
				return fmt.Errorf("retirement %s missing from readback", retirements[i].RetirementID)
			}
		}
	}
	for tag := range actual {
		if (strings.HasPrefix(tag, "pickle-active:") || strings.HasPrefix(tag, "pickle-retired:")) && !expected[tag] {
			return fmt.Errorf("unexpected managed rule %s", tag)
		}
	}
	return nil
}

func validateManagedReadback(iface string, rules []Rule, retirements []snapshot.Retirement, guards Guards, chains []*nftables.Chain, natRules, fwdRules []*nftables.Rule, sets []*nftables.Set) error {
	if err := validateOwnedChains(chains); err != nil {
		return err
	}
	expectedNat := renderRules(iface, rules, guards)
	expectedFwd := renderForwardRules(iface, rules)
	for i := range retirements {
		for _, d := range []expr.MetaKey{expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME} {
			expectedFwd = append(expectedFwd, retirementDropExprs(iface, &retirements[i], d))
		}
	}
	if len(natRules) != len(expectedNat) || len(fwdRules) != len(expectedFwd) {
		return errors.New("managed rule count differs from desired state")
	}
	natTags := expectedNatTags(rules, guards)
	fwdTags := make([]string, 2*len(rules), 2*len(rules)+2*len(retirements))
	for i := range retirements {
		fwdTags = append(fwdTags, retirementTag(&retirements[i], expr.MetaKeyIIFNAME), retirementTag(&retirements[i], expr.MetaKeyOIFNAME))
	}
	for i, want := range expectedNat {
		if string(natRules[i].UserData) != natTags[i] || !managedExprsEqual(natRules[i].Exprs, want) {
			return fmt.Errorf("managed nat rule %d differs from desired semantics or tag", i)
		}
	}
	for i, want := range expectedFwd {
		if string(fwdRules[i].UserData) != fwdTags[i] || !managedExprsEqual(fwdRules[i].Exprs, want) {
			return fmt.Errorf("managed forward rule %d differs from desired semantics or tag", i)
		}
	}
	expectedSets := map[string]*nftables.Set{}
	for i := range rules {
		if effectiveGuards(&rules[i], guards).PerSourceRate > 0 {
			s := perSourceSet(nil, rules[i].MappingID)
			expectedSets[s.Name] = s
		}
	}
	if len(sets) != len(expectedSets) {
		return errors.New("managed set count differs from desired state")
	}
	for _, got := range sets {
		want, ok := expectedSets[got.Name]
		if !ok || got.KeyType.Name != want.KeyType.Name || got.Dynamic != want.Dynamic || got.HasTimeout != want.HasTimeout || got.Timeout != want.Timeout || got.Size != want.Size {
			return fmt.Errorf("managed set %s differs from desired state", got.Name)
		}
	}
	return nil
}

func validateOwnedChains(chains []*nftables.Chain) error {
	owned := []*nftables.Chain{}
	for _, c := range chains {
		if c.Table != nil && c.Table.Family == nftables.TableFamilyIPv4 && c.Table.Name == TableName {
			owned = append(owned, c)
		}
	}
	if len(owned) != 2 {
		return fmt.Errorf("owned table has %d chains, want 2", len(owned))
	}
	want := func(name string, typ nftables.ChainType, hook nftables.ChainHook, priority nftables.ChainPriority) bool {
		for _, c := range owned {
			if c.Name == name && c.Type == typ && c.Hooknum != nil && *c.Hooknum == hook && c.Priority != nil && *c.Priority == priority && c.Policy != nil && *c.Policy == nftables.ChainPolicyAccept {
				return true
			}
		}
		return false
	}
	if !want(chainName, nftables.ChainTypeNAT, *nftables.ChainHookPrerouting, *nftables.ChainPriorityNATDest) || !want(fwdChainName, nftables.ChainTypeFilter, *nftables.ChainHookForward, *nftables.ChainPriorityFilter) {
		return errors.New("managed chain hook or priority differs from desired state")
	}
	return nil
}

func expectedNatTags(rules []Rule, g Guards) []string {
	out := []string{}
	for i := range rules {
		r := &rules[i]
		eff := effectiveGuards(r, g)
		if r.SourcePolicy != nil {
			out = append(out, "")
		}
		if eff.PerSourceRate > 0 {
			out = append(out, "")
		}
		if eff.NewConnRate > 0 {
			out = append(out, "")
		}
		if eff.MaxConn > 0 {
			out = append(out, "")
		}
		out = append(out, activeTag(r))
	}
	return out
}

func managedExprsEqual(got, want []expr.Any) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		switch w := want[i].(type) {
		case *expr.Meta:
			g, ok := got[i].(*expr.Meta)
			if !ok || g.Key != w.Key || g.Register != w.Register || g.SourceRegister != w.SourceRegister {
				return false
			}
		case *expr.Cmp:
			g, ok := got[i].(*expr.Cmp)
			if !ok || g.Op != w.Op || g.Register != w.Register || !bytes.Equal(g.Data, w.Data) {
				return false
			}
		case *expr.Payload:
			g, ok := got[i].(*expr.Payload)
			if !ok || g.OperationType != w.OperationType || g.DestRegister != w.DestRegister || g.SourceRegister != w.SourceRegister || g.Base != w.Base || g.Offset != w.Offset || g.Len != w.Len || g.CsumType != w.CsumType || g.CsumOffset != w.CsumOffset || g.CsumFlags != w.CsumFlags {
				return false
			}
		case *expr.Ct:
			g, ok := got[i].(*expr.Ct)
			if !ok || g.Register != w.Register || g.SourceRegister != w.SourceRegister || g.Key != w.Key || g.Direction != w.Direction || g.OptDirection != w.OptDirection {
				return false
			}
		case *expr.Immediate:
			g, ok := got[i].(*expr.Immediate)
			if !ok || g.Register != w.Register || !bytes.Equal(g.Data, w.Data) {
				return false
			}
		case *expr.Objref:
			g, ok := got[i].(*expr.Objref)
			if !ok || g.Type != w.Type || g.Name != w.Name {
				return false
			}
		case *expr.NAT:
			g, ok := got[i].(*expr.NAT)
			if !ok {
				return false
			}
			addrMaxOK := g.RegAddrMax == w.RegAddrMax || (w.RegAddrMax == 0 && g.RegAddrMax == w.RegAddrMin)
			protoMaxOK := g.RegProtoMax == w.RegProtoMax || (w.RegProtoMax == 0 && g.RegProtoMax == w.RegProtoMin)
			if g.Type != w.Type || g.Family != w.Family || g.RegAddrMin != w.RegAddrMin || !addrMaxOK || g.RegProtoMin != w.RegProtoMin || !protoMaxOK || g.Random != w.Random || g.FullyRandom != w.FullyRandom || g.Persistent != w.Persistent || g.Prefix != w.Prefix {
				return false
			}
		case *expr.Bitwise:
			g, ok := got[i].(*expr.Bitwise)
			if !ok || g.SourceRegister != w.SourceRegister || g.DestRegister != w.DestRegister || g.Len != w.Len || !bytes.Equal(g.Mask, w.Mask) || !bytes.Equal(g.Xor, w.Xor) {
				return false
			}
		case *expr.Verdict:
			g, ok := got[i].(*expr.Verdict)
			if !ok || g.Kind != w.Kind {
				return false
			}
		case *expr.Counter:
			if _, ok := got[i].(*expr.Counter); !ok {
				return false
			}
		case *expr.Limit:
			g, ok := got[i].(*expr.Limit)
			if !ok || g.Type != w.Type || g.Rate != w.Rate || g.Over != w.Over || g.Unit != w.Unit || g.Burst != w.Burst {
				return false
			}
		case *expr.Connlimit:
			g, ok := got[i].(*expr.Connlimit)
			if !ok || g.Count != w.Count || g.Flags != w.Flags {
				return false
			}
		case *expr.Dynset:
			g, ok := got[i].(*expr.Dynset)
			if !ok || g.SrcRegKey != w.SrcRegKey || g.SrcRegData != w.SrcRegData || g.SetName != w.SetName || g.Operation != w.Operation || g.Timeout != w.Timeout || g.Invert != w.Invert || !managedExprsEqual(g.Exprs, w.Exprs) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// ReadCounters reads every named counter in the agent's table and folds the
// six per-mapping objects into one Counters per mapping id. Objects whose
// name does not parse are skipped (never fail the whole read over one
// malformed object). A missing table surfaces as an error — callers treat a
// failed read as "no new data", not as zeros.
func ReadCounters() (map[int64]Counters, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("open netlink: %w", err)
	}
	objs, err := conn.GetObjects(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: TableName})
	if err != nil {
		return nil, fmt.Errorf("get counters: %w", err)
	}
	out := make(map[int64]Counters)
	for _, o := range objs {
		c, okType := o.(*nftables.CounterObj)
		if !okType {
			continue
		}
		id, suffix, okName := parseCounterName(c.Name)
		if !okName {
			continue
		}
		e := out[id]
		switch suffix {
		case "new":
			e.NewConns = c.Packets
		case "in":
			e.InPackets, e.InBytes = c.Packets, c.Bytes
		case "out":
			e.OutPackets, e.OutBytes = c.Packets, c.Bytes
		case "rd":
			e.RateDropped = c.Packets
		case "cd":
			e.ConnDropped = c.Packets
		case "pd":
			e.PerSourceDropped = c.Packets
		}
		out[id] = e
	}
	return out, nil
}

// renderRules produces the ordered per-mapping nat-chain rule set (each entry
// is one rule's expression list). Kept pure — no netlink — so the
// load-bearing properties (guards emitted BEFORE the DNAT rule, the
// 0-disables-skip logic, override resolution) are unit-testable without a
// kernel.
//
// Order within a mapping: source allowlist, per-source guard, aggregate rate
// guard, connlimit guard, then DNAT. The allowlist excludes denied sources
// before they consume guard state. Per-source-first among guards keeps a
// single flooding source from draining the aggregate token bucket, so other
// clients of the same mapping still get through; when the per-source set is
// full, new sources fall through to the aggregate guard (bounded either way).
// Rate-before-connlimit is also deliberate — evaluating the connlimit
// expression adds the packet's tuple to the kernel's conncount list as a side
// effect, so the cheaper token buckets run first and keep flood packets out
// of that list (a sub-rate attacker still reaches the connlimit). A guard
// placed AFTER the DNAT rule would never run (the NAT verdict ends
// evaluation).
func renderRules(iface string, rules []Rule, g Guards) [][]expr.Any {
	out := make([][]expr.Any, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		eff := effectiveGuards(r, g)
		if acl := sourceDropExprs(iface, r); acl != nil {
			out = append(out, acl)
		}
		if eff.PerSourceRate > 0 {
			out = append(out, perSourceExprs(iface, r, eff.PerSourceRate, eff.PerSourceBurst))
		}
		if eff.NewConnRate > 0 {
			out = append(out, guardExprs(iface, r, &expr.Limit{
				Type:  expr.LimitTypePkts,
				Rate:  eff.NewConnRate,
				Over:  true,
				Unit:  expr.LimitTimeSecond,
				Burst: eff.NewConnBurst,
			}, "rd"))
		}
		if eff.MaxConn > 0 {
			out = append(out, guardExprs(iface, r, &expr.Connlimit{Count: eff.MaxConn, Flags: connlimitInv}, "cd"))
		}
		out = append(out, dnatExprs(iface, r))
	}
	return out
}

// NFT_CONNLIMIT_F_INV — "over": drop when the tracked count exceeds Count.
const connlimitInv = 1

// NFT_DYNSET_OP_UPDATE — refresh the element (and its timeout) when it
// already exists; required for meter-style per-source accounting.
const dynsetOpUpdate = 1

// matchExprs renders the mapping selector shared by guard and DNAT rules:
//
//	iifname <iface> <proto> dport <publicPort>
func matchExprs(iface string, r *Rule) []expr.Any {
	proto := byte(protoTCP)
	if r.Proto == snapshot.ProtoUDP {
		proto = protoUDP
	}
	pubPort := make([]byte, 2)
	binary.BigEndian.PutUint16(pubPort, r.PublicPort)
	return []expr.Any{
		// public-interface ingress only (tunnel packets must not re-match)
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(iface)},
		// transport protocol
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		// destination port
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: pubPort},
	}
}

// objrefCounter references a named counter object from a rule, replacing the
// anonymous `counter` statement so the agent can READ the values back
// (anonymous rule counters are only reachable by dumping rules).
func objrefCounter(id int64, suffix string) expr.Any {
	return &expr.Objref{Type: int(nftables.ObjTypeCounter), Name: counterName(id, suffix)}
}

// guardExprs = the mapping match + a limiting expression + a named counter +
// drop. The counter makes a guard's drops visible (`... over N counter
// drop`) — the telemetry that distinguishes an attack in progress from a
// false positive (e.g. a legitimate service whose tracked-entry count outgrew
// MaxConn), and the feed for the sync report / auto-suspension path.
func guardExprs(iface string, r *Rule, limit expr.Any, counterSuffix string) []expr.Any {
	return append(matchExprs(iface, r), limit, objrefCounter(r.MappingID, counterSuffix), &expr.Verdict{Kind: expr.VerdictDrop})
}

// perSourceExprs renders the per-source rate guard:
//
//	iifname <iface> <proto> dport <publicPort>
//	  update @ps<id> { ip saddr limit rate over R/second burst B packets }
//	  counter name m<id>_pd drop
//
// The dynset update tracks each source address in the mapping's dynamic set
// with a per-element token bucket; only packets EXCEEDING their source's rate
// match (Over) and reach the counter+drop. Under-rate packets fail the match
// and continue to the aggregate guards. Reset-on-replace transient: a
// whole-table replace empties the set, so right after a generation bump every
// source starts a fresh bucket (a brief widening, bounded by the aggregate
// guard which suffers the same reset).
func perSourceExprs(iface string, r *Rule, rate uint64, burst uint32) []expr.Any {
	return append(matchExprs(iface, r),
		// ip saddr → register 1 (IPv4 source address, network header offset 12)
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		&expr.Dynset{
			SrcRegKey: 1,
			SetName:   setName(r.MappingID),
			Operation: dynsetOpUpdate,
			Timeout:   perSourceTimeout,
			Exprs: []expr.Any{&expr.Limit{
				Type:  expr.LimitTypePkts,
				Rate:  rate,
				Over:  true,
				Unit:  expr.LimitTimeSecond,
				Burst: burst,
			}},
		},
		objrefCounter(r.MappingID, "pd"),
		&expr.Verdict{Kind: expr.VerdictDrop},
	)
}

// dnatExprs renders the terminal rule:
//
//	iifname <iface> <proto> dport <publicPort> counter name m<id>_new dnat to <target>:<targetPort>
func dnatExprs(iface string, r *Rule) []expr.Any {
	dstPort := make([]byte, 2)
	binary.BigEndian.PutUint16(dstPort, r.TargetPort)
	out := matchExprs(iface, r)
	if r.FlowMark != 0 {
		mark := make([]byte, 4)
		binary.NativeEndian.PutUint32(mark, r.FlowMark)
		out = append(out, &expr.Immediate{Register: 1, Data: mark}, &expr.Ct{Register: 1, SourceRegister: true, Key: expr.CtKeyMARK})
	}
	return append(out,
		// per-mapping counter. NOTE: this rule is in a nat chain, so it counts
		// each flow's FIRST packet only — a new-connection counter, NOT a byte
		// meter (its byte total reads ~0 regardless of volume). Byte metering
		// lives in the forward chain (renderForwardRules).
		objrefCounter(r.MappingID, "new"),
		// dnat to target:port
		&expr.Immediate{Register: 1, Data: r.Target[:]},
		&expr.Immediate{Register: 2, Data: dstPort},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      uint32(nftables.TableFamilyIPv4),
			RegAddrMin:  1,
			RegProtoMin: 2,
		},
	)
}

func retirementDropExprs(iface string, r *snapshot.Retirement, ifKey expr.MetaKey) []expr.Any {
	proto := byte(protoTCP)
	if r.Proto == snapshot.ProtoUDP {
		proto = protoUDP
	}
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, r.PublicPort)
	mark := make([]byte, 4)
	binary.NativeEndian.PutUint32(mark, r.FlowMark)
	dnatMask := make([]byte, 4)
	binary.NativeEndian.PutUint32(dnatMask, ctStatusDNAT)
	return []expr.Any{
		&expr.Meta{Key: ifKey, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(iface)},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		&expr.Ct{Register: 1, Key: expr.CtKeyMARK}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: mark},
		&expr.Ct{Register: 1, Key: expr.CtKeyPROTODST, Direction: ctDirOriginal}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: port},
		&expr.Ct{Register: 1, Key: expr.CtKeySTATUS}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: dnatMask, Xor: make([]byte, 4)}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

// renderForwardRules produces the two counting rules per mapping in the
// forward chain (COUNTING only — no verdicts, filtering stays in the static
// table):
//
//	in : iifname <iface> <proto> ct original proto-dst <publicPort> counter name m<id>_in
//	out: oifname <iface> <proto> ct original proto-dst <publicPort> counter name m<id>_out
//
// Selector rationale: post-DNAT the packet headers no longer carry the public
// port, but the flow's conntrack ORIGINAL tuple does — the original tuple is
// recorded as the first packet arrived (dst = relay:publicPort) and stays
// attached to the flow in BOTH directions, so `ct original proto-dst` picks
// out exactly this mapping's traffic regardless of the rewritten ports.
func renderForwardRules(iface string, rules []Rule) [][]expr.Any {
	out := make([][]expr.Any, 0, 2*len(rules))
	for i := range rules {
		r := &rules[i]
		out = append(out,
			forwardCountExprs(iface, r, expr.MetaKeyIIFNAME, "in"),
			forwardCountExprs(iface, r, expr.MetaKeyOIFNAME, "out"),
		)
	}
	return out
}

// ctDirOriginal is IP_CT_DIR_ORIGINAL: read the conntrack tuple of the
// flow's original direction (client → relay public port).
const ctDirOriginal = 0

// ctStatusDNAT is IPS_DST_NAT from the kernel's conntrack status bits: the
// flow has a destination-NAT binding. The ct status register is a host-endian
// u32, so the bitwise mask below uses native byte order.
const ctStatusDNAT = 0x20

func forwardCountExprs(iface string, r *Rule, ifKey expr.MetaKey, counterSuffix string) []expr.Any {
	proto := byte(protoTCP)
	if r.Proto == snapshot.ProtoUDP {
		proto = protoUDP
	}
	pubPort := make([]byte, 2)
	binary.BigEndian.PutUint16(pubPort, r.PublicPort)
	dnatMask := make([]byte, 4)
	binary.NativeEndian.PutUint32(dnatMask, ctStatusDNAT)
	return []expr.Any{
		// public interface on the matching side (in: ingress, out: egress);
		// the other side is the tunnel
		&expr.Meta{Key: ifKey, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(iface)},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		// ct original proto-dst == publicPort (see renderForwardRules)
		&expr.Ct{Register: 1, Key: expr.CtKeyPROTODST, Direction: ctDirOriginal},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: pubPort},
		// ct status dnat: only flows this table's DNAT actually translated.
		// Without it, traffic to a relay-local listener on the same port
		// (or any non-DNAT flow the interface+port match happens to catch)
		// would pollute the mapping's byte counts.
		&expr.Ct{Register: 1, Key: expr.CtKeySTATUS},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: dnatMask, Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
		objrefCounter(r.MappingID, counterSuffix),
	}
}

// ifname renders an interface name as the kernel's fixed 16-byte,
// NUL-terminated form.
func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n)
	return b
}

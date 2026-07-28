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
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/pnuops/pickle-relay-agent/internal/snapshot"
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
	MappingID  int64
	Proto      snapshot.Proto
	PublicPort uint16
	Target     [4]byte
	TargetPort uint16

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
			CtMax:          m.CtMax,
			NewConnRate:    m.NewConnRate,
			NewConnBurst:   m.NewConnBurst,
			PerSourceRate:  m.PerSourceRate,
			PerSourceBurst: m.PerSourceBurst,
		})
	}
	return rules
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
	// flow's first packet), so byte/packet meters live here. All filtering
	// stays in the host's static table.
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
	for _, exprs := range renderRules(iface, rules, g) {
		conn.AddRule(&nftables.Rule{Table: table, Chain: nat, Exprs: exprs})
	}
	for _, exprs := range renderForwardRules(iface, rules) {
		conn.AddRule(&nftables.Rule{Table: table, Chain: fwd, Exprs: exprs})
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("apply %d rules: %w", len(rules), err)
	}
	return nil
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
// Order within a mapping: per-source guard, then aggregate rate guard, then
// connlimit guard, then DNAT. Per-source-first is deliberate — it keeps a
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
	return append(matchExprs(iface, r),
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

func forwardCountExprs(iface string, r *Rule, ifKey expr.MetaKey, counterSuffix string) []expr.Any {
	proto := byte(protoTCP)
	if r.Proto == snapshot.ProtoUDP {
		proto = protoUDP
	}
	pubPort := make([]byte, 2)
	binary.BigEndian.PutUint16(pubPort, r.PublicPort)
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

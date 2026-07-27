// Package nftctl converges the kernel's DNAT rules to a mapping snapshot.
//
// Ownership contract: this agent owns EXACTLY ONE nftables table
// (ip pickle_relay_dnat) and never touches anything else — flushing the
// ruleset is structurally impossible here (no such call exists in this
// package). Static plumbing (masquerade, MSS clamp) lives in a separate
// table owned by the host's boot configuration.
//
// Atomicity contract: every apply replaces the whole table in ONE netlink
// batch (delete + re-create + all rules). The kernel commits or rejects the
// batch as a unit, so partial application cannot exist: either the previous
// rule set stays or the new one is live.
//
// Netlink is used directly (google/nftables), not an exec of nft(8): no
// child processes means the systemd unit can keep SystemCallFilter and
// MemoryDenyWriteExecute, and there is no rule-string assembly surface.
package nftctl

import (
	"encoding/binary"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/pnuops/pickle-relay-agent/internal/snapshot"
)

// TableName is the one table this agent owns.
const TableName = "pickle_relay_dnat"

const chainName = "prerouting"

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
}

// Plan converts a validated snapshot into the ordered rule list.
func Plan(s *snapshot.Snapshot) []Rule {
	rules := make([]Rule, 0, len(s.Mappings))
	for i := range s.Mappings {
		m := &s.Mappings[i]
		rules = append(rules, Rule{
			MappingID:  m.ID,
			Proto:      m.Proto,
			PublicPort: m.PublicPort,
			Target:     m.Target().As4(),
			TargetPort: m.TargetPort,
		})
	}
	return rules
}

// Apply replaces the agent's table with the planned rules in one atomic
// netlink batch. iface is the public interface DNAT binds to.
func Apply(iface string, rules []Rule) error {
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
	chain := conn.AddChain(&nftables.Chain{
		Name:     chainName,
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Policy:   &accept,
	})

	for i := range rules {
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: ruleExprs(iface, &rules[i]),
		})
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("apply %d rules: %w", len(rules), err)
	}
	return nil
}

// ruleExprs renders one rule:
//
//	iifname <iface> <proto> dport <publicPort> counter dnat to <target>:<targetPort>
func ruleExprs(iface string, r *Rule) []expr.Any {
	proto := byte(protoTCP)
	if r.Proto == snapshot.ProtoUDP {
		proto = protoUDP
	}
	pubPort := make([]byte, 2)
	binary.BigEndian.PutUint16(pubPort, r.PublicPort)
	dstPort := make([]byte, 2)
	binary.BigEndian.PutUint16(dstPort, r.TargetPort)

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
		// per-mapping byte/packet counter (abuse attribution: masquerade
		// destroys client IPs, these counters are the accounting signal)
		&expr.Counter{},
		// dnat to target:port
		&expr.Immediate{Register: 1, Data: r.Target[:]},
		&expr.Immediate{Register: 2, Data: dstPort},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      uint32(nftables.TableFamilyIPv4),
			RegAddrMin:  1,
			RegProtoMin: 2,
		},
	}
}

// ifname renders an interface name as the kernel's fixed 16-byte,
// NUL-terminated form.
func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n)
	return b
}

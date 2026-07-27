package nftctl

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/google/nftables/expr"

	"github.com/pnuops/pickle-relay-agent/internal/snapshot"
)

func testSnapshot(t *testing.T) *snapshot.Snapshot {
	// RFC 5737 documentation addresses only
	s, err := snapshot.Parse([]byte(`{
	  "generation": 3,
	  "mappings": [
	    {"id": 11, "proto": "tcp", "publicPort": 10080, "targetAddr": "192.0.2.8", "targetPort": 80},
	    {"id": 12, "proto": "udp", "publicPort": 10053, "targetAddr": "192.0.2.9", "targetPort": 53}
	  ]}`), snapshot.Limits{
		TargetCIDR: netip.MustParsePrefix("192.0.2.0/24"),
		BandMin:    10000, BandMax: 19999,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPlan(t *testing.T) {
	rules := Plan(testSnapshot(t))
	if len(rules) != 2 {
		t.Fatalf("rules = %d", len(rules))
	}
	if rules[0].Proto != snapshot.ProtoTCP || rules[0].PublicPort != 10080 ||
		rules[0].Target != [4]byte{192, 0, 2, 8} || rules[0].TargetPort != 80 {
		t.Fatalf("rule 0 = %+v", rules[0])
	}
	if rules[1].Proto != snapshot.ProtoUDP || rules[1].Target != [4]byte{192, 0, 2, 9} {
		t.Fatalf("rule 1 = %+v", rules[1])
	}
}

// TestDnatExprs pins the rendered DNAT expression sequence: iifname match,
// l4proto match, dport match, counter, dnat. A drifted order/content here means
// the kernel rule no longer says what the design says.
func TestDnatExprs(t *testing.T) {
	r := Plan(testSnapshot(t))[0]
	exprs := dnatExprs("eth0", &r)
	if len(exprs) != 10 {
		t.Fatalf("expr count = %d, want 10", len(exprs))
	}
	if m, ok := exprs[0].(*expr.Meta); !ok || m.Key != expr.MetaKeyIIFNAME {
		t.Fatalf("expr 0 = %#v, want iifname meta", exprs[0])
	}
	if c, ok := exprs[1].(*expr.Cmp); !ok || string(c.Data[:4]) != "eth0" || len(c.Data) != 16 {
		t.Fatalf("expr 1 = %#v, want 16-byte ifname cmp", exprs[1])
	}
	if c, ok := exprs[3].(*expr.Cmp); !ok || c.Data[0] != protoTCP {
		t.Fatalf("expr 3 = %#v, want tcp proto cmp", exprs[3])
	}
	if p, ok := exprs[4].(*expr.Payload); !ok || p.Offset != 2 || p.Len != 2 {
		t.Fatalf("expr 4 = %#v, want dport payload", exprs[4])
	}
	if c, ok := exprs[5].(*expr.Cmp); !ok || binary.BigEndian.Uint16(c.Data) != 10080 {
		t.Fatalf("expr 5 = %#v, want dport 10080", exprs[5])
	}
	if _, ok := exprs[6].(*expr.Counter); !ok {
		t.Fatalf("expr 6 = %#v, want counter", exprs[6])
	}
	if n, ok := exprs[9].(*expr.NAT); !ok || n.Type != expr.NATTypeDestNAT {
		t.Fatalf("expr 9 = %#v, want dnat", exprs[9])
	}
}

// TestGuardExprs pins the abuse-guard rules: same mapping match, then the
// limiting expression, a counter, then a drop verdict — placed AHEAD of the
// DNAT rule so a flood is dropped before its conntrack entry is confirmed.
func TestGuardExprs(t *testing.T) {
	r := Plan(testSnapshot(t))[0]

	cl := guardExprs("eth0", &r, &expr.Connlimit{Count: 512, Flags: connlimitInv})
	if len(cl) != 9 {
		t.Fatalf("connlimit guard expr count = %d, want 9", len(cl))
	}
	if c, ok := cl[6].(*expr.Connlimit); !ok || c.Count != 512 || c.Flags != connlimitInv {
		t.Fatalf("expr 6 = %#v, want connlimit over 512", cl[6])
	}
	if _, ok := cl[7].(*expr.Counter); !ok {
		t.Fatalf("expr 7 = %#v, want counter (drop visibility)", cl[7])
	}
	if v, ok := cl[8].(*expr.Verdict); !ok || v.Kind != expr.VerdictDrop {
		t.Fatalf("expr 8 = %#v, want drop", cl[8])
	}
	// the match head must be identical to the DNAT rule's, so the guard and the
	// DNAT select exactly the same traffic
	if string(cl[1].(*expr.Cmp).Data[:4]) != "eth0" || binary.BigEndian.Uint16(cl[5].(*expr.Cmp).Data) != 10080 {
		t.Fatalf("guard match head diverged from mapping selector")
	}

	lim := guardExprs("eth0", &r, &expr.Limit{Type: expr.LimitTypePkts, Rate: 200, Over: true, Unit: expr.LimitTimeSecond, Burst: 400})
	if l, ok := lim[6].(*expr.Limit); !ok || l.Rate != 200 || !l.Over || l.Burst != 400 {
		t.Fatalf("expr 6 = %#v, want rate over 200/s burst 400", lim[6])
	}
}

// TestRenderRulesOrderAndSkip pins the load-bearing properties: within a
// mapping the rate guard comes first, then the connlimit guard, then the DNAT
// rule; and a zeroed guard is skipped entirely.
func TestRenderRulesOrderAndSkip(t *testing.T) {
	rules := Plan(testSnapshot(t)) // 2 mappings

	full := renderRules("eth0", rules, Guards{MaxConn: 512, NewConnRate: 200, NewConnBurst: 400})
	if len(full) != 6 { // 2 mappings × (rate + connlimit + dnat)
		t.Fatalf("full render = %d rules, want 6", len(full))
	}
	// mapping 0: [rate][connlimit][dnat]
	if _, ok := full[0][6].(*expr.Limit); !ok {
		t.Fatalf("rule 0 should be the rate guard, got %#v", full[0][6])
	}
	if _, ok := full[1][6].(*expr.Connlimit); !ok {
		t.Fatalf("rule 1 should be the connlimit guard, got %#v", full[1][6])
	}
	if _, ok := full[2][len(full[2])-1].(*expr.NAT); !ok {
		t.Fatalf("rule 2 should be the DNAT rule")
	}

	// only connlimit: rate guard skipped
	onlyCl := renderRules("eth0", rules, Guards{MaxConn: 512})
	if len(onlyCl) != 4 { // 2 × (connlimit + dnat)
		t.Fatalf("connlimit-only render = %d, want 4", len(onlyCl))
	}
	// no guards: just the DNAT rules
	none := renderRules("eth0", rules, Guards{})
	if len(none) != 2 {
		t.Fatalf("no-guard render = %d, want 2 (dnat only)", len(none))
	}
	if _, ok := none[0][len(none[0])-1].(*expr.NAT); !ok {
		t.Fatalf("no-guard rule 0 should be DNAT")
	}
}

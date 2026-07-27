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

// TestRuleExprs pins the rendered expression sequence: iifname match, l4proto
// match, dport match, counter, dnat. A drifted order/content here means the
// kernel rule no longer says what the design says.
func TestRuleExprs(t *testing.T) {
	r := Plan(testSnapshot(t))[0]
	exprs := ruleExprs("eth0", &r)
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

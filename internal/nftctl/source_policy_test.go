package nftctl

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/google/nftables/expr"
	"github.com/pnuops/pickle-relay-agent/internal/snapshot"
	"github.com/pnuops/pickle-relay-agent/internal/sourcepolicy"
)

func TestSourcePolicyDropsOnlyUnlistedMappingTraffic(t *testing.T) {
	for _, proto := range []snapshot.Proto{snapshot.ProtoTCP, snapshot.ProtoUDP} {
		for _, tc := range []struct {
			name   string
			cidrs  []string
			source string
			drop   bool
		}{
			{"first allowed prefix", []string{"192.0.2.0/24", "203.0.113.7/32"}, "192.0.2.1", false},
			{"last allowed prefix", []string{"192.0.2.0/24", "203.0.113.7/32"}, "203.0.113.7", false},
			{"different source", []string{"192.0.2.0/24", "203.0.113.7/32"}, "198.51.100.8", true},
			{"adjacent host", []string{"203.0.113.7/32"}, "203.0.113.8", true},
			{"explicit deny", []string{}, "192.0.2.1", true},
			{"explicit public", []string{"0.0.0.0/0"}, "192.0.2.1", false},
		} {
			t.Run(string(proto)+"/"+tc.name, func(t *testing.T) {
				policy, err := sourcepolicy.Parse(tc.cidrs)
				if err != nil {
					t.Fatal(err)
				}
				r := Rule{MappingID: 101, Proto: proto, PublicPort: 12345, SourcePolicy: policy}
				rules := sourceDropExprs("eth0", &r)
				protocol := byte(protoTCP)
				if proto == snapshot.ProtoUDP {
					protocol = protoUDP
				}
				if got := evaluateSourceDrop(t, rules, "eth0", protocol, 12345, tc.source); got != tc.drop {
					t.Fatalf("source %s dropped = %v, want %v", tc.source, got, tc.drop)
				}
				for _, other := range []struct {
					iface string
					proto byte
					port  uint16
				}{
					{"wg0", protocol, 12345}, {"eth0", protocol, 12346}, {"eth0", 1, 12345},
				} {
					if evaluateSourceDrop(t, rules, other.iface, other.proto, other.port, tc.source) {
						t.Fatalf("policy dropped traffic outside its mapping: %+v", other)
					}
				}
			})
		}
	}
}

func TestSourcePolicyPrecedesGuardsAndNAT(t *testing.T) {
	policy, err := sourcepolicy.Parse([]string{})
	if err != nil {
		t.Fatal(err)
	}
	r := Rule{MappingID: 101, Proto: snapshot.ProtoTCP, PublicPort: 12345, SourcePolicy: policy}
	guards := Guards{MaxConn: 5, NewConnRate: 10, NewConnBurst: 20, PerSourceRate: 2, PerSourceBurst: 4}
	rules := renderRules("eth0", []Rule{r}, guards)
	if len(rules) != 5 {
		t.Fatalf("rule count = %d, want ACL + three guards + DNAT", len(rules))
	}
	if !evaluateSourceDrop(t, rules[0], "eth0", protoTCP, 12345, "192.0.2.1") {
		t.Fatal("source deny is not first")
	}
	last := rules[len(rules)-1]
	if _, ok := last[len(last)-1].(*expr.NAT); !ok {
		t.Fatal("DNAT must remain last")
	}
	for _, e := range rules[0] {
		switch e.(type) {
		case *expr.NAT, *expr.Limit, *expr.Connlimit, *expr.Dynset, *expr.Ct:
			t.Fatalf("ACL has guard or conntrack side effects: %T", e)
		}
	}
	for _, forward := range renderForwardRules("eth0", []Rule{r}) {
		for _, e := range forward {
			if _, ok := e.(*expr.Verdict); ok {
				t.Fatal("source policy must not filter established forward traffic")
			}
		}
	}
	legacy := r
	legacy.SourcePolicy = nil
	if sourceDropExprs("eth0", &legacy) != nil || len(renderRules("eth0", []Rule{legacy}, guards)) != 4 {
		t.Fatal("legacy mapping acquired source restrictions")
	}
}

// evaluateSourceDrop runs the generated selector and IPv4 comparisons against
// packet values. Unexpected expression types fail rather than default to allow.
func evaluateSourceDrop(t *testing.T, rules []expr.Any, iface string, proto byte, port uint16, source string) bool {
	t.Helper()
	registers := map[uint32][]byte{}
	for _, e := range rules {
		switch e := e.(type) {
		case *expr.Meta:
			switch e.Key {
			case expr.MetaKeyIIFNAME:
				registers[e.Register] = ifname(iface)
			case expr.MetaKeyL4PROTO:
				registers[e.Register] = []byte{proto}
			default:
				t.Fatalf("unexpected meta key %v", e.Key)
			}
		case *expr.Payload:
			switch {
			case e.Base == expr.PayloadBaseTransportHeader && e.Offset == 2 && e.Len == 2:
				data := make([]byte, 2)
				binary.BigEndian.PutUint16(data, port)
				registers[e.DestRegister] = data
			case e.Base == expr.PayloadBaseNetworkHeader && e.Offset == 12 && e.Len == 4:
				address := netip.MustParseAddr(source).As4()
				registers[e.DestRegister] = address[:]
			default:
				t.Fatalf("unexpected payload location %+v", e)
			}
		case *expr.Bitwise:
			value := bytes.Clone(registers[e.SourceRegister])
			if len(value) != int(e.Len) || len(e.Mask) != len(value) || len(e.Xor) != len(value) {
				t.Fatalf("incompatible bitwise expression %+v", e)
			}
			for i := range value {
				value[i] = value[i]&e.Mask[i] ^ e.Xor[i]
			}
			registers[e.DestRegister] = value
		case *expr.Cmp:
			equal := bytes.Equal(registers[e.Register], e.Data)
			if e.Op != expr.CmpOpEq && e.Op != expr.CmpOpNeq {
				t.Fatalf("unexpected comparison %+v", e)
			}
			if e.Op == expr.CmpOpEq && !equal || e.Op == expr.CmpOpNeq && equal {
				return false
			}
		case *expr.Counter:
		case *expr.Verdict:
			if e.Kind != expr.VerdictDrop {
				t.Fatalf("unexpected verdict %+v", e)
			}
			return true
		default:
			t.Fatalf("unexpected ACL expression %T", e)
		}
	}
	return false
}

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
	if o, ok := exprs[6].(*expr.Objref); !ok || o.Name != "m11_new" {
		t.Fatalf("expr 6 = %#v, want objref counter m11_new", exprs[6])
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

	cl := guardExprs("eth0", &r, &expr.Connlimit{Count: 512, Flags: connlimitInv}, "cd")
	if len(cl) != 9 {
		t.Fatalf("connlimit guard expr count = %d, want 9", len(cl))
	}
	if c, ok := cl[6].(*expr.Connlimit); !ok || c.Count != 512 || c.Flags != connlimitInv {
		t.Fatalf("expr 6 = %#v, want connlimit over 512", cl[6])
	}
	if o, ok := cl[7].(*expr.Objref); !ok || o.Name != "m11_cd" {
		t.Fatalf("expr 7 = %#v, want objref counter m11_cd (drop visibility)", cl[7])
	}
	if v, ok := cl[8].(*expr.Verdict); !ok || v.Kind != expr.VerdictDrop {
		t.Fatalf("expr 8 = %#v, want drop", cl[8])
	}
	// the match head must be identical to the DNAT rule's, so the guard and the
	// DNAT select exactly the same traffic
	if string(cl[1].(*expr.Cmp).Data[:4]) != "eth0" || binary.BigEndian.Uint16(cl[5].(*expr.Cmp).Data) != 10080 {
		t.Fatalf("guard match head diverged from mapping selector")
	}

	lim := guardExprs("eth0", &r, &expr.Limit{Type: expr.LimitTypePkts, Rate: 200, Over: true, Unit: expr.LimitTimeSecond, Burst: 400}, "rd")
	if l, ok := lim[6].(*expr.Limit); !ok || l.Rate != 200 || !l.Over || l.Burst != 400 {
		t.Fatalf("expr 6 = %#v, want rate over 200/s burst 400", lim[6])
	}
	if o, ok := lim[7].(*expr.Objref); !ok || o.Name != "m11_rd" {
		t.Fatalf("expr 7 = %#v, want objref counter m11_rd", lim[7])
	}
}

// TestRenderRulesOrderAndSkip pins the load-bearing properties: within a
// mapping the per-source guard comes first, then the aggregate rate guard,
// then the connlimit guard, then the DNAT rule; and a zeroed guard is skipped
// entirely.
func TestRenderRulesOrderAndSkip(t *testing.T) {
	rules := Plan(testSnapshot(t)) // 2 mappings

	full := renderRules("eth0", rules, Guards{
		MaxConn: 512, NewConnRate: 200, NewConnBurst: 400,
		PerSourceRate: 50, PerSourceBurst: 100,
	})
	if len(full) != 8 { // 2 mappings × (per-source + rate + connlimit + dnat)
		t.Fatalf("full render = %d rules, want 8", len(full))
	}
	// mapping 0: [per-source][rate][connlimit][dnat]
	if _, ok := full[0][7].(*expr.Dynset); !ok {
		t.Fatalf("rule 0 should be the per-source guard, got %#v", full[0][7])
	}
	if _, ok := full[1][6].(*expr.Limit); !ok {
		t.Fatalf("rule 1 should be the rate guard, got %#v", full[1][6])
	}
	if _, ok := full[2][6].(*expr.Connlimit); !ok {
		t.Fatalf("rule 2 should be the connlimit guard, got %#v", full[2][6])
	}
	if _, ok := full[3][len(full[3])-1].(*expr.NAT); !ok {
		t.Fatalf("rule 3 should be the DNAT rule")
	}

	// only connlimit: per-source and rate guards skipped
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

// TestPerSourceExprs pins the per-source guard rule: mapping match, saddr
// payload, dynset update with an embedded over-limit, named drop counter,
// drop verdict.
func TestPerSourceExprs(t *testing.T) {
	r := Plan(testSnapshot(t))[0]
	exprs := perSourceExprs("eth0", &r, 50, 100)
	if len(exprs) != 10 {
		t.Fatalf("expr count = %d, want 10", len(exprs))
	}
	if p, ok := exprs[6].(*expr.Payload); !ok || p.Base != expr.PayloadBaseNetworkHeader || p.Offset != 12 || p.Len != 4 {
		t.Fatalf("expr 6 = %#v, want ip saddr payload", exprs[6])
	}
	d, ok := exprs[7].(*expr.Dynset)
	if !ok || d.SetName != "ps11" || d.Operation != dynsetOpUpdate || d.SrcRegKey != 1 || d.Timeout != perSourceTimeout {
		t.Fatalf("expr 7 = %#v, want dynset update on ps11", exprs[7])
	}
	if len(d.Exprs) != 1 {
		t.Fatalf("dynset exprs = %d, want 1 embedded limit", len(d.Exprs))
	}
	if l, ok := d.Exprs[0].(*expr.Limit); !ok || l.Rate != 50 || !l.Over || l.Burst != 100 || l.Unit != expr.LimitTimeSecond {
		t.Fatalf("embedded limit = %#v, want over 50/s burst 100", d.Exprs[0])
	}
	if o, ok := exprs[8].(*expr.Objref); !ok || o.Name != "m11_pd" {
		t.Fatalf("expr 8 = %#v, want objref counter m11_pd", exprs[8])
	}
	if v, ok := exprs[9].(*expr.Verdict); !ok || v.Kind != expr.VerdictDrop {
		t.Fatalf("expr 9 = %#v, want drop", exprs[9])
	}
}

// TestPerSourceSetSpec pins the dynamic set backing the per-source guard.
func TestPerSourceSetSpec(t *testing.T) {
	s := perSourceSet(nil, 11)
	if s.Name != "ps11" {
		t.Fatalf("set name = %q", s.Name)
	}
	if !s.Dynamic || !s.HasTimeout || s.Timeout != perSourceTimeout || s.Size != perSourceSetSize {
		t.Fatalf("set spec = %+v, want dynamic, 60s timeout, size 4096", s)
	}
	if s.KeyType.Bytes != 4 {
		t.Fatalf("key type = %+v, want ipv4_addr (4 bytes)", s.KeyType)
	}
}

// TestEffectiveGuards pins the override resolution: nil keeps the default,
// explicit 0 disables, any other value replaces.
func TestEffectiveGuards(t *testing.T) {
	defaults := Guards{MaxConn: 512, NewConnRate: 200, NewConnBurst: 400, PerSourceRate: 50, PerSourceBurst: 100}

	// nil overrides: defaults pass through untouched
	r := Rule{MappingID: 1}
	if g := effectiveGuards(&r, defaults); g != defaults {
		t.Fatalf("nil overrides changed guards: %+v", g)
	}

	zero32, zero64 := uint32(0), uint64(0)
	v32, v64 := uint32(9), uint64(9000)
	r = Rule{
		MappingID:   1,
		CtMax:       &zero32, // explicit 0 → connlimit disabled for this mapping
		NewConnRate: &v64, NewConnBurst: &v32,
		PerSourceRate: &zero64, // explicit 0 → per-source guard disabled
	}
	g := effectiveGuards(&r, defaults)
	if g.MaxConn != 0 || g.PerSourceRate != 0 {
		t.Fatalf("explicit 0 must disable: %+v", g)
	}
	if g.NewConnRate != 9000 || g.NewConnBurst != 9 {
		t.Fatalf("value override not applied: %+v", g)
	}
	if g.PerSourceBurst != 100 {
		t.Fatalf("untouched field must keep default: %+v", g)
	}

	// a disabling override must remove the rendered rule
	rules := []Rule{r}
	rules[0].Proto, rules[0].PublicPort = snapshot.ProtoTCP, 10080
	rendered := renderRules("eth0", rules, defaults)
	if len(rendered) != 2 { // rate guard + dnat (connlimit and per-source disabled)
		t.Fatalf("render with disabling overrides = %d rules, want 2", len(rendered))
	}
	if l, ok := rendered[0][6].(*expr.Limit); !ok || l.Rate != 9000 {
		t.Fatalf("rendered rate = %#v, want overridden 9000", rendered[0][6])
	}
}

// TestPlanCarriesOverrides pins that Plan copies the snapshot's guard
// override pointers onto the rules.
func TestPlanCarriesOverrides(t *testing.T) {
	s, err := snapshot.Parse([]byte(`{
	  "generation": 4,
	  "mappings": [
	    {"id": 21, "proto": "tcp", "publicPort": 10090, "targetAddr": "192.0.2.8", "targetPort": 90,
	     "ctMax": 64, "newConnRate": 10, "newConnBurst": 20, "perSourceRate": 5, "perSourceBurst": 10}
	  ]}`), snapshot.Limits{
		TargetCIDR: netip.MustParsePrefix("192.0.2.0/24"),
		BandMin:    10000, BandMax: 19999,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := Plan(s)[0]
	if r.CtMax == nil || *r.CtMax != 64 || r.NewConnRate == nil || *r.NewConnRate != 10 ||
		r.NewConnBurst == nil || *r.NewConnBurst != 20 || r.PerSourceRate == nil || *r.PerSourceRate != 5 ||
		r.PerSourceBurst == nil || *r.PerSourceBurst != 10 {
		t.Fatalf("overrides not carried: %+v", r)
	}
}

// TestForwardRules pins the counting rules: per mapping an in-rule (iifname)
// and an out-rule (oifname), both selecting by ct original proto-dst AND
// ct status dnat, ending in the named counter and NO verdict (counting only).
func TestForwardRules(t *testing.T) {
	rules := Plan(testSnapshot(t)) // 2 mappings
	fwd := renderForwardRules("eth0", rules)
	if len(fwd) != 4 { // 2 mappings × (in + out)
		t.Fatalf("forward rules = %d, want 4", len(fwd))
	}
	in, out := fwd[0], fwd[1]
	if m, ok := in[0].(*expr.Meta); !ok || m.Key != expr.MetaKeyIIFNAME {
		t.Fatalf("in rule expr 0 = %#v, want iifname", in[0])
	}
	if m, ok := out[0].(*expr.Meta); !ok || m.Key != expr.MetaKeyOIFNAME {
		t.Fatalf("out rule expr 0 = %#v, want oifname", out[0])
	}
	for name, exprs := range map[string][]expr.Any{"in": in, "out": out} {
		if len(exprs) != 10 {
			t.Fatalf("%s rule expr count = %d, want 10", name, len(exprs))
		}
		if c, ok := exprs[1].(*expr.Cmp); !ok || string(c.Data[:4]) != "eth0" || len(c.Data) != 16 {
			t.Fatalf("%s rule expr 1 = %#v, want 16-byte ifname cmp", name, exprs[1])
		}
		if c, ok := exprs[3].(*expr.Cmp); !ok || c.Data[0] != protoTCP {
			t.Fatalf("%s rule expr 3 = %#v, want tcp proto cmp", name, exprs[3])
		}
		ct, ok := exprs[4].(*expr.Ct)
		if !ok || ct.Key != expr.CtKeyPROTODST || ct.Direction != ctDirOriginal {
			t.Fatalf("%s rule expr 4 = %#v, want ct original proto-dst", name, exprs[4])
		}
		if c, ok := exprs[5].(*expr.Cmp); !ok || binary.BigEndian.Uint16(c.Data) != 10080 {
			t.Fatalf("%s rule expr 5 = %#v, want public port 10080", name, exprs[5])
		}
		// ct status dnat: status load, mask to the DNAT bit, must be non-zero
		if ct, ok := exprs[6].(*expr.Ct); !ok || ct.Key != expr.CtKeySTATUS {
			t.Fatalf("%s rule expr 6 = %#v, want ct status", name, exprs[6])
		}
		bw, ok := exprs[7].(*expr.Bitwise)
		if !ok || bw.Len != 4 || binary.NativeEndian.Uint32(bw.Mask) != ctStatusDNAT {
			t.Fatalf("%s rule expr 7 = %#v, want bitwise mask 0x20", name, exprs[7])
		}
		if c, ok := exprs[8].(*expr.Cmp); !ok || c.Op != expr.CmpOpNeq || binary.NativeEndian.Uint32(c.Data) != 0 {
			t.Fatalf("%s rule expr 8 = %#v, want cmp neq 0", name, exprs[8])
		}
		// last expr is the counter — no verdict follows (counting only)
		if _, ok := exprs[len(exprs)-1].(*expr.Objref); !ok {
			t.Fatalf("%s rule must end in the named counter, got %#v", name, exprs[len(exprs)-1])
		}
	}
	if in[9].(*expr.Objref).Name != "m11_in" || out[9].(*expr.Objref).Name != "m11_out" {
		t.Fatalf("counter names = %q/%q, want m11_in/m11_out",
			in[9].(*expr.Objref).Name, out[9].(*expr.Objref).Name)
	}
	// udp mapping's rules select udp
	if c := fwd[2][3].(*expr.Cmp); c.Data[0] != protoUDP {
		t.Fatalf("udp in rule proto = %d, want udp", c.Data[0])
	}
}

// TestCounterNames pins the six per-mapping counter object names and the
// parser's round trip (plus its malformed-name rejection, which ReadCounters
// relies on to skip foreign objects).
func TestCounterNames(t *testing.T) {
	want := []string{"m11_new", "m11_in", "m11_out", "m11_rd", "m11_cd", "m11_pd"}
	for i, sfx := range counterSuffixes {
		if got := counterName(11, sfx); got != want[i] {
			t.Fatalf("counterName(11, %s) = %q, want %q", sfx, got, want[i])
		}
		id, suffix, ok := parseCounterName(want[i])
		if !ok || id != 11 || suffix != sfx {
			t.Fatalf("parseCounterName(%q) = %d/%q/%v", want[i], id, suffix, ok)
		}
	}
	for _, bad := range []string{"", "m", "m_in", "mX_in", "11_in", "m11", "m11_", "m11_xx", "m-1_in", "m11_in_extra_x"} {
		if _, _, ok := parseCounterName(bad); ok {
			t.Fatalf("parseCounterName(%q) accepted", bad)
		}
	}
}

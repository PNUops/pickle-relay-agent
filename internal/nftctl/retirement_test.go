package nftctl

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/pnuops/pickle-relay-agent/internal/snapshot"
	"github.com/pnuops/pickle-relay-agent/internal/sourcepolicy"
)

func TestManagedDNATSetsConntrackMarkBeforeTranslation(t *testing.T) {
	r := Rule{MappingID: 7, Proto: snapshot.ProtoTCP, PublicPort: 10080, Target: [4]byte{192, 0, 2, 8}, TargetPort: 80, FlowMark: 42}
	exprs := dnatExprs("eth0", &r)
	mark, ok := exprs[6].(*expr.Immediate)
	if !ok || binary.NativeEndian.Uint32(mark.Data) != 42 {
		t.Fatalf("mark expression = %#v", exprs[6])
	}
	store, ok := exprs[7].(*expr.Ct)
	if !ok || !store.SourceRegister || store.Key != expr.CtKeyMARK {
		t.Fatalf("ct mark store = %#v", exprs[7])
	}
	if _, ok := exprs[len(exprs)-1].(*expr.NAT); !ok {
		t.Fatal("DNAT must remain terminal")
	}
}

func TestIntegrationManagedApplyAndSemanticReadback(t *testing.T) {
	if os.Getenv("PICKLE_RELAY_KERNEL_TEST") != "1" {
		t.Skip("requires an isolated Linux network namespace")
	}
	iface := os.Getenv("PICKLE_RELAY_TEST_IFACE")
	if iface == "" {
		iface = "lo"
	}
	if os.Getenv("PICKLE_RELAY_TEST_PHASE") == "quarantine" {
		if err := ApplyQuarantine(iface); err != nil {
			t.Fatal(err)
		}
		if err := VerifyQuarantine(iface); err != nil {
			t.Fatal(err)
		}
		return
	}
	base := []Rule{{MappingID: 7, Proto: snapshot.ProtoUDP, PublicPort: 10053, Target: [4]byte{192, 0, 2, 8}, TargetPort: 53, FlowMark: 42}, {MappingID: 8, Proto: snapshot.ProtoUDP, PublicPort: 10054, Target: [4]byte{192, 0, 2, 8}, TargetPort: 54, FlowMark: 43}}
	rules, retirements := base, []snapshot.Retirement{}
	switch os.Getenv("PICKLE_RELAY_TEST_PHASE") {
	case "target-seed":
		rules = []Rule{{MappingID: 9, Proto: snapshot.ProtoUDP, PublicPort: 10055, Target: [4]byte{192, 0, 2, 9}, TargetPort: 55, FlowMark: 42}}
	case "retire":
		r := snapshot.Retirement{RetirementID: "11111111-2222-4333-8444-555555555555", MappingID: 7, Generation: 3, Proto: snapshot.ProtoUDP, PublicPort: 10053, TargetAddr: "192.0.2.8", TargetPort: 53, FlowMark: 42}
		r.TupleHash = snapshot.TupleHash(r.MappingID, r.Proto, r.PublicPort, r.TargetAddr, r.TargetPort, r.FlowMark)
		retirements = []snapshot.Retirement{r}
		rules = base[1:]
	case "resume":
		rules = append(base[1:], Rule{MappingID: 10, Proto: snapshot.ProtoUDP, PublicPort: 10053, Target: [4]byte{192, 0, 2, 8}, TargetPort: 53, FlowMark: 45})
	case "acl-allow", "acl-deny":
		cidrs := []string{"198.51.100.2/32"}
		if os.Getenv("PICKLE_RELAY_TEST_PHASE") == "acl-deny" {
			cidrs = []string{}
		}
		policy, err := sourcepolicy.Parse(cidrs)
		if err != nil {
			t.Fatal(err)
		}
		rules = append(base[1:], Rule{MappingID: 10, Proto: snapshot.ProtoUDP, PublicPort: 10053, Target: [4]byte{192, 0, 2, 8}, TargetPort: 53, FlowMark: 45}, Rule{MappingID: 11, Proto: snapshot.ProtoUDP, PublicPort: 10056, Target: [4]byte{192, 0, 2, 8}, TargetPort: 56, FlowMark: 46, SourcePolicy: policy})
	}
	guards := Guards{MaxConn: 512, NewConnRate: 200, NewConnBurst: 400, PerSourceRate: 50, PerSourceBurst: 100}
	if err := ApplyManaged(iface, rules, retirements, guards); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManaged(iface, rules, retirements, guards); err != nil {
		t.Fatal(err)
	}
}

func TestManagedReadbackRejectsSameTagWithWrongSemantics(t *testing.T) {
	r := Rule{MappingID: 7, Proto: snapshot.ProtoTCP, PublicPort: 10080, Target: [4]byte{192, 0, 2, 8}, TargetPort: 80, FlowMark: 42}
	ret := snapshot.Retirement{RetirementID: "11111111-2222-4333-8444-555555555555", MappingID: 8, Proto: snapshot.ProtoUDP, PublicPort: 10053, TargetAddr: "192.0.2.9", TargetPort: 53, FlowMark: 43}
	accept := nftables.ChainPolicyAccept
	table := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: TableName}
	chains := []*nftables.Chain{{Name: chainName, Table: table, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest, Policy: &accept}, {Name: fwdChainName, Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &accept}}
	nat := []*nftables.Rule{{Exprs: dnatExprs("eth0", &r), UserData: []byte(activeTag(&r))}}
	fwd := []*nftables.Rule{}
	for _, expressions := range renderForwardRules("eth0", []Rule{r}) {
		fwd = append(fwd, &nftables.Rule{Exprs: expressions})
	}
	for _, d := range []expr.MetaKey{expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME} {
		fwd = append(fwd, &nftables.Rule{Exprs: retirementDropExprs("eth0", &ret, d), UserData: []byte(retirementTag(&ret, d))})
	}
	if err := validateManagedReadback("eth0", []Rule{r}, []snapshot.Retirement{ret}, Guards{}, chains, nat, fwd, nil); err != nil {
		t.Fatal(err)
	}
	bad := *nat[0]
	bad.Exprs = append([]expr.Any(nil), nat[0].Exprs...)
	wrong := make([]byte, 4)
	binary.NativeEndian.PutUint32(wrong, 99)
	bad.Exprs[6] = &expr.Immediate{Register: 1, Data: wrong}
	if err := validateManagedReadback("eth0", []Rule{r}, []snapshot.Retirement{ret}, Guards{}, chains, []*nftables.Rule{&bad}, fwd, nil); err == nil {
		t.Fatal("wrong mark expression accepted with same tag")
	}
	badNAT := *nat[0]
	badNAT.Exprs = append([]expr.Any(nil), nat[0].Exprs...)
	n := *(badNAT.Exprs[len(badNAT.Exprs)-1].(*expr.NAT))
	n.Random = true
	n.RegAddrMax = 99
	badNAT.Exprs[len(badNAT.Exprs)-1] = &n
	if err := validateManagedReadback("eth0", []Rule{r}, []snapshot.Retirement{ret}, Guards{}, chains, []*nftables.Rule{&badNAT}, fwd, nil); err == nil {
		t.Fatal("malicious NAT flag accepted")
	}
	badMeta := *nat[0]
	badMeta.Exprs = append([]expr.Any(nil), nat[0].Exprs...)
	m := *(badMeta.Exprs[0].(*expr.Meta))
	m.SourceRegister = true
	badMeta.Exprs[0] = &m
	if err := validateManagedReadback("eth0", []Rule{r}, []snapshot.Retirement{ret}, Guards{}, chains, []*nftables.Rule{&badMeta}, fwd, nil); err == nil {
		t.Fatal("wrong meta register mode accepted")
	}
	missingTag := append([]*nftables.Rule(nil), fwd...)
	missing := *missingTag[len(missingTag)-1]
	missing.UserData = nil
	missingTag[len(missingTag)-1] = &missing
	if err := validateManagedReadback("eth0", []Rule{r}, []snapshot.Retirement{ret}, Guards{}, chains, nat, missingTag, nil); err == nil {
		t.Fatal("missing retirement tag accepted")
	}
	duplicateTag := append([]*nftables.Rule(nil), fwd...)
	duplicate := *duplicateTag[len(duplicateTag)-1]
	duplicate.UserData = duplicateTag[len(duplicateTag)-2].UserData
	duplicateTag[len(duplicateTag)-1] = &duplicate
	if err := validateManagedReadback("eth0", []Rule{r}, []snapshot.Retirement{ret}, Guards{}, chains, nat, duplicateTag, nil); err == nil {
		t.Fatal("duplicate retirement tag accepted")
	}
	swapped := append([]*nftables.Rule(nil), fwd...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if err := validateManagedReadback("eth0", []Rule{r}, []snapshot.Retirement{ret}, Guards{}, chains, nat, swapped, nil); err == nil {
		t.Fatal("swapped forward rules accepted")
	}
	deny, _ := sourcepolicy.Parse([]string{})
	aclRule := r
	aclRule.SourcePolicy = deny
	aclNatExprs := renderRules("eth0", []Rule{aclRule}, Guards{})
	aclNat := []*nftables.Rule{{Exprs: aclNatExprs[0]}, {Exprs: aclNatExprs[1], UserData: []byte(activeTag(&aclRule))}}
	aclFwd := []*nftables.Rule{}
	for _, expressions := range renderForwardRules("eth0", []Rule{aclRule}) {
		aclFwd = append(aclFwd, &nftables.Rule{Exprs: expressions})
	}
	if err := validateManagedReadback("eth0", []Rule{aclRule}, nil, Guards{}, chains, aclNat, aclFwd, nil); err != nil {
		t.Fatal(err)
	}
	wrongACL := append([]*nftables.Rule(nil), aclNat...)
	source := *wrongACL[0]
	source.Exprs = append([]expr.Any(nil), source.Exprs...)
	source.Exprs[len(source.Exprs)-1] = &expr.Verdict{Kind: expr.VerdictAccept}
	wrongACL[0] = &source
	if err := validateManagedReadback("eth0", []Rule{aclRule}, nil, Guards{}, chains, wrongACL, aclFwd, nil); err == nil {
		t.Fatal("wrong source-policy verdict accepted")
	}
	brokenChains := append([]*nftables.Chain(nil), chains...)
	copyChain := *brokenChains[1]
	copyChain.Hooknum = nil
	brokenChains[1] = &copyChain
	if err := validateManagedReadback("eth0", []Rule{r}, []snapshot.Retirement{ret}, Guards{}, brokenChains, nat, fwd, nil); err == nil {
		t.Fatal("missing forward hook accepted")
	}
	extraChains := append([]*nftables.Chain(nil), chains...)
	extraChains = append(extraChains, &nftables.Chain{Name: "unexpected", Table: table})
	if err := validateManagedReadback("eth0", []Rule{r}, []snapshot.Retirement{ret}, Guards{}, extraChains, nat, fwd, nil); err == nil {
		t.Fatal("unexpected owned-table chain accepted")
	}
	guarded := Guards{PerSourceRate: 1, PerSourceBurst: 1}
	guardedNat := []*nftables.Rule{}
	for _, expressions := range renderRules("eth0", []Rule{r}, guarded) {
		guardedNat = append(guardedNat, &nftables.Rule{Exprs: expressions})
	}
	if err := validateManagedReadback("eth0", []Rule{r}, []snapshot.Retirement{ret}, guarded, chains, guardedNat, fwd, nil); err == nil {
		t.Fatal("missing managed set accepted")
	}
}

func TestRetirementDropsBothDirectionsByMarkAndOriginalTuple(t *testing.T) {
	r := snapshot.Retirement{RetirementID: "11111111-2222-4333-8444-555555555555", MappingID: 7, Proto: snapshot.ProtoUDP, PublicPort: 10053, TargetAddr: "192.0.2.8", TargetPort: 53, FlowMark: 42}
	for _, key := range []expr.MetaKey{expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME} {
		exprs := retirementDropExprs("eth0", &r, key)
		if meta, ok := exprs[0].(*expr.Meta); !ok || meta.Key != key {
			t.Fatalf("direction = %#v", exprs[0])
		}
		if ct, ok := exprs[4].(*expr.Ct); !ok || ct.Key != expr.CtKeyMARK {
			t.Fatalf("mark read = %#v", exprs[4])
		}
		if cmp, ok := exprs[5].(*expr.Cmp); !ok || binary.NativeEndian.Uint32(cmp.Data) != 42 {
			t.Fatalf("mark compare = %#v", exprs[5])
		}
		if ct, ok := exprs[6].(*expr.Ct); !ok || ct.Key != expr.CtKeyPROTODST || ct.Direction != ctDirOriginal {
			t.Fatalf("tuple read = %#v", exprs[6])
		}
		if verdict, ok := exprs[len(exprs)-1].(*expr.Verdict); !ok || verdict.Kind != expr.VerdictDrop {
			t.Fatal("retirement is not terminal drop")
		}
	}
}

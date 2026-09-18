package snapshot

import (
	"fmt"
	"strings"
	"testing"
)

func TestManagedSnapshotRequiresExactMarksAndTupleHash(t *testing.T) {
	hash := TupleHash(8, ProtoUDP, 10053, "192.0.2.9", 53, 22)
	body := fmt.Sprintf(`{"generation":4,"mappings":[{"id":7,"proto":"tcp","publicPort":10080,"targetAddr":"192.0.2.8","targetPort":80,"flowMark":21}],"retirements":[{"retirementId":"11111111-2222-4333-8444-555555555555","mappingId":8,"generation":4,"proto":"udp","publicPort":10053,"targetAddr":"192.0.2.9","targetPort":53,"flowMark":22,"tupleHash":"%s"}],"acknowledgedRetirementHighWater":0}`, hash)
	s, err := Parse([]byte(body), testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if s.Mappings[0].FlowMark == nil || *s.Mappings[0].FlowMark != 21 || len(*s.Retirements) != 1 {
		t.Fatalf("snapshot = %+v", s)
	}
	for name, bad := range map[string]string{
		"null mark":           strings.Replace(body, `"flowMark":21`, `"flowMark":null`, 1),
		"zero mark":           strings.Replace(body, `"flowMark":21`, `"flowMark":0`, 1),
		"duplicate mark":      strings.Replace(body, `"flowMark":22`, `"flowMark":21`, 1),
		"bad hash":            strings.Replace(body, hash, strings.Repeat("0", 64), 1),
		"missing retirements": strings.Split(body, `,"retirements"`)[0] + `}`,
	} {
		if _, err := Parse([]byte(bad), testLimits()); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestTupleHashCanonicalForm(t *testing.T) {
	if got := TupleHash(8, ProtoUDP, 10053, "192.0.2.9", 53, 22); got != "7d909bea936f3ead089f7d75f333a3592a589822fbd6e4ef06cb43a3a8d3dbbf" {
		t.Fatalf("tuple hash = %s", got)
	}
}

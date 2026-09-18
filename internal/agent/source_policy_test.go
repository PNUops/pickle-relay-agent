package agent

import (
	"context"
	"strings"
	"testing"
)

func TestPolicyFlowsFromSyncToKernelPlanAndMalformedUpdateIsRejected(t *testing.T) {
	allow := strings.Replace(gen2Body, `"targetPort":80}`, `"targetPort":80,"sourcePolicy":{"allowedCidrs":[]}}`, 1)
	invalid := strings.Replace(strings.Replace(allow, `"generation":2`, `"generation":3`, 1), `{"allowedCidrs":[]}`, `null`, 1)
	src := &fakeSource{responses: []syncResp{{body: []byte(allow), changed: true}, {body: []byte(invalid), changed: true}}}
	kernel := &fakeKernel{}
	a := newTestAgent(t, src, kernel)
	if !a.cycle(context.Background()) {
		t.Fatal("valid policy was not applied")
	}
	if len(kernel.lastRules) != 1 || kernel.lastRules[0].SourcePolicy == nil || len(kernel.lastRules[0].SourcePolicy.Prefixes()) != 0 {
		t.Fatal("explicit deny disappeared before kernel plan")
	}
	if a.cycle(context.Background()) || kernel.applyCalls != 1 || a.appliedGeneration != 2 {
		t.Fatal("malformed policy replaced the current kernel plan")
	}
	if len(src.reports[0].Capabilities) != 2 || src.reports[0].Capabilities[0] != "source-acl-v1" || src.reports[0].Capabilities[1] != "mapping-retirement-v1" {
		t.Fatal("capability absent from heartbeat")
	}
}

//go:build linux

package conntrackctl

import (
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/pnuops/pickle-relay-agent/internal/snapshot"
	"github.com/ti-mo/conntrack"
)

func flowIDs(flows []conntrack.Flow) []string {
	out := make([]string, len(flows))
	for i, f := range flows {
		out[i] = fmt.Sprintf("%d/0x%x", f.ID, f.Mark)
	}
	sort.Strings(out)
	return out
}

func printFlows(t *testing.T, c *conntrack.Conn) {
	t.Helper()
	all, err := c.Dump(nil)
	if err != nil {
		t.Logf("conntrack dump failed: %v", err)
		return
	}
	for _, f := range all {
		t.Logf("flow id=%d mark=0x%x status=0x%x orig=%s reply=%s", f.ID, f.Mark, uint32(f.Status), f.TupleOrig.String(), f.TupleReply.String())
	}
}

func TestExactRetiredFlowPredicate(t *testing.T) {
	r := snapshot.Retirement{Proto: snapshot.ProtoUDP, PublicPort: 10053, TargetAddr: "192.0.2.8", TargetPort: 53, FlowMark: 42}
	f := conntrack.NewFlow(17, 0, netip.MustParseAddr("198.51.100.9"), netip.MustParseAddr("203.0.113.7"), 40000, 10053, 30, 42)
	f.TupleReply.IP.SourceAddress = netip.MustParseAddr("192.0.2.8")
	f.TupleReply.Proto.SourcePort = 53
	f.Status = conntrack.StatusDstNAT
	if !matches(f, r) {
		t.Fatal("exact retired flow not selected")
	}
	other := f
	other.Mark = 43
	if matches(other, r) {
		t.Fatal("different mark selected")
	}
	other = f
	other.TupleReply.IP.SourceAddress = netip.MustParseAddr("192.0.2.9")
	if matches(other, r) {
		t.Fatal("different target selected")
	}
	other = f
	other.TupleOrig.Proto.DestinationPort = 10054
	if matches(other, r) {
		t.Fatal("different public port selected")
	}
}

func TestIntegrationClearDeletesOnlyExactRetiredFlow(t *testing.T) {
	if os.Getenv("PICKLE_RELAY_KERNEL_TEST") != "1" {
		t.Skip("requires an isolated Linux network namespace")
	}
	c, err := conntrack.Dial(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := snapshot.Retirement{RetirementID: "11111111-2222-4333-8444-555555555555", Proto: snapshot.ProtoUDP, PublicPort: 10053, TargetAddr: "192.0.2.8", TargetPort: 53, FlowMark: 42}
	otherTarget := r
	otherTarget.FlowMark = 42
	otherTarget.PublicPort = 10055
	otherTarget.TargetAddr = "192.0.2.9"
	otherTarget.TargetPort = 55
	printFlows(t, c)
	exactBefore, err := flows(c, r)
	if err != nil || len(exactBefore) == 0 {
		t.Fatalf("actual DNAT fixture missing: %v (%d)", err, len(exactBefore))
	}
	targetBefore, err := flows(c, otherTarget)
	if err != nil || len(targetBefore) == 0 {
		t.Fatalf("different target fixture missing: %v (%d)", err, len(targetBefore))
	}
	markBefore, err := c.DumpFilter(conntrack.NewFilter().Mark(43).MarkMask(^uint32(0)), nil)
	if err != nil || len(markBefore) == 0 {
		t.Fatalf("different mark fixture missing: %v (%d)", err, len(markBefore))
	}
	fmt.Printf("conntrack before exact=%v otherMark=%v otherTarget=%v\n", flowIDs(exactBefore), flowIDs(markBefore), flowIDs(targetBefore))
	if err := (Netlink{}).Clear(r); err != nil {
		t.Fatal(err)
	}
	if err := (Netlink{}).Zero(r); err != nil {
		t.Fatal(err)
	}
	targetAfter, _ := flows(c, otherTarget)
	markAfter, _ := c.DumpFilter(conntrack.NewFilter().Mark(43).MarkMask(^uint32(0)), nil)
	fmt.Printf("conntrack after exact=[] otherMark=%v otherTarget=%v\n", flowIDs(markAfter), flowIDs(targetAfter))
	if !reflect.DeepEqual(flowIDs(targetAfter), flowIDs(targetBefore)) || !reflect.DeepEqual(flowIDs(markAfter), flowIDs(markBefore)) {
		t.Fatal("unrelated flow deleted")
	}
}

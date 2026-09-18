//go:build linux

package conntrackctl

import (
	"fmt"
	"github.com/pnuops/pickle-relay-agent/internal/snapshot"
	"github.com/ti-mo/conntrack"
	"time"
)

type Controller interface {
	Clear(snapshot.Retirement) error
	Zero(snapshot.Retirement) error
}
type Netlink struct{}

const operationTimeout = 3 * time.Second

func withConn(fn func(*conntrack.Conn) error) error {
	c, e := conntrack.Dial(nil)
	if e != nil {
		return e
	}
	done := make(chan error, 1)
	go func() { done <- fn(c) }()
	timer := time.NewTimer(operationTimeout)
	defer timer.Stop()
	select {
	case e := <-done:
		_ = c.Close()
		return e
	case <-timer.C:
		_ = c.Close()
		<-done
		return fmt.Errorf("conntrack operation exceeded %s", operationTimeout)
	}
}

func matches(f conntrack.Flow, r snapshot.Retirement) bool {
	proto := uint8(6)
	if r.Proto == snapshot.ProtoUDP {
		proto = 17
	}
	return f.Mark == r.FlowMark && f.TupleOrig.Proto.Protocol == proto && f.TupleOrig.Proto.DestinationPort == r.PublicPort && f.TupleReply.IP.SourceAddress.String() == r.TargetAddr && f.TupleReply.Proto.SourcePort == r.TargetPort && f.Status.DstNAT()
}
func flows(c *conntrack.Conn, r snapshot.Retirement) ([]conntrack.Flow, error) {
	all, e := c.DumpFilter(conntrack.NewFilter().Mark(r.FlowMark).MarkMask(^uint32(0)), nil)
	if e != nil {
		return nil, e
	}
	out := []conntrack.Flow{}
	for _, f := range all {
		if matches(f, r) {
			out = append(out, f)
		}
	}
	return out, nil
}
func (Netlink) Clear(r snapshot.Retirement) error {
	return withConn(func(c *conntrack.Conn) error {
		found, e := flows(c, r)
		if e != nil {
			return e
		}
		for _, f := range found {
			if e = c.Delete(f); e != nil {
				return fmt.Errorf("delete conntrack id %d: %w", f.ID, e)
			}
		}
		left, e := flows(c, r)
		if e != nil {
			return e
		}
		if len(left) != 0 {
			return fmt.Errorf("retirement %s still has %d conntrack flows", r.RetirementID, len(left))
		}
		return nil
	})
}
func (Netlink) Zero(r snapshot.Retirement) error {
	return withConn(func(c *conntrack.Conn) error {
		left, e := flows(c, r)
		if e != nil {
			return e
		}
		if len(left) != 0 {
			return fmt.Errorf("retirement %s regained %d conntrack flows", r.RetirementID, len(left))
		}
		return nil
	})
}

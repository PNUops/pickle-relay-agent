//go:build !linux

package conntrackctl

import (
	"errors"

	"github.com/pnuops/pickle-relay-agent/internal/snapshot"
)

type Controller interface {
	Clear(snapshot.Retirement) error
	Zero(snapshot.Retirement) error
}

type Netlink struct{}

func (Netlink) Clear(snapshot.Retirement) error {
	return errors.New("conntrack retirement requires Linux")
}
func (Netlink) Zero(snapshot.Retirement) error {
	return errors.New("conntrack retirement requires Linux")
}

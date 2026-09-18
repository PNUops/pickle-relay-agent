package nftctl

import (
	"encoding/binary"

	"github.com/google/nftables/expr"
)

// sourceDropExprs drops new flows whose original source matches no allowed
// prefix. The nat prerouting chain runs before destination/source translation
// and is not revisited by established flows, so replacing this rule does not
// terminate an existing conntrack binding. It must precede guards and DNAT.
//
// Each not-equal comparison must succeed before the drop can run. A source
// allowed by any prefix fails that comparison and continues to the guards;
// an empty allowlist reaches the drop immediately after the mapping selector.
func sourceDropExprs(iface string, r *Rule) []expr.Any {
	if r.SourcePolicy == nil {
		return nil
	}
	result := matchExprs(iface, r)
	for _, prefix := range r.SourcePolicy.Prefixes() {
		address := prefix.Addr().As4()
		mask := make([]byte, 4)
		binary.BigEndian.PutUint32(mask, ^uint32(0)<<(32-prefix.Bits()))
		result = append(result,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: make([]byte, 4)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: address[:]},
		)
	}
	return append(result, &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop})
}

// Package sourcepolicy validates source networks before they reach a firewall.
package sourcepolicy

import (
	"fmt"
	"net/netip"
	"slices"
)

// Policy is an immutable allowlist. A nil policy preserves legacy access;
// a non-nil policy with no prefixes denies every source.
type Policy struct {
	prefixes []netip.Prefix
}

// MaxCIDRs bounds the number of comparisons generated for one policy.
const MaxCIDRs = 128

// Parse accepts canonical network CIDRs only. It rejects bare addresses,
// host bits, mapped IPv4, zones and non-canonical spellings.
func Parse(cidrs []string) (*Policy, error) {
	if cidrs == nil {
		return nil, nil
	}
	if len(cidrs) > MaxCIDRs {
		return nil, fmt.Errorf("source CIDR count %d exceeds %d", len(cidrs), MaxCIDRs)
	}
	p := &Policy{prefixes: make([]netip.Prefix, 0, len(cidrs))}
	seen := make(map[netip.Prefix]struct{}, len(cidrs))
	for i, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() || prefix.String() != cidr {
			return nil, fmt.Errorf("source CIDR %d is not a canonical network prefix: %q", i, cidr)
		}
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("source CIDR %d must be IPv4: %q", i, cidr)
		}
		if _, duplicate := seen[prefix]; duplicate {
			return nil, fmt.Errorf("duplicate source CIDR: %q", cidr)
		}
		seen[prefix] = struct{}{}
		p.prefixes = append(p.prefixes, prefix)
	}
	slices.SortFunc(p.prefixes, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return p, nil
}

// Prefixes returns a copy so callers cannot alter validated policy state.
func (p *Policy) Prefixes() []netip.Prefix {
	if p == nil {
		return nil
	}
	return slices.Clone(p.prefixes)
}

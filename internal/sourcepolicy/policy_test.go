package sourcepolicy

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
)

func TestParseRejectsDuplicateAndOversizedPolicies(t *testing.T) {
	if p, err := Parse([]string{"192.0.2.0/24", "192.0.2.0/24"}); err == nil || p != nil {
		t.Fatalf("duplicate prefixes accepted: %v, %v", p, err)
	}
	maximum := make([]string, MaxCIDRs)
	for i := range maximum {
		maximum[i] = fmt.Sprintf("192.0.2.%d/32", i)
	}
	if _, err := Parse(maximum); err != nil {
		t.Fatalf("maximum-size policy rejected: %v", err)
	}
	if p, err := Parse(append(maximum, "198.51.100.1/32")); err == nil || p != nil {
		t.Fatalf("oversized policy accepted: %v, %v", p, err)
	}
}

func TestParsePreservesLegacyAndExplicitDeny(t *testing.T) {
	legacy, err := Parse(nil)
	if err != nil || legacy != nil {
		t.Fatalf("omitted policy = %v, %v", legacy, err)
	}
	deny, err := Parse([]string{})
	if err != nil || deny == nil || len(deny.Prefixes()) != 0 {
		t.Fatalf("explicit deny policy = %v, %v", deny, err)
	}
}

func TestParseRejectsUnsafeOrAmbiguousPrefixes(t *testing.T) {
	for _, value := range []string{
		"", "all", "example.com", "192.0.2.1", "192.0.2.1/24",
		"192.0.2.0/33", "192.000.2.0/24", "192.0.2.0/024",
		" 192.0.2.0/24", "192.0.2.0/24\n", "192.0.2.0/24; allow all",
		"::ffff:192.0.2.1/128", "fe80::%eth0/64", "2001:db8::1/64",
		"2001:DB8::/32", "2001:0db8::/32", "2001:db8::/129",
	} {
		t.Run(value, func(t *testing.T) {
			if p, err := Parse([]string{"198.51.100.0/24", value}); err == nil || p != nil {
				t.Fatalf("invalid policy accepted: %v, %v", p, err)
			}
		})
	}
}

func TestParseCanonicalizesOrderAndDoesNotExposeMutableState(t *testing.T) {
	input := []string{"203.0.113.7/32", "192.0.2.0/24", "0.0.0.0/0"}
	p, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("203.0.113.7/32"),
	}
	input[0] = "198.51.100.0/24"
	got := p.Prefixes()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prefixes = %v, want %v", got, want)
	}
	got[0] = netip.MustParsePrefix("198.51.100.0/24")
	if !reflect.DeepEqual(p.Prefixes(), want) {
		t.Fatal("caller modified policy through returned prefixes")
	}
}

func TestParseRejectsUnsupportedIPv6(t *testing.T) {
	for _, value := range []string{"::/0", "2001:db8::/32", "2001:db8::7/128"} {
		if p, err := Parse([]string{value}); err == nil || p != nil {
			t.Fatalf("IPv6 policy accepted: %v, %v", p, err)
		}
	}
}

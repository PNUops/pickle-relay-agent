package sourcepolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOptionalPolicyPreservesLegacyAndExplicitEmptyOnRoundTrip(t *testing.T) {
	type payload struct {
		Policy Optional `json:"sourcePolicy,omitzero"`
	}
	for _, input := range []string{`{}`, `{"sourcePolicy":{"allowedCidrs":[]}}`, `{"sourcePolicy":{"allowedCidrs":["192.0.2.0/24"]}}`} {
		var value payload
		if err := json.Unmarshal([]byte(input), &value); err != nil {
			t.Fatal(err)
		}
		output, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if string(output) != input {
			t.Fatalf("round trip %s => %s", input, output)
		}
		if value.Policy.IsZero() != (input == `{}`) {
			t.Fatalf("wrong legacy state for %s", input)
		}
	}
}

func TestOptionalPolicyRejectsMalformedOrAmbiguousInput(t *testing.T) {
	for _, input := range []string{
		`null`, `[]`, `true`, `{}`, `{"allowedCidrs":null}`, `{"allowedCidrs":"192.0.2.0/24"}`,
		`{"allowedCidrs":[null]}`, `{"allowedCidrs":[],"unknown":1}`,
		`{"allowedCidrs":[],"allowedCidrs":["0.0.0.0/0"]}`,
		`{"allowedCidrs":["192.0.2.1/24"]}`, `{"allowedCidrs":["192.0.2.0/24","192.0.2.0/24"]}`,
		`{"allowedCidrs":["192.0.2.0/24;deny all"]}`,
	} {
		var policy Optional
		if err := json.Unmarshal([]byte(input), &policy); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	input := `{"allowedCidrs":[` + strings.Repeat(`"192.0.2.0/24",`, MaxCIDRs) + `"198.51.100.0/24"]}`
	var policy Optional
	if err := json.Unmarshal([]byte(input), &policy); err == nil {
		t.Fatal("accepted too many CIDRs")
	}
}

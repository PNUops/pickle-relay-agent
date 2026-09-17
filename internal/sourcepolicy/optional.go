package sourcepolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Capability identifies support for per-route source allowlists.
const Capability = "source-acl-v1"

// Optional distinguishes an omitted legacy policy from an explicit allowlist.
// Keep this value as a struct field with omitzero so JSON null reaches the decoder.
type Optional struct {
	policy *Policy
}

// FromCIDRs constructs a policy for a trusted in-process caller. nil omits it.
func FromCIDRs(cidrs []string) (Optional, error) {
	policy, err := Parse(cidrs)
	return Optional{policy: policy}, err
}

// IsZero preserves omission when legacy state is persisted or marshaled.
func (o Optional) IsZero() bool { return o.policy == nil }

// Value returns the immutable validated policy, or nil for legacy access.
func (o Optional) Value() *Policy { return o.policy }

// UnmarshalJSON refuses null, unknown or repeated fields and incomplete policies.
func (o *Optional) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("sourcePolicy must be an object with allowedCidrs")
	}
	var cidrs []string
	seen := false
	for dec.More() {
		field, err := dec.Token()
		if err != nil || field != "allowedCidrs" || seen {
			return fmt.Errorf("sourcePolicy requires exactly one allowedCidrs field")
		}
		seen = true
		if err := dec.Decode(&cidrs); err != nil {
			return fmt.Errorf("sourcePolicy.allowedCidrs: %w", err)
		}
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	if !seen || cidrs == nil {
		return fmt.Errorf("sourcePolicy.allowedCidrs must be an explicit array")
	}
	policy, err := Parse(cidrs)
	if err != nil {
		return err
	}
	o.policy = policy
	return nil
}

// MarshalJSON preserves an explicit empty allowlist instead of emitting null.
func (o Optional) MarshalJSON() ([]byte, error) {
	if o.IsZero() {
		return []byte("null"), nil
	}
	cidrs := make([]string, 0, len(o.policy.prefixes))
	for _, prefix := range o.policy.prefixes {
		cidrs = append(cidrs, prefix.String())
	}
	return json.Marshal(struct {
		AllowedCIDRs []string `json:"allowedCidrs"`
	}{cidrs})
}

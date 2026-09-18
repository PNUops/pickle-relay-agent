package snapshot

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestSourcePolicyRejectsNullAndPersistsExplicitDeny(t *testing.T) {
	for _, policy := range []string{`null`, `{}`, `{"allowedCidrs":null}`, `{"allowedCidrs":["2001:db8::/32"]}`} {
		body := fmt.Sprintf(`{"generation":1,"mappings":[{"id":1,"proto":"tcp","publicPort":10080,"targetAddr":"192.0.2.8","targetPort":80,"sourcePolicy":%s}]}`, policy)
		if _, err := Parse([]byte(body), testLimits()); err == nil {
			t.Fatalf("accepted %s", policy)
		}
	}
	for _, policy := range []string{"", `,"sourcePolicy":{"allowedCidrs":[]}`, `,"sourcePolicy":{"allowedCidrs":["198.51.100.0/24"]}`} {
		body := fmt.Sprintf(`{"generation":1,"mappings":[{"id":1,"proto":"tcp","publicPort":10080,"targetAddr":"192.0.2.8","targetPort":80%s}]}`, policy)
		s, err := Parse([]byte(body), testLimits())
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "state.json")
		if err := s.Persist(path); err != nil {
			t.Fatal(err)
		}
		got, err := LoadPersisted(path, testLimits(), 24*time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if got.Mappings[0].SourcePolicy.IsZero() != (policy == "") {
			t.Fatal("policy omission changed during persistence")
		}
	}
}

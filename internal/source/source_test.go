package source

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileSourceIgnoresReport(t *testing.T) {
	// RFC 5737 documentation addresses only.
	body := []byte(`{"generation":2,"mappings":[{"id":1,"proto":"tcp","publicPort":10000,"targetAddr":"192.0.2.1","targetPort":80}]}`)
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, body, 0o640); err != nil {
		t.Fatal(err)
	}
	src := FileSource{Path: path}
	id := int64(1)
	rep := Report{
		AppliedGeneration: 99,
		AgentVersion:      "test",
		LastError:         []ErrItem{{MappingID: &id, Message: "ignored"}},
		Counters:          []MappingCounters{{MappingID: 1, NewConns: 5}},
	}
	got, changed, err := src.Sync(context.Background(), rep)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("file source must always report changed=true")
	}
	if string(got) != string(body) {
		t.Fatalf("body = %q", got)
	}
}

func TestFileSourceMissingFile(t *testing.T) {
	src := FileSource{Path: filepath.Join(t.TempDir(), "absent.json")}
	if _, _, err := src.Sync(context.Background(), Report{}); err == nil {
		t.Fatal("missing file must error")
	}
}

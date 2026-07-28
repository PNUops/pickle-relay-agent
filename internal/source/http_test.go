package source

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// All fixture addresses are RFC 5737 documentation ranges.
const changedBody = `{"generation":6,"mappings":[{"id":1,"proto":"tcp","publicPort":10000,"targetAddr":"192.0.2.1","targetPort":80}]}`

func TestHTTPSyncRequestShape(t *testing.T) {
	var gotReq *http.Request
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReq = r.Clone(context.Background())
		gotBody, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{"generation":5}`))
	}))
	defer srv.Close()

	src := NewHTTP(srv.URL+"/internal/relays/1/sync", "tok123")
	rep := Report{AppliedGeneration: 5, AgentVersion: "v1.2.3"}
	body, changed, err := src.Sync(context.Background(), rep)
	if err != nil {
		t.Fatal(err)
	}
	if changed || body != nil {
		t.Fatalf("changed=%v body=%q, want unchanged/nil", changed, body)
	}
	if gotReq.Method != http.MethodPost {
		t.Fatalf("method = %s", gotReq.Method)
	}
	if gotReq.URL.Path != "/internal/relays/1/sync" {
		t.Fatalf("path = %s", gotReq.URL.Path)
	}
	if h := gotReq.Header.Get("Authorization"); h != "Bearer tok123" {
		t.Fatalf("authorization = %q", h)
	}
	if h := gotReq.Header.Get("Content-Type"); h != "application/json" {
		t.Fatalf("content-type = %q", h)
	}
	if h := gotReq.Header.Get("Accept"); h != "application/json" {
		t.Fatalf("accept = %q", h)
	}

	// empty lastError/counters must be OMITTED (omitempty), not null/[]
	var m map[string]any
	if err := json.Unmarshal(gotBody, &m); err != nil {
		t.Fatal(err)
	}
	if m["appliedGeneration"] != float64(5) || m["agentVersion"] != "v1.2.3" {
		t.Fatalf("request body = %s", gotBody)
	}
	for _, k := range []string{"lastError", "counters"} {
		if _, present := m[k]; present {
			t.Fatalf("%s must be omitted when empty: %s", k, gotBody)
		}
	}
}

func TestHTTPSyncReportFieldsSerialized(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{"generation":3}`))
	}))
	defer srv.Close()

	id := int64(42)
	rep := Report{
		AppliedGeneration: 3,
		AgentVersion:      "dev",
		LastError:         []ErrItem{{MappingID: &id, Message: "boom"}, {Message: "general"}},
		Counters: []MappingCounters{{
			MappingID: 42, NewConns: 1, InPackets: 2, InBytes: 3, OutPackets: 4, OutBytes: 5,
			RateDropped: 6, ConnDropped: 7, PerSourceDropped: 8,
		}},
	}
	if _, _, err := NewHTTP(srv.URL, "t").Sync(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	var m struct {
		LastError []map[string]any `json:"lastError"`
		Counters  []map[string]any `json:"counters"`
	}
	if err := json.Unmarshal(gotBody, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.LastError) != 2 || m.LastError[0]["mappingId"] != float64(42) || m.LastError[0]["message"] != "boom" {
		t.Fatalf("lastError = %v", m.LastError)
	}
	if _, present := m.LastError[1]["mappingId"]; present {
		t.Fatalf("unattributed item must omit mappingId: %v", m.LastError[1])
	}
	want := map[string]float64{
		"mappingId": 42, "newConns": 1, "inPackets": 2, "inBytes": 3, "outPackets": 4,
		"outBytes": 5, "rateDropped": 6, "connDropped": 7, "perSourceDropped": 8,
	}
	if len(m.Counters) != 1 {
		t.Fatalf("counters = %v", m.Counters)
	}
	for k, v := range want {
		if m.Counters[0][k] != v {
			t.Fatalf("counter field %s = %v, want %v", k, m.Counters[0][k], v)
		}
	}
}

func TestHTTPSyncChangedReturnsOriginalBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(changedBody))
	}))
	defer srv.Close()

	body, changed, err := NewHTTP(srv.URL, "t").Sync(context.Background(), Report{AppliedGeneration: 5})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("want changed=true")
	}
	if string(body) != changedBody {
		t.Fatalf("body must be the original bytes unmodified: %q", body)
	}
}

func TestHTTPSyncTinyGenerationMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"generation":9}`)) // no mappings, yet not our generation
	}))
	defer srv.Close()

	_, _, err := NewHTTP(srv.URL, "t").Sync(context.Background(), Report{AppliedGeneration: 5})
	if err == nil || !strings.Contains(err.Error(), "generation 9") {
		t.Fatalf("want protocol error, got %v", err)
	}
}

func TestHTTPSyncRejectsBadResponses(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"unknown envelope field": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"generation":5,"extra":true}`))
		},
		"trailing data": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"generation":5}{"generation":6}`))
		},
		"not json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`<html>gateway error</html>`))
		},
		"non-200": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusForbidden)
		},
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(http.StatusTemporaryRedirect)
		},
		"over-limit body": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"generation":5,"mappings":[`))
			filler := strings.Repeat("x", 1<<20)
			for i := 0; i < 9; i++ {
				w.Write([]byte(filler))
			}
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()
			if _, _, err := NewHTTP(srv.URL, "t").Sync(context.Background(), Report{AppliedGeneration: 5}); err == nil {
				t.Fatal("accepted, want error")
			}
		})
	}
}

func TestHTTPSyncConnectionRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing listens anymore
	if _, _, err := NewHTTP(url, "t").Sync(context.Background(), Report{}); err == nil {
		t.Fatal("want connection error")
	}
}

func TestHTTPSyncSanitizesErrItems(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{"generation":0}`))
	}))
	defer srv.Close()

	items := make([]ErrItem, 0, 12)
	items = append(items, ErrItem{Message: "\x1b[31mred\x1b[0m\r\nline\ttab\x7f end"})
	items = append(items, ErrItem{Message: strings.Repeat("한", 600)}) // 1800 bytes of 3-byte runes
	for i := 0; i < 10; i++ {
		items = append(items, ErrItem{Message: "filler"})
	}
	if _, _, err := NewHTTP(srv.URL, "t").Sync(context.Background(), Report{LastError: items}); err != nil {
		t.Fatal(err)
	}
	var m struct {
		LastError []ErrItem `json:"lastError"`
	}
	if err := json.Unmarshal(gotBody, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.LastError) != maxErrItems {
		t.Fatalf("items = %d, want capped at %d", len(m.LastError), maxErrItems)
	}
	if got := m.LastError[0].Message; got != "[31mred[0mlinetab end" {
		t.Fatalf("control chars not stripped: %q", got)
	}
	long := m.LastError[1].Message
	if len(long) > maxErrMessageBytes {
		t.Fatalf("message = %d bytes, want <= %d", len(long), maxErrMessageBytes)
	}
	// the cut must land on a rune boundary (1024/3 leaves a remainder)
	if !strings.HasSuffix(long, "한") || len(long) != 1023 {
		t.Fatalf("truncation not on rune boundary: %d bytes", len(long))
	}
}

func TestSanitizeMessageKeepsPlainText(t *testing.T) {
	in := "mapping 7: target 192.0.2.9 outside allowed 192.0.2.0/28"
	if got := sanitizeMessage(in); got != in {
		t.Fatalf("plain text mangled: %q", got)
	}
}

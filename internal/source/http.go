package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// requestTimeout bounds one whole sync exchange. It must stay BELOW the
	// minimum poll interval (5s): a hung request has to resolve before the
	// next tick, so cycles can never pile up behind a dead server.
	requestTimeout = 4 * time.Second

	// maxResponseBytes caps the response read (8 MiB). A full 10k-mapping
	// snapshot is well under 2 MiB; anything larger is not a snapshot.
	maxResponseBytes = 8 << 20

	// Report bounds, enforced client-side before the request is built. The
	// server enforces the same caps; trimming here keeps a huge or
	// ANSI-laden kernel error from bloating every heartbeat.
	maxErrItems        = 8
	maxErrMessageBytes = 1024
)

// HTTPSource syncs against the platform's relay sync endpoint: one POST
// carries the report up and the desired state back.
type HTTPSource struct {
	url    string
	token  string
	client *http.Client
}

// NewHTTP builds the production sync source. url is the full sync endpoint
// (the relay id is part of the path); token is the per-relay bearer token.
func NewHTTP(url, token string) *HTTPSource {
	return &HTTPSource{url: url, token: token, client: &http.Client{
		Timeout: requestTimeout,
		// Explicit transport with NO proxy: the default transport honors
		// HTTP(S)_PROXY from the environment, which would route the bearer
		// token through whatever host those variables name. The sync target
		// is a direct tunnel address; a proxy is never correct here.
		Transport: &http.Transport{Proxy: nil},
		// Never chase redirects: the sync endpoint answers in place, and a
		// redirect must not be followed with the bearer token attached. The
		// 3xx surfaces below as an unexpected status instead.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

// syncEnvelope is the strict probe of the response: enough to decide
// changed/unchanged WITHOUT parsing mappings — on change the ORIGINAL body
// bytes are handed to snapshot.Parse, keeping that the single validation
// path. DisallowUnknownFields stays deliberately strict; the recorded
// contract rule is "agents upgrade before any sync-response field addition".
type syncEnvelope struct {
	Generation int64           `json:"generation"`
	Mappings   json.RawMessage `json:"mappings"`
}

// Sync implements Source.
func (h *HTTPSource) Sync(ctx context.Context, r Report) ([]byte, bool, error) {
	r.LastError = sanitizeErrItems(r.LastError)
	reqBody, err := json.Marshal(r)
	if err != nil {
		return nil, false, fmt.Errorf("sync: marshal report: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, false, fmt.Errorf("sync: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("sync: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 200 is the only success shape; everything else (including 3xx —
		// a redirect would break the bearer flow) is an error.
		return nil, false, fmt.Errorf("sync: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("sync: read response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return nil, false, fmt.Errorf("sync: response exceeds %d bytes", maxResponseBytes)
	}

	var env syncEnvelope
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, false, fmt.Errorf("sync: bad response envelope: %w", err)
	}
	if dec.More() {
		return nil, false, errors.New("sync: trailing data after response JSON")
	}
	if env.Mappings == nil {
		// Tiny (unchanged) response: it must confirm the generation we
		// reported as applied. Any other value with no mappings attached is
		// a protocol violation — apply nothing.
		if env.Generation != r.AppliedGeneration {
			return nil, false, fmt.Errorf("sync: unchanged response carries generation %d, applied is %d",
				env.Generation, r.AppliedGeneration)
		}
		return nil, false, nil
	}
	// Changed: return the ORIGINAL bytes unmodified. snapshot.Parse is the
	// single place the snapshot is decoded and validated.
	return body, true, nil
}

// sanitizeErrItems applies the wire caps to the report's error items: at
// most maxErrItems entries, each message control-char-stripped and truncated
// to maxErrMessageBytes.
func sanitizeErrItems(items []ErrItem) []ErrItem {
	if items == nil {
		return nil
	}
	if len(items) > maxErrItems {
		items = items[:maxErrItems]
	}
	out := make([]ErrItem, len(items))
	for i, it := range items {
		it.Message = sanitizeMessage(it.Message)
		out[i] = it
	}
	return out
}

// sanitizeMessage strips control characters (agent strings reach operator
// terminals and audit rows — no ANSI escapes, no newline injection) and
// truncates to the byte cap on a rune boundary.
func sanitizeMessage(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	t := b.String()
	if len(t) > maxErrMessageBytes {
		t = t[:maxErrMessageBytes]
		// a byte cut can split a multi-byte rune; trim to the last boundary
		for len(t) > 0 && !utf8.ValidString(t) {
			t = t[:len(t)-1]
		}
	}
	return t
}

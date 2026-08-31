package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakePublisher records what would have been queued.
type fakePublisher struct {
	mu        sync.Mutex
	published [][]byte
	err       error
}

func (p *fakePublisher) Publish(_ context.Context, body []byte) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return "", p.err
	}
	p.published = append(p.published, body)
	return "1-0", nil
}

func (p *fakePublisher) Close() error { return nil }
func (p *fakePublisher) Name() string { return "fake" }

func (p *fakePublisher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.published)
}

func newTestServer(t *testing.T, pub *fakePublisher, tokens []string) http.Handler {
	t.Helper()
	s := New(Options{
		Publisher: pub,
		Tokens:    tokens,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return s.srv.Handler
}

const validEnvelope = `{
	"schema_version": "1.0",
	"source": "test-feed",
	"collected_at": "2026-08-31T06:00:00Z",
	"records": [{"kind": "indicator", "indicator": {"type": "domain", "raw_value": "evil.com"}}]
}`

func post(t *testing.T, h http.Handler, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/envelopes", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSubmitAccepts(t *testing.T) {
	pub := &fakePublisher{}
	h := newTestServer(t, pub, []string{"secret-token"})

	rec := post(t, h, "secret-token", validEnvelope)

	// 202, not 200: the envelope is queued, not written.
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusAccepted, rec.Body)
	}
	var resp submitResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Accepted || resp.Source != "test-feed" || resp.Records != 1 {
		t.Errorf("response = %+v, want accepted with the source and record count", resp)
	}
	if pub.count() != 1 {
		t.Errorf("published %d envelopes, want 1", pub.count())
	}
}

// An unauthenticated write path into a CTI database is not a development
// convenience. Every one of these must be refused, and nothing may be queued.
func TestSubmitRejectsBadAuth(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"no token", ""},
		{"wrong token", "not-the-token"},
		{"prefix of the real token", "secret"},
		{"token with trailing junk", "secret-token-extra"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub := &fakePublisher{}
			h := newTestServer(t, pub, []string{"secret-token"})

			rec := post(t, h, tt.token, validEnvelope)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
			if pub.count() != 0 {
				t.Error("an unauthorised request was queued")
			}
		})
	}
}

// With no tokens configured the endpoint refuses everything rather than
// defaulting to open.
func TestSubmitRefusesWhenNoTokensConfigured(t *testing.T) {
	pub := &fakePublisher{}
	h := newTestServer(t, pub, nil)

	rec := post(t, h, "anything", validEnvelope)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if pub.count() != 0 {
		t.Error("an envelope was queued with no authentication configured")
	}
}

func TestSubmitAcceptsAnyConfiguredToken(t *testing.T) {
	pub := &fakePublisher{}
	h := newTestServer(t, pub, []string{"first", "second", "third"})

	for _, token := range []string{"first", "second", "third"} {
		if rec := post(t, h, token, validEnvelope); rec.Code != http.StatusAccepted {
			t.Errorf("token %q: status = %d, want %d", token, rec.Code, http.StatusAccepted)
		}
	}
}

// A collector author should get their errors back synchronously, with field
// paths, rather than discovering them hours later in a dead-letter table.
func TestSubmitReturnsValidationProblems(t *testing.T) {
	pub := &fakePublisher{}
	h := newTestServer(t, pub, []string{"secret-token"})

	bad := `{
		"schema_version": "1.0",
		"source": "NOT A SLUG",
		"collected_at": "2026-08-31T06:00:00Z",
		"records": [{"kind": "indicator", "indicator": {"type": "domain", "raw_value": ""}}]
	}`
	rec := post(t, h, "secret-token", bad)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusUnprocessableEntity, rec.Body)
	}
	var resp submitResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Problems) < 2 {
		t.Errorf("problems = %v, want one per invalid field", resp.Problems)
	}
	var sawSource, sawValue bool
	for _, p := range resp.Problems {
		if strings.HasPrefix(p, "source:") {
			sawSource = true
		}
		if strings.Contains(p, "raw_value") {
			sawValue = true
		}
	}
	if !sawSource || !sawValue {
		t.Errorf("problems = %v, want both the source and the raw_value named", resp.Problems)
	}
	if pub.count() != 0 {
		t.Error("an invalid envelope was queued")
	}
}

func TestSubmitRejectsMalformedJSON(t *testing.T) {
	pub := &fakePublisher{}
	h := newTestServer(t, pub, []string{"secret-token"})

	rec := post(t, h, "secret-token", `{"schema_version":`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if pub.count() != 0 {
		t.Error("malformed JSON was queued")
	}
}

func TestHealthAndMetrics(t *testing.T) {
	h := newTestServer(t, &fakePublisher{}, []string{"t"})

	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, rec.Code)
		}
	}
}

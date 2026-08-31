// Package httpapi serves the envelope submission endpoint, health probes and
// metrics.
//
// The submission endpoint publishes to the queue; it does not write to
// Postgres. That is not laziness — it is the "exactly one process writes"
// rule. A collector that cannot speak Redis can still submit over HTTP, and the
// envelope still travels the same path, through the same canonicaliser, with
// the same idempotency and the same dead-lettering.
package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/hoardcti/ingest/internal/envelope"
	"github.com/hoardcti/ingest/internal/queue"
	"github.com/hoardcti/ingest/internal/store"
)

// Options configure the server.
type Options struct {
	Addr string

	// Publisher receives accepted envelopes. Nil disables the submission
	// endpoint, leaving only health and metrics.
	Publisher queue.Publisher

	// Store backs the readiness probe.
	Store *store.Store

	// Tokens are the accepted bearer tokens. Submission is refused outright
	// when this is empty — an unauthenticated write path into a threat
	// intelligence database is not a development convenience.
	Tokens []string

	// Registry serves /metrics. Nil uses the default gatherer.
	Registry *prometheus.Registry

	MaxBodyBytes int64
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	Logger *slog.Logger
}

func (o *Options) setDefaults() {
	if o.Addr == "" {
		o.Addr = ":8080"
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = 32 << 20
	}
	if o.ReadTimeout <= 0 {
		o.ReadTimeout = 30 * time.Second
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = 30 * time.Second
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
}

// Server is the HTTP surface.
type Server struct {
	opts Options
	log  *slog.Logger
	srv  *http.Server
}

// New builds the server.
func New(opts Options) *Server {
	opts.setDefaults()
	s := &Server{opts: opts, log: opts.Logger}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("POST /v1/envelopes", s.handleSubmit)

	var gatherer prometheus.Gatherer = prometheus.DefaultGatherer
	if opts.Registry != nil {
		gatherer = opts.Registry
	}
	mux.Handle("GET /metrics", promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{}))

	s.srv = &http.Server{
		Addr:              opts.Addr,
		Handler:           mux,
		ReadTimeout:       opts.ReadTimeout,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      opts.WriteTimeout,
		IdleTimeout:       120 * time.Second,
	}
	return s
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("http server listening",
			"addr", s.opts.Addr,
			"submission", s.opts.Publisher != nil && len(s.opts.Tokens) > 0)
		if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
		defer cancel()
		if err := s.srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("http shutdown: %w", err)
		}
		s.log.Info("http server stopped")
		return nil
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReady reports whether the service can actually do its job. It checks
// Postgres, because an ingest service that cannot write is not ready however
// well it answers HTTP.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.opts.Store == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	if err := s.opts.Store.Ping(ctx); err != nil {
		s.log.Warn("readiness check failed", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "unavailable",
			"reason": "database unreachable",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// submitResponse is what a collector gets back.
type submitResponse struct {
	Accepted  bool     `json:"accepted"`
	MessageID string   `json:"message_id,omitempty"`
	Source    string   `json:"source,omitempty"`
	Records   int      `json:"records,omitempty"`
	Error     string   `json:"error,omitempty"`
	Problems  []string `json:"problems,omitempty"`
}

// handleSubmit accepts an envelope and publishes it to the queue.
//
// The envelope is validated here as well as in the worker. That is deliberate
// duplication: a collector author gets their errors back synchronously, with
// field paths, instead of discovering them hours later in a dead-letter table.
func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if s.opts.Publisher == nil {
		writeJSON(w, http.StatusNotImplemented, submitResponse{
			Error: "submission endpoint is not configured; no queue publisher",
		})
		return
	}
	if len(s.opts.Tokens) == 0 {
		s.log.Error("submission attempted but no tokens are configured; refusing")
		writeJSON(w, http.StatusServiceUnavailable, submitResponse{
			Error: "submission endpoint is not configured; no authentication tokens set",
		})
		return
	}
	if !s.authorised(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="hoardcti-ingest"`)
		writeJSON(w, http.StatusUnauthorized, submitResponse{Error: "invalid or missing bearer token"})
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.opts.MaxBodyBytes))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeJSON(w, http.StatusRequestEntityTooLarge, submitResponse{
				Error: fmt.Sprintf("envelope exceeds the %d byte limit; split it into "+
					"several envelopes", s.opts.MaxBodyBytes),
			})
			return
		}
		writeJSON(w, http.StatusBadRequest, submitResponse{Error: "could not read request body"})
		return
	}

	e, err := envelope.Decode(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, submitResponse{Error: err.Error()})
		return
	}
	if err := envelope.Validate(e); err != nil {
		resp := submitResponse{Source: e.Source, Error: "envelope failed validation"}
		var ve envelope.ValidationErrors
		if errors.As(err, &ve) {
			resp.Problems = make([]string, 0, len(ve))
			for _, p := range ve {
				resp.Problems = append(resp.Problems, p.Error())
			}
		} else {
			resp.Error = err.Error()
		}
		writeJSON(w, http.StatusUnprocessableEntity, resp)
		return
	}

	id, err := s.opts.Publisher.Publish(r.Context(), body)
	if err != nil {
		s.log.Error("publish failed", "source", e.Source, "error", err)
		writeJSON(w, http.StatusServiceUnavailable, submitResponse{
			Source: e.Source,
			Error:  "could not queue the envelope; retry",
		})
		return
	}

	s.log.Info("envelope queued",
		"source", e.Source, "records", len(e.Records), "message_id", id)

	// 202, not 200: the envelope is queued, not yet written. A collector that
	// treats this as "stored" will be wrong about it.
	writeJSON(w, http.StatusAccepted, submitResponse{
		Accepted:  true,
		MessageID: id,
		Source:    e.Source,
		Records:   len(e.Records),
	})
}

// authorised checks the bearer token in constant time, so the endpoint does not
// leak the token's prefix through response timing.
func (s *Server) authorised(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}

	// Every token is compared, with no early exit, for the same reason.
	match := false
	for _, want := range s.opts.Tokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(want)) == 1 {
			match = true
		}
	}
	return match
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

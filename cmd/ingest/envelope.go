package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/hoardcti/ingest/internal/config"
	"github.com/hoardcti/ingest/internal/envelope"
	"github.com/hoardcti/ingest/internal/ingest"
	"github.com/hoardcti/ingest/internal/queue"
)

// validateReport is one file's result from `ingest validate -json`.
//
// The JSON shape is a contract with the GitHub action, which turns it into step
// outputs and a job summary. Parsing the human-readable output instead would
// break the first time someone rewords a message.
type validateReport struct {
	Path          string   `json:"path"`
	OK            bool     `json:"ok"`
	Source        string   `json:"source,omitempty"`
	Records       int      `json:"records"`
	Relationships int      `json:"relationships"`
	Problems      []string `json:"problems,omitempty"`
}

// loadReport is one file's result from `ingest load -json`.
type loadReport struct {
	Path           string `json:"path"`
	OK             bool   `json:"ok"`
	Duplicate      bool   `json:"duplicate"`
	Source         string `json:"source,omitempty"`
	Digest         string `json:"digest,omitempty"`
	RecordsWritten int    `json:"records_written"`
	RecordsDropped int    `json:"records_dropped"`
	Entities       int    `json:"entities"`
	Sightings      int    `json:"sightings"`
	Relationships  int    `json:"relationships"`
	ElapsedMS      int64  `json:"elapsed_ms"`
	Error          string `json:"error,omitempty"`
}

// submitReport is one file's result from `ingest submit -json`.
type submitReport struct {
	Path      string `json:"path"`
	OK        bool   `json:"ok"`
	MessageID string `json:"message_id,omitempty"`
	Source    string `json:"source,omitempty"`
	Records   int    `json:"records"`
	Error     string `json:"error,omitempty"`
}

// cmdValidate checks envelopes against the contract without touching any
// infrastructure. It is what a collector author runs while writing a feed
// mapping, what CI runs over the example envelopes, and what the action's
// mode=validate runs.
func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit results as a JSON array on stdout")
	paths, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New("validate needs at least one file, or - for stdin")
	}

	reports := make([]validateReport, 0, len(paths))
	failed := 0

	for _, path := range paths {
		r := validateReport{Path: path}

		body, err := readEnvelopeFile(path)
		if err != nil {
			r.Problems = []string{err.Error()}
			reports = append(reports, r)
			failed++
			continue
		}
		e, err := envelope.Decode(body)
		if err != nil {
			r.Problems = []string{err.Error()}
			reports = append(reports, r)
			failed++
			continue
		}

		r.Source = e.Source
		r.Records = len(e.Records)
		r.Relationships = len(e.Relationships)

		if err := envelope.Validate(e); err != nil {
			r.Problems = problemStrings(err)
			reports = append(reports, r)
			failed++
			continue
		}
		r.OK = true
		reports = append(reports, r)
	}

	if *asJSON {
		if err := printJSON(reports); err != nil {
			return err
		}
	} else {
		for _, r := range reports {
			if r.OK {
				fmt.Printf("%s: ok — source %s, %d records, %d relationships\n",
					r.Path, r.Source, r.Records, r.Relationships)
				continue
			}
			fmt.Printf("%s: FAIL\n", r.Path)
			for _, p := range r.Problems {
				fmt.Printf("  %s\n", p)
			}
		}
	}

	if failed > 0 {
		return fmt.Errorf("%d of %d envelopes failed validation", failed, len(paths))
	}
	return nil
}

// cmdSubmit publishes envelopes to the queue, exactly as a collector would.
func cmdSubmit(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("submit", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit results as a JSON array on stdout")
	paths, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New("submit needs at least one file, or - for stdin")
	}

	client, err := openRedis(cfg)
	if err != nil {
		return err
	}
	defer client.Close()

	pub := queue.NewRedisPublisher(client, cfg.Queue.Stream, cfg.Queue.MaxLen)

	reports := make([]submitReport, 0, len(paths))
	failed := 0

	for _, path := range paths {
		r := submitReport{Path: path}

		body, err := readEnvelopeFile(path)
		if err != nil {
			r.Error = err.Error()
			reports = append(reports, r)
			failed++
			continue
		}
		e, err := envelope.Decode(body)
		if err != nil {
			r.Error = err.Error()
			reports = append(reports, r)
			failed++
			continue
		}
		r.Source = e.Source
		r.Records = len(e.Records)

		// Validated here so a bad envelope is caught at the keyboard rather
		// than in the dead-letter table.
		if err := envelope.Validate(e); err != nil {
			r.Error = err.Error()
			reports = append(reports, r)
			failed++
			continue
		}

		id, err := pub.Publish(ctx, body)
		if err != nil {
			r.Error = err.Error()
			reports = append(reports, r)
			failed++
			continue
		}
		log.Debug("envelope published", "path", path, "message_id", id)

		r.OK = true
		r.MessageID = id
		reports = append(reports, r)
	}

	if *asJSON {
		if err := printJSON(reports); err != nil {
			return err
		}
	} else {
		for _, r := range reports {
			if r.OK {
				fmt.Printf("%s: queued as %s (source %s, %d records)\n",
					r.Path, r.MessageID, r.Source, r.Records)
			} else {
				fmt.Printf("%s: FAILED — %s\n", r.Path, r.Error)
			}
		}
	}

	if failed > 0 {
		return fmt.Errorf("%d of %d envelopes could not be queued", failed, len(paths))
	}
	return nil
}

// cmdLoad processes envelopes directly, bypassing the queue.
//
// For backfills, for replaying an archived payload after a parser fix, and for
// the action's mode=direct, where the collector's runner is the only process
// that will ever see the envelope. It uses the same service as the queue
// consumer, so canonicalisation, idempotency and dead-lettering are identical.
func cmdLoad(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("load", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit results as a JSON array on stdout")
	paths, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New("load needs at least one file, or - for stdin")
	}

	st, err := openStore(ctx, cfg, log, true)
	if err != nil {
		return err
	}
	defer st.Close()

	ar, err := openArchive(ctx, cfg)
	if err != nil {
		return err
	}

	client, err := openRedis(cfg)
	if err != nil && !errors.Is(err, config.ErrNoRedis) {
		return err
	}
	if client != nil {
		defer client.Close()
	}

	svc := ingest.New(st, ar, openCache(cfg, client), ingest.Options{
		CacheTTL:     cfg.Redis.CacheTTL,
		MaxDropRatio: cfg.Ingest.MaxDropRatio,
		Logger:       log,
	})

	reports := make([]loadReport, 0, len(paths))
	failed := 0

	for _, path := range paths {
		r := loadReport{Path: path}

		body, err := readEnvelopeFile(path)
		if err != nil {
			r.Error = err.Error()
			reports = append(reports, r)
			failed++
			continue
		}

		// Every file is attempted, and failures are reported together. A run
		// that stopped at the first bad envelope would leave the rest of a
		// collection silently unprocessed, and the operator would not know how
		// much was missing.
		res, err := svc.Process(ctx, body)
		r.Source = res.Source
		r.Digest = res.Digest
		if err != nil {
			r.Error = err.Error()
			reports = append(reports, r)
			failed++
			continue
		}

		r.OK = true
		r.Duplicate = res.Duplicate
		r.RecordsWritten = res.RecordsWritten
		r.RecordsDropped = res.RecordsDropped
		r.Entities = res.Entities
		r.Sightings = res.Sightings
		r.Relationships = res.Relationships
		r.ElapsedMS = res.Elapsed.Round(time.Millisecond).Milliseconds()
		reports = append(reports, r)
	}

	if *asJSON {
		if err := printJSON(reports); err != nil {
			return err
		}
	} else {
		for _, r := range reports {
			switch {
			case !r.OK:
				fmt.Printf("%s: FAILED — %s\n", r.Path, r.Error)
			case r.Duplicate:
				fmt.Printf("%s: already ingested (digest %s); nothing written\n",
					r.Path, shortDigest(r.Digest))
			default:
				fmt.Printf("%s: %d records, %d entities, %d sightings, %d relationships",
					r.Path, r.RecordsWritten, r.Entities, r.Sightings, r.Relationships)
				if r.RecordsDropped > 0 {
					fmt.Printf(", %d dropped", r.RecordsDropped)
				}
				fmt.Printf(" in %dms\n", r.ElapsedMS)
			}
		}
	}

	if failed > 0 {
		return fmt.Errorf("%d of %d envelopes could not be ingested", failed, len(paths))
	}
	return nil
}

// problemStrings flattens a validation error into one line per problem, keeping
// the JSON path that locates each one.
func problemStrings(err error) []string {
	var ve envelope.ValidationErrors
	if errors.As(err, &ve) {
		out := make([]string, 0, len(ve))
		for _, p := range ve {
			out = append(out, p.Error())
		}
		return out
	}
	return []string{err.Error()}
}

// printJSON writes a report array to stdout. Reports go to stdout and logs to
// stderr, so `ingest load -json … | jq` works without the log lines fouling it.
func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return nil
}

func shortDigest(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

func readEnvelopeFile(path string) ([]byte, error) {
	if path == "-" {
		body, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		return body, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return body, nil
}

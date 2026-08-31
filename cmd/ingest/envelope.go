package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/hoardcti/ingest/internal/config"
	"github.com/hoardcti/ingest/internal/envelope"
	"github.com/hoardcti/ingest/internal/ingest"
	"github.com/hoardcti/ingest/internal/queue"
)

// cmdValidate checks an envelope against the contract without touching any
// infrastructure. It is what a collector author runs while writing a feed
// mapping, and what CI runs over the example envelopes.
func cmdValidate(args []string) error {
	if len(args) < 1 {
		return errors.New("validate needs a file, or - for stdin")
	}

	failed := 0
	for _, path := range args {
		body, err := readEnvelopeFile(path)
		if err != nil {
			return err
		}
		e, err := envelope.Decode(body)
		if err != nil {
			fmt.Printf("%s: FAIL\n  %v\n", path, err)
			failed++
			continue
		}
		if err := envelope.Validate(e); err != nil {
			fmt.Printf("%s: FAIL\n", path)
			var ve envelope.ValidationErrors
			if errors.As(err, &ve) {
				for _, p := range ve {
					fmt.Printf("  %s\n", p.Error())
				}
			} else {
				fmt.Printf("  %v\n", err)
			}
			failed++
			continue
		}
		fmt.Printf("%s: ok — source %s, %d records, %d relationships\n",
			path, e.Source, len(e.Records), len(e.Relationships))
	}

	if failed > 0 {
		return fmt.Errorf("%d of %d envelopes failed validation", failed, len(args))
	}
	return nil
}

// cmdSubmit publishes an envelope to the queue, exactly as a collector would.
func cmdSubmit(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string) error {
	if len(args) < 1 {
		return errors.New("submit needs a file, or - for stdin")
	}

	client, err := openRedis(cfg)
	if err != nil {
		return err
	}
	defer client.Close()

	pub := queue.NewRedisPublisher(client, cfg.Queue.Stream, cfg.Queue.MaxLen)

	for _, path := range args {
		body, err := readEnvelopeFile(path)
		if err != nil {
			return err
		}
		e, err := envelope.Decode(body)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		// Validated here so a bad envelope is caught at the keyboard rather
		// than in the dead-letter table.
		if err := envelope.Validate(e); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}

		id, err := pub.Publish(ctx, body)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		log.Debug("envelope published", "path", path, "message_id", id)
		fmt.Printf("%s: queued as %s (source %s, %d records)\n",
			path, id, e.Source, len(e.Records))
	}
	return nil
}

// cmdLoad processes an envelope directly, bypassing the queue.
//
// For backfills and for replaying an archived payload after a parser fix, where
// going through the queue adds nothing but a hop. It uses the same service, so
// canonicalisation, idempotency and dead-lettering all behave identically.
func cmdLoad(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string) error {
	if len(args) < 1 {
		return errors.New("load needs a file, or - for stdin")
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

	for _, path := range args {
		body, err := readEnvelopeFile(path)
		if err != nil {
			return err
		}
		res, err := svc.Process(ctx, body)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if res.Duplicate {
			fmt.Printf("%s: already ingested (digest %s); nothing written\n",
				path, res.Digest[:12])
			continue
		}
		fmt.Printf("%s: %d records, %d entities, %d sightings, %d relationships",
			path, res.RecordsWritten, res.Entities, res.Sightings, res.Relationships)
		if res.RecordsDropped > 0 {
			fmt.Printf(", %d dropped", res.RecordsDropped)
		}
		fmt.Printf(" in %s\n", shortDuration(res.Elapsed))
	}
	return nil
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

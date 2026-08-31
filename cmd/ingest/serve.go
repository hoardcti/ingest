package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"golang.org/x/sync/errgroup"

	"github.com/hoardcti/ingest/internal/config"
	"github.com/hoardcti/ingest/internal/httpapi"
	"github.com/hoardcti/ingest/internal/ingest"
	"github.com/hoardcti/ingest/internal/queue"
	"github.com/hoardcti/ingest/internal/telemetry"
)

func cmdServe(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	httpOnly := fs.Bool("http-only", false,
		"serve the submission endpoint and metrics without consuming the queue")
	noHTTP := fs.Bool("no-http", false,
		"consume the queue without serving HTTP (also disables /metrics)")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}
	if *httpOnly && *noHTTP {
		return errors.New("-http-only and -no-http are mutually exclusive")
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	metrics := telemetry.New(registry)

	st, err := openStore(ctx, cfg, log, true)
	if err != nil {
		return err
	}
	defer st.Close()

	ar, err := openArchive(ctx, cfg)
	if err != nil {
		return err
	}
	if cfg.Archive.Backend == "none" {
		log.Warn("no raw archive configured; upstream payloads are not being kept. " +
			"Reprocessing history later will require re-scraping, which for many " +
			"CTI sources is not possible")
	}

	// A missing Redis URL is a deployment choice; a malformed one is a mistake,
	// and starting up half-configured would hide it.
	redisClient, err := openRedis(cfg)
	if err != nil {
		if !errors.Is(err, config.ErrNoRedis) {
			return err
		}
		log.Warn("no Redis configured; the queue and the indicator lookup cache " +
			"are both unavailable")
		redisClient = nil
	} else {
		defer redisClient.Close()
	}

	svc := ingest.New(st, ar, openCache(cfg, redisClient), ingest.Options{
		CacheTTL:     cfg.Redis.CacheTTL,
		MaxDropRatio: cfg.Ingest.MaxDropRatio,
		Logger:       log,
		Metrics:      metrics,
	})

	g, gctx := errgroup.WithContext(ctx)

	var publisher queue.Publisher
	if redisClient != nil {
		publisher = queue.NewRedisPublisher(redisClient, cfg.Queue.Stream, cfg.Queue.MaxLen)
	}

	if !*noHTTP {
		if cfg.HTTP.Addr == "" {
			log.Warn("HTTP server disabled; /metrics and the health probes are unavailable")
		} else {
			srv := httpapi.New(httpapi.Options{
				Addr:         cfg.HTTP.Addr,
				Publisher:    publisher,
				Store:        st,
				Tokens:       cfg.HTTP.Tokens,
				Registry:     registry,
				MaxBodyBytes: cfg.HTTP.MaxBodyBytes,
				ReadTimeout:  cfg.HTTP.ReadTimeout,
				WriteTimeout: cfg.HTTP.WriteTimeout,
				Logger:       log,
			})
			if len(cfg.HTTP.Tokens) == 0 {
				log.Warn("no " + config.EnvPrefix + "HTTP_TOKENS configured; the " +
					"submission endpoint will refuse every request")
			}
			g.Go(func() error { return srv.Run(gctx) })
		}
	}

	if !*httpOnly {
		if redisClient == nil {
			return fmt.Errorf("%w, so there is no queue to consume; set it, or run "+
				"with -http-only", config.ErrNoRedis)
		}
		consumer, err := queue.NewRedisConsumer(ctx, queue.RedisOptions{
			Client:        redisClient,
			Stream:        cfg.Queue.Stream,
			Group:         cfg.Queue.Group,
			Consumer:      cfg.Queue.Consumer,
			MinIdle:       cfg.Queue.MinIdle,
			ClaimInterval: cfg.Queue.ClaimInterval,
			MaxLen:        cfg.Queue.MaxLen,
			Logger:        log,
		})
		if err != nil {
			return err
		}
		defer consumer.Close()

		runner := ingest.NewRunner(svc, consumer, ingest.RunnerOptions{
			Workers:       cfg.Queue.Workers,
			Prefetch:      cfg.Queue.Prefetch,
			BlockTimeout:  cfg.Queue.BlockTimeout,
			MaxDeliveries: cfg.Queue.MaxDeliveries,
			Logger:        log,
			Metrics:       metrics,
		})
		g.Go(func() error { return runner.Run(gctx) })
	}

	// Provision partitions up front and then leave it to `ingest maintain` on a
	// schedule. Doing it here as well means a fresh deployment on the 1st of the
	// month does not spend its first minutes sending sightings to the default
	// partition.
	if _, err := st.EnsureSightingPartitionsAhead(ctx, 2); err != nil {
		log.Warn("could not provision sighting partitions at startup", "error", err)
	}

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

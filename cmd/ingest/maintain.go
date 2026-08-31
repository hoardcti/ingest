package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"time"

	"github.com/hoardcti/ingest/internal/config"
)

// cmdMaintain does the periodic housekeeping the sighting table needs. Run it
// from cron, daily.
func cmdMaintain(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("maintain", flag.ContinueOnError)
	ahead := fs.Int("ahead", 2,
		"how many months of sighting partitions to provision beyond the current one")
	retain := fs.Duration("retain", 0,
		"drop sighting partitions entirely older than this, e.g. 4380h for ~6 months. "+
			"Zero keeps everything")
	dryRun := fs.Bool("dry-run", false, "report what retention would drop without dropping it")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}

	st, err := openStore(ctx, cfg, log, false)
	if err != nil {
		return err
	}
	defer st.Close()

	created, err := st.EnsureSightingPartitionsAhead(ctx, *ahead)
	if err != nil {
		return err
	}
	fmt.Printf("sighting partitions present through %s\n", created[len(created)-1])

	// The default partition must stay empty. Rows in it are sightings that
	// arrived when their partition did not exist — and their presence makes
	// creating that partition fail, so this quietly compounds.
	n, err := st.DefaultPartitionRows(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		fmt.Printf("WARNING: %d rows in sighting_default.\n", n)
		fmt.Println("  These arrived while their partition did not exist, and they now")
		fmt.Println("  block that partition from being created. Detach the default,")
		fmt.Println("  create the missing partitions, move the rows across, reattach.")
		fmt.Println("  Then find out why maintain was not running.")
	}

	if *retain > 0 {
		cutoff := time.Now().Add(-*retain)
		if *dryRun {
			fmt.Printf("dry run: would drop sighting partitions ending on or before %s\n",
				cutoff.UTC().Format(time.RFC3339))
			return nil
		}
		dropped, err := st.DropSightingPartitionsBefore(ctx, cutoff)
		if err != nil {
			return err
		}
		if len(dropped) == 0 {
			fmt.Printf("no sighting partitions older than %s\n",
				cutoff.UTC().Format("2006-01-02"))
		}
		for _, name := range dropped {
			fmt.Printf("dropped %s\n", name)
		}
	}

	return nil
}

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"

	"github.com/hoardcti/ingest/internal/config"
)

func cmdSource(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string) error {
	if len(args) == 0 {
		return errors.New("source needs a subcommand: add, list")
	}

	st, err := openStore(ctx, cfg, log, false)
	if err != nil {
		return err
	}
	defer st.Close()

	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("source add", flag.ContinueOnError)
		name := fs.String("name", "", "human-readable feed name (defaults to the slug)")
		url := fs.String("url", "", "where the feed is published")
		tlp := fs.String("tlp", "clear", "TLP marking: clear, green, amber, amber+strict, red")
		disabled := fs.Bool("disabled", false, "register the feed but do not accept envelopes from it")
		positional, err := parseFlags(fs, args[1:])
		if err != nil {
			return err
		}
		if len(positional) != 1 {
			return errors.New("source add needs exactly one slug, " +
				"e.g. `ingest source add abuse-ch-urlhaus -name URLhaus`")
		}
		slug := positional[0]

		src, err := st.UpsertSource(ctx, slug, *name, *url, *tlp, !*disabled)
		if err != nil {
			return err
		}
		state := "enabled"
		if !src.Enabled {
			state = "disabled"
		}
		fmt.Printf("%s  %s  %s  (%s)\n", src.ID.String(), src.Slug, src.Name, state)
		return nil

	case "list":
		sources, err := st.ListSources(ctx)
		if err != nil {
			return err
		}
		if len(sources) == 0 {
			fmt.Println("no sources configured; add one with `ingest source add <slug>`")
			return nil
		}
		fmt.Printf("%-38s  %-9s  %-28s  %s\n", "ID", "STATE", "SLUG", "NAME")
		for _, s := range sources {
			state := "enabled"
			if !s.Enabled {
				state = "disabled"
			}
			fmt.Printf("%-38s  %-9s  %-28s  %s\n", s.ID.String(), state, s.Slug, s.Name)
		}
		return nil

	default:
		return fmt.Errorf("unknown source subcommand %q", args[0])
	}
}

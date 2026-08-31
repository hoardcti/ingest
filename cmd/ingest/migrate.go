package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/hoardcti/ingest/internal/config"
	"github.com/hoardcti/ingest/internal/store"
)

func cmdMigrate(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string) error {
	if len(args) == 0 {
		return errors.New("migrate needs a subcommand: up, up-to, down, down-to, status, version")
	}

	// checkSchema is off here for the obvious reason: this is the command that
	// resolves a pending schema.
	st, err := openStore(ctx, cfg, log, false)
	if err != nil {
		return err
	}
	defer st.Close()

	m, err := store.NewMigrator(st, log)
	if err != nil {
		return err
	}
	defer m.Close()

	switch args[0] {
	case "up":
		applied, err := m.Up(ctx)
		if err != nil {
			return err
		}
		return reportApplied(ctx, m, applied, "applied")

	case "up-to":
		v, err := parseVersion(args, "up-to")
		if err != nil {
			return err
		}
		applied, err := m.UpTo(ctx, v)
		if err != nil {
			return err
		}
		return reportApplied(ctx, m, applied, "applied")

	case "down":
		v, err := m.Down(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("rolled back migration %d\n", v)
		return nil

	case "down-to":
		v, err := parseVersion(args, "down-to")
		if err != nil {
			return err
		}
		rolled, err := m.DownTo(ctx, v)
		if err != nil {
			return err
		}
		return reportApplied(ctx, m, rolled, "rolled back")

	case "status":
		st, err := m.Status(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("%-10s  %-9s  %s\n", "VERSION", "STATE", "SOURCE")
		for _, s := range st {
			state := "pending"
			if s.Applied {
				state = "applied"
			}
			fmt.Printf("%-10d  %-9s  %s\n", s.Version, state, s.Source)
		}
		return nil

	case "version":
		v, err := m.Version(ctx)
		if err != nil {
			return err
		}
		fmt.Println(v)
		return nil

	default:
		return fmt.Errorf("unknown migrate subcommand %q", args[0])
	}
}

func parseVersion(args []string, sub string) (int64, error) {
	if len(args) < 2 {
		return 0, fmt.Errorf("migrate %s needs a version number", sub)
	}
	v, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("migrate %s: %q is not a version number", sub, args[1])
	}
	return v, nil
}

func reportApplied(ctx context.Context, m *store.Migrator, versions []int64, verb string) error {
	if len(versions) == 0 {
		fmt.Println("no migrations to apply; schema is up to date")
	} else {
		for _, v := range versions {
			fmt.Printf("%s migration %d\n", verb, v)
		}
	}
	v, err := m.Version(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("schema version is now %d\n", v)
	return nil
}

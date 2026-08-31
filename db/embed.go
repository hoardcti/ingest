// Package db holds the SQL migrations that define the HoardCTI schema.
//
// The migrations are embedded into the binary so that `ingest migrate up` works
// from a scratch container with no repository checkout and no external
// migration tool on PATH.
package db

import "embed"

// Migrations contains the goose migration set, rooted at "migrations".
//
//go:embed migrations/*.sql
var Migrations embed.FS

// MigrationsDir is the path within [Migrations] that goose should scan.
const MigrationsDir = "migrations"

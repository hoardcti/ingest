# Schema

This repository owns the HoardCTI database schema. The migrations in
`migrations/` are the source of truth; everything else — the Go write path, the
Drizzle schema in the TypeScript repository — derives from them.

## Layout

```
db/
  embed.go                       go:embed of the migration set
  migrations/
    00001_core.sql               entity, relationship, source, sighting
    00002_modules.sql            indicator, cve, breach
    00003_ingest_bookkeeping.sql envelope idempotency, dead letters
```

## Running migrations

Migrations are embedded in the binary and applied by [goose](https://github.com/pressly/goose):

```bash
ingest migrate up
```

Other subcommands: `migrate status`, `migrate down` (one step), `migrate up-to
<version>`, `migrate down-to <version>`, `migrate version`.

Migrations run inside a transaction and take a Postgres advisory lock, so
starting several replicas at once is safe — one applies, the rest wait and then
find nothing to do.

## The module pattern

Every module record has a row in `entity` and a row in its own table, sharing an
id:

```
entity (id, kind='cve', canonical_key='CVE-2024-3094', …)
   └── cve (entity_id = same id, cvss_score, published_at, …)
```

The module table's primary key **is** the `entity_id`. No separate surrogate
key, no join table, no nullable columns for fields that only apply to one kind.

Three properties fall out of this:

**Modules never reference each other directly.** A CVE linked to an indicator is
a row in `relationship`, not a foreign key in `cve`. A module can therefore
point at a kind that did not exist when it was written, and removing a module
does not break the ones that referenced it.

**Generic features work over `entity` alone.** Dedup, sightings, traversal, TTL
and search are written once against the core tables and cover every module,
present and future.

**Adding a module is additive.** One migration, one kind constant. `00001` and
the other modules are untouched.

## Adding a module

1. New migration: `db/migrations/0000N_<name>.sql`, following the shape of
   `00002_modules.sql`.
   - `entity_id uuid PRIMARY KEY REFERENCES entity (id) ON DELETE CASCADE`
   - only columns specific to this kind; anything shared belongs in `entity`
2. Add the kind constant and its canonicaliser in `internal/canonical`, and
   register it in `canonical.Registry`.
3. Add the module payload to `internal/envelope` and to
   `contract/envelope-v1.schema.json`.
4. Add the upsert to `internal/store/modules.go`.
5. Mirror the table into the Drizzle schema in the TypeScript repository.

Steps 2–4 are each a compile error away from being noticed if you skip one; the
`canonical` registry test enumerates kinds and fails on an unregistered one.

## Canonical keys

`UNIQUE (kind, canonical_key)` is the deduplication guarantee for the whole
system, so canonicalisation has to be deterministic and it has to happen in
exactly one place — `internal/canonical`, at write time. Never at query time,
never in a scraper.

| Kind | Canonical key |
|---|---|
| `cve` | `CVE-2024-3094` — uppercase, as issued |
| `breach` | slug, e.g. `linkedin-2021` |
| `indicator` | normalised value — defanging stripped, punycode resolved, hashes lowercased |

## Notes

- **`kind` is `text`, not an enum.** Enums need `ALTER TYPE … ADD VALUE` to
  extend, which defeats the point of a modular schema. Type safety lives at the
  application boundary in `internal/canonical`.
- **`sighting` is partitioned from day one.** Monthly `PARTITION BY RANGE
  (observed_at)`. Converting a large table to a partitioned one rewrites it
  under an `ACCESS EXCLUSIVE` lock, and you discover you need partitioning at
  exactly the moment you cannot afford that. `ingest maintain` provisions
  partitions ahead of time; `sighting_default` catches anything that slips
  through and is expected to stay empty.
- **Retention drops partitions, never rows.** `SELECT
  drop_sighting_partitions_before(now() - interval '18 months')`, or
  `ingest maintain --retain 18m`.
- **`inet` for IPs is deliberately not used.** `indicator.value` is `text` so a
  single column holds every observable type. If IP range queries become a real
  feature, add a nullable `inet` column alongside it rather than splitting the
  table.
- **Reverse traversal is indexed.** `relationship_target_idx` exists because
  "what points at this entity" is asked as often as the forward direction.

## Relationship to the Drizzle schema

The TypeScript repository keeps a Drizzle schema as its read model. It is a
mirror, not a source: `drizzle-kit generate` must not be used to produce
migrations against this database. When you change a table here, update the
Drizzle file in the same pull request and run `drizzle-kit introspect` to
confirm the two agree.

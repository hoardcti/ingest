# ingest

The single process that writes to the HoardCTI database.

## Overview

Collectors — in Go, Python, TypeScript, or a declarative feed manifest — fetch
from upstream sources and emit **envelopes**. This service consumes them,
archives the raw payload, canonicalises every value exactly once, writes one
transaction per envelope, and projects the result into the indicator lookup
cache.

Collectors run as GitHub Actions workflows and call this repository's action to
hand their envelopes over. The action has two modes, and they differ in where
the writing happens and therefore in what credentials a collector holds:

```
collector workflow (GitHub Actions)
  scrape ──► envelope.json ──► hoardcti/ingest action
                                     │
              mode: submit ──────────┤                    mode: direct
              (holds a bearer token) │        (holds the database URL)
                                     ▼                          │
                               Redis Streams                    │
                                     │                          │
                                     ▼                          │
                            ingest service ◄────────────────────┘
                                     │   same canonicaliser, same writer
                                     ├──► object storage (raw archive)
                                     ├──► Redis (indicator lookup cache)
                                     ▼
                                 PostgreSQL
```

Two rules hold the design together.

**One canonical envelope.** Defined once, in
[`contract/envelope-v1.schema.json`](contract/envelope-v1.schema.json). That
file is the actual centre of the system; collectors in three languages generate
their types from it.

**Exactly one implementation writes to Postgres.** If Go, Python and Node each
implemented their own defanging and hash normalisation, they would produce three
subtly different answers, `UNIQUE (kind, canonical_key)` would quietly stop
deduplicating, and nobody would notice for months.

Note *implementation*, not *process*. `mode: direct` runs the writer on the
collector's own runner, so there may be many concurrent writers — but they are
all the same binary, canonicalising identically, against a database whose unique
constraints and idempotency claims are built for it. What must never happen is a
second implementation of the rules.

## Installation

Requires Go 1.25, PostgreSQL 14 or later, and Redis or Valkey.

```bash
git clone https://github.com/hoardcti/ingest.git && cd ingest && make build
```

Or use the container image:

```bash
docker build -t hoardcti/ingest .
```

## Using it from a collector workflow

Add the action as a step, straight after whatever produced the envelope:

```yaml
- name: Ingest
  uses: hoardcti/ingest@v1
  with:
    envelope: out/*.json
    endpoint: https://ingest.example.org
    token: ${{ secrets.HOARDCTI_INGEST_TOKEN }}
```

A **composite action, not a reusable workflow**, and the reason matters: a
`workflow_call` job runs on its own runner with its own empty workspace and
cannot see files a previous job wrote. `envelope` is a path in *your* workspace,
so the action has to run in the same job as the step that created it. If you
genuinely want ingest as a separate job, see the reusable workflow below — it
takes an artifact, because that is the only thing that crosses a job boundary.

### Modes

| Mode | What it does | What the collector holds |
|---|---|---|
| `submit` (default) | POSTs to the running ingest service | A bearer token |
| `direct` | Writes to Postgres from the runner | The database URL |
| `validate` | Checks against the contract and stops | Nothing at all |

`validate` needs no infrastructure, which makes it the right thing to run on
every pull request in a collector repository — a feed mapping is checked before
it ever reaches the database:

```yaml
- uses: hoardcti/ingest@v1
  with:
    envelope: testdata/*.json
    mode: validate
```

`direct` removes the need for a publicly reachable service, at the cost of
giving every collector repository a database credential and requiring Postgres
to accept connections from GitHub's runner ranges, which are broad. `submit`
keeps the credential a revocable token and the database private. Start with
`submit` unless you have a reason not to.

### Inputs

`envelope` is required. `mode` defaults to `submit`. `endpoint` and `token` are
required for `submit`; `database-url` for `direct`. Globs are expanded, one
pattern per line:

```yaml
with:
  envelope: |
    out/indicators/*.json
    out/cves/*.json
```

Newline-separated rather than space-separated, so a file whose name contains a
space still works. The full input list, including the `archive-*` options for
`direct` mode, is in [`action.yml`](action.yml).

### Outputs

`envelopes`, `accepted`, `duplicates`, `records`, `sightings`, `relationships`,
`dropped`, and `result` — the last being the per-envelope detail as JSON:

```yaml
- id: ingest
  uses: hoardcti/ingest@v1
  with: { envelope: out/*.json, mode: direct, database-url: "${{ secrets.DB_URL }}" }

- run: echo "wrote ${{ steps.ingest.outputs.records }} records"
```

The step fails if any envelope is rejected, and writes a table to the job
summary either way. It does **not** fail when every envelope turns out to be a
duplicate — a collector re-running over unchanged upstream data is the normal
case, not an error. `fail-on-duplicate: true` if you would rather know.

### As a separate job

```yaml
jobs:
  scrape:
    runs-on: ubuntu-latest
    steps:
      - run: ./scrape.sh > envelope.json
      - uses: actions/upload-artifact@v7
        with: { name: envelopes, path: envelope.json }

  ingest:
    needs: scrape
    uses: hoardcti/ingest/.github/workflows/ingest.yml@v1
    with:
      artifact: envelopes
      endpoint: https://ingest.example.org
    secrets:
      token: ${{ secrets.HOARDCTI_INGEST_TOKEN }}
```

There is a complete, commented collector workflow in
[`docs/collector-workflow-example.yml`](docs/collector-workflow-example.yml).

## Usage

Start the development stack and load an example envelope:

```bash
make up && make migrate && make seed
```

Run the service:

```bash
make serve
```

Then submit an envelope over HTTP:

```bash
curl -sS -X POST http://localhost:8080/v1/envelopes -H 'Authorization: Bearer dev-token' -H 'Content-Type: application/json' --data @contract/examples/indicator-batch.json
```

### Commands

| Command | What it does |
|---|---|
| `ingest migrate up` | Apply the schema. Also `status`, `version`, `down`, `up-to`, `down-to` |
| `ingest source add <slug>` | Register a feed. `--name`, `--url`, `--tlp`, `--disabled` |
| `ingest source list` | List configured feeds |
| `ingest serve` | Consume the queue. `-http-only`, `-no-http` |
| `ingest maintain` | Provision sighting partitions, apply retention |
| `ingest submit <file>` | Publish an envelope to the queue |
| `ingest load <file>` | Write an envelope directly, bypassing the queue |
| `ingest validate <file>` | Check an envelope against the contract. Needs no database |
| _all three above_ | Take `-json` for machine-readable output; the action parses it |
| `ingest version` | Print the commit this binary was built from |

`validate` needs nothing but the binary, which makes it the right thing to run
in a collector's own CI.

### Configuration

Environment only, all prefixed `HOARDCTI_`. See
[`.env.example`](.env.example) for the full list with defaults. The only
required variable is `HOARDCTI_DATABASE_URL`.

The settings most worth getting right:

| Variable | Why it matters |
|---|---|
| `HOARDCTI_QUEUE_WORKERS` | Each worker holds a transaction for the length of its batch. Must stay below `DATABASE_MAX_CONNS`; startup refuses a configuration that cannot serve them all |
| `HOARDCTI_QUEUE_MIN_IDLE` | How long before a replica may claim another's message. Set it longer than the slowest legitimate batch, or replicas steal work mid-write |
| `HOARDCTI_ARCHIVE_BACKEND` | Left at `none`, upstream payloads are not kept and reprocessing history means re-scraping — often impossible |
| `HOARDCTI_HTTP_TOKENS` | With none set, the submission endpoint refuses every request rather than defaulting to open |
| `HOARDCTI_CACHE_TTL` | Must exceed your slowest feed's collection interval, or indicators fall out of the cache between collections |

### Operating it

`ingest maintain` is the only thing that needs a schedule. Run it daily:

```bash
ingest maintain --ahead 2 --retain 8760h
```

It provisions sighting partitions ahead of time, warns if anything has landed in
`sighting_default`, and drops partitions past the retention window. Retention
drops whole partitions rather than deleting rows — a `DELETE` over the same data
would rewrite hundreds of millions of rows and leave the table needing a vacuum.

`/metrics` exposes Prometheus instrumentation. The three to alert on:

- `hoardcti_ingest_queue_pending` — sustained growth means consumers are dying
  mid-batch.
- `hoardcti_ingest_records_dropped_total` — a rising rate on one source means
  that feed's format has changed.
- `hoardcti_ingest_envelopes_total{outcome="dead_letter"}` — envelopes parked in
  `ingest_dead_letter`, waiting for someone.

### Metrics locally

Prometheus is **opt-in**, behind a compose profile, so the default stack stays
to the two things ingest cannot run without:

```bash
make metrics
```

That is `docker compose --profile metrics up -d --build prometheus`. It comes up
on [localhost:9090](http://localhost:9090) — `/targets` to check the scrape,
`/graph` for the expression browser.

It scrapes `host.docker.internal:8080`, deliberately rather than the `ingest`
service name, so the same config works whether you are running `make serve` on
the host or `docker compose --profile full up`. Change the port there if you
change `HOARDCTI_HTTP_ADDR`; `serve -no-http` exposes nothing to scrape at all.

The config and rules live in `deploy/prometheus/` and are baked into a small
image rather than bind-mounted, because bind mounts fail on any machine whose
project drive is not shared with the container runtime. Rebuild after editing
them, or `curl -XPOST localhost:9090/-/reload` for a rules-only change.

`rules.yml` ships six recording rules — the expressions worth graphing,
precomputed:

| Rule | Answers |
|---|---|
| `hoardcti:records_ingested:rate5m` | Throughput, by source and kind |
| `hoardcti:sightings:rate5m` | Observation rate, by source |
| `hoardcti:records_dropped:ratio15m` | What proportion of a feed is failing to canonicalise |
| `hoardcti:envelopes:ratio_duplicate5m` | How much of the stream is redelivery |
| `hoardcti:write_duration:p50_5m` / `:p99_5m` | Batch write latency, by source |

and eight alerts covering the metrics above plus dead letters, cache
write-through failures, and slow writes. Thresholds are tuned to be visible on a
development stack — raise the `for:` durations before pointing an Alertmanager
at them.

## How it works

### Canonicalisation

[`internal/canonical`](internal/canonical) is the one place normalisation
happens: never at query time, never in a collector, never twice. It strips
defanging (`hxxp://evil[.]com` → `http://evil.com`), resolves punycode,
lowercases hashes, unmaps IPv4-in-IPv6, masks CIDR host bits, drops default
ports and URL fragments, and uppercases CVE ids.

Two properties are tested explicitly, because both failure modes are silent:
different spellings of one indicator must **converge**, and genuinely different
indicators must **not merge**. `http://evil.com/a` and `http://evil.com/a/` stay
distinct; `hxxps://EVIL.com:443/` and `https://evil.com/` do not.

### The write path

Row-by-row upserts of fifty thousand indicators would spend the whole time in
round trips. Instead, entities go in over the COPY protocol into a staging
table and are merged with a single `INSERT … SELECT … ON CONFLICT DO UPDATE`;
everything downstream of that merge is one statement per table, not one per row.

Two details that are not obvious from the SQL:

- The merge has an `ORDER BY`. Concurrent batches touching overlapping entities
  must take row locks in the same sequence or they deadlock.
- It has a `GROUP BY` too. `ON CONFLICT DO UPDATE` refuses to touch the same row
  twice in one statement, and a feed listing the same indicator under two tags
  is entirely normal.

### Idempotency

Delivery is at-least-once, so a consumer that dies after `COMMIT` but before
acknowledging will be handed the same envelope again. The service claims a row
in `ingest_envelope` **inside the ingest transaction**, keyed on the SHA-256 of
the delivered message bytes.

That key is deliberately not the payload's `content_hash`. A redelivery is
byte-identical and is correctly suppressed; a blocklist re-collected the next
day and found unchanged has the same `content_hash` but a later `collected_at`,
so a different digest — and it must produce new sightings, because "still listed
today" is exactly the fact the sighting table exists to record.

### Failure handling

Failures are sorted into two kinds, and the distinction is the whole of the
queue's error handling:

- **Permanent** — malformed envelope, unknown source, a feed whose format has
  changed. Retrying cannot fix it, so it is parked in `ingest_dead_letter` and
  acknowledged. A poison message must not stall the consumer group forever.
- **Transient** — database down, Redis unreachable. It will come back, so the
  message is left unacknowledged and redelivered.

Getting this backwards gives you either a permanently stuck consumer group or
silent data loss during an outage.

Within an envelope, individual records may fail canonicalisation without taking
the batch down: four malformed lines in fifty thousand loads the other 49,996
and tells you about the four. But if more than `MAX_DROP_RATIO` of them fail,
the feed has changed format and the whole envelope is rejected — ingesting the
remains would lose data quietly.

## Development

```bash
make up                 # Postgres and Valkey
make metrics            # + Prometheus, opt-in
make check              # what CI runs, minus the database tests
make test-integration   # everything, including the database tests
make race               # under the race detector
make down               # stop everything, profiles included
```

The store tests are skipped without `HOARDCTI_TEST_DATABASE_URL`. They exercise
real SQL — partitioning, the ON CONFLICT merges, COPY into a staging table —
because a mock would only assert that the mock matches itself. CI runs them
against a real PostgreSQL service container.

### Adding a module

See [`db/README.md`](db/README.md). The short version: one migration, one
canonicaliser, one payload type, one upsert. `entity`, `relationship` and
`sighting` are untouched, and so is every other module.

### Changing the envelope

`contract/envelope-v1.schema.json` is the published contract. Three tests keep
the Go implementation honest about it: the examples must satisfy the schema, the
hand-written Go validator must accept everything the schema accepts, and what
the Go structs marshal must still satisfy the schema. Break any one of those and
CI says so.

Additive changes bump the minor version — the decoder ignores unknown fields, so
a collector on 1.1 keeps working against a 1.0 service. Anything else needs a
major version and a migration plan.

## Layout

```
cmd/ingest/          CLI: serve, migrate, source, maintain, submit, load, validate
action.yml           The composite action collectors call from their workflows
contract/            The cross-language envelope contract and worked examples
docs/                A complete collector workflow to copy
db/                  Embedded goose migrations; the schema source of truth
deploy/prometheus/   Opt-in metrics: scrape config, recording rules, alerts
internal/
  archive/           Raw payload store, content-hash keyed (S3/R2, filesystem, none)
  cache/             Indicator lookup projection into Redis/Valkey
  canonical/         Normalisation — the one place it happens
  config/            Environment configuration
  envelope/          Wire types and validation
  httpapi/           Submission endpoint, health probes, metrics
  ingest/            The service: decode → archive → canonicalise → write → cache
  queue/             Redis Streams consumer group and publisher
  store/             Every write to Postgres
  telemetry/         Prometheus instrumentation
```

## Licence

GPL-3.0. See [LICENSE](LICENSE).

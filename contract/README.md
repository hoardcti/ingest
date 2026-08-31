# The envelope contract

`envelope-v1.schema.json` is the one contract between collectors and the ingest
service. It is the centre of the system: collectors in Go, Python and TypeScript
all generate their types from this file, and it is the only thing they need to
know about the database.

## The shape

```
schema_version                    1.x
source                            slug, matching source.slug in the database
source_run_id                     groups envelopes from one collector run
collected_at                      when the collector fetched the payload
content_hash                      sha256 of the upstream payload — provenance
raw_ref | raw                     archived payload, or the payload itself
default_context                   applied to every record that does not override
records[]                         { kind, observed_at, context, <payload> }
relationships[]                   { source, target, type, confidence, metadata }
```

## The two things collectors get wrong

**`raw_value`, not `value`.** Collectors report what they saw; they do not
interpret it. A collector emitting `hxxp://evil[.]com` is behaving *correctly* —
defanging, punycode, hash casing and URL normalisation are all handled once, in
the ingest service. A collector that normalises on its own is not being helpful:
it is creating a second implementation that will drift from the first, and the
deduplication guarantee depends on there being exactly one.

**One envelope, many records.** The ingest service writes a whole envelope in a
single transaction using the COPY protocol, so fifty thousand records cost
barely more than one. Emitting one envelope per indicator works, but it is
thousands of times more expensive and gives up the batching entirely.

## Validating

Nothing but the binary is needed, which makes this the right thing to put in a
collector's own CI:

```bash
ingest validate my-envelope.json
```

It reports every problem at once, located by JSON path, rather than one per run.

## Examples

| File | Shows |
|---|---|
| `examples/indicator-batch.json` | Defanged observables, type inference, per-record context, relationships between records |
| `examples/cve-enrichment.json` | CVE records, and an edge pointing at an entity that appears nowhere else in the envelope |
| `examples/breach-with-inline-raw.json` | A breach record, an inline payload for the service to archive, and a derived slug |

These are checked against the schema in CI, so they are safe to copy from.

## Generating types

The schema is standard JSON Schema 2020-12, so the usual generators work:

```bash
# TypeScript
npx json-schema-to-typescript contract/envelope-v1.schema.json -o envelope.ts

# Python
datamodel-codegen --input contract/envelope-v1.schema.json --output envelope.py
```

Go types are maintained by hand in `internal/envelope` rather than generated,
because the hot-path validator needs to be hand-written anyway. Three tests keep
them in agreement with this file — see the "Changing the envelope" section of
the top-level README.

## Versioning

`schema_version` is `MAJOR.MINOR`.

**Minor** bumps are additive: new optional fields, new enum members. The Go
decoder ignores unknown fields on purpose, so a collector running 1.1 keeps
working against an ingest service still on 1.0. Note the asymmetry — the schema
sets `additionalProperties: false` so a typo in a hand-written envelope is caught
at authoring time, while the runtime decoder is lenient so a version skew does
not take production down.

**Major** bumps are anything else: a removed field, a changed meaning, a
narrowed type. The ingest service rejects an envelope whose major version it does
not implement rather than guessing at it. Migrating means running both versions
side by side until every collector has moved.

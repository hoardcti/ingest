-- Bookkeeping owned by the ingest service itself. Nothing here is part of the
-- CTI data model -- it exists so that at-least-once delivery from the queue
-- produces exactly-once effects, and so that failures are visible rather than
-- silent.

-- +goose Up

-- Envelope-level idempotency. Redis Streams -- and every other at-least-once
-- transport -- will redeliver: a consumer that dies after COMMIT but before
-- XACK is handed the same envelope again. Claiming a row here inside the ingest
-- transaction makes the replay a no-op instead of a second set of sightings.
--
-- The key is envelope_digest, the SHA-256 of the delivered message bytes, and
-- NOT content_hash. The distinction matters:
--
--   * A redelivery is byte-identical, so it has the same digest and is
--     correctly suppressed.
--   * A blocklist re-collected the next day and found unchanged has the same
--     content_hash but a later collected_at, so a different digest -- and it
--     must produce new sightings, because "still present today" is exactly the
--     fact the sighting table exists to record.
--
-- Keying on content_hash would collapse the second case into the first and
-- quietly stop recording that a source still stands behind its data.
--
-- Scoped per source, because two feeds shipping identical bytes are two
-- legitimate observations and collapsing them would lose an attribution.
CREATE TABLE ingest_envelope (
    source_id       uuid        NOT NULL REFERENCES source (id) ON DELETE CASCADE,
    envelope_digest text        NOT NULL,
    content_hash    text,
    source_run_id   text,
    schema_version  text        NOT NULL,
    record_count    integer     NOT NULL DEFAULT 0,
    raw_ref         text,
    received_at     timestamptz NOT NULL DEFAULT now(),
    processed_at    timestamptz,
    PRIMARY KEY (source_id, envelope_digest)
);

CREATE INDEX ingest_envelope_received_idx ON ingest_envelope (received_at);
CREATE INDEX ingest_envelope_content_idx ON ingest_envelope (content_hash)
    WHERE content_hash IS NOT NULL;
CREATE INDEX ingest_envelope_run_idx ON ingest_envelope (source_run_id)
    WHERE source_run_id IS NOT NULL;

-- Envelopes that could not be processed. A poison message must not be able to
-- stall a consumer group forever, so it is parked here with the reason and the
-- original payload, acknowledged on the stream, and dealt with out of band.
CREATE TABLE ingest_dead_letter (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    source_slug text,
    message_id  text,
    stage       text        NOT NULL,
    reason      text        NOT NULL,
    payload     jsonb,
    failed_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ingest_dead_letter_failed_idx ON ingest_dead_letter (failed_at);
CREATE INDEX ingest_dead_letter_source_idx ON ingest_dead_letter (source_slug);

-- +goose Down
DROP TABLE IF EXISTS ingest_dead_letter;
DROP TABLE IF EXISTS ingest_envelope;

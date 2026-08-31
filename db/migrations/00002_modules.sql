-- Module tables. Each extends `entity` 1:1 through a primary key that *is* the
-- entity id -- no surrogate key, no join table, and no nullable columns for
-- fields that only apply to one kind.
--
-- Adding a module is additive: one new migration, one new kind constant in
-- internal/canonical. Nothing in 00001_core.sql changes, and no existing module
-- changes either.

-- +goose Up

-- Observables: IPs, domains, URLs, email addresses, file hashes.
--
-- `value` is canonical (defanging stripped, punycode resolved, hashes
-- lowercased) and equals the owning entity's canonical_key. `raw_value` keeps
-- what the feed actually sent, for provenance -- a scraper emitting
-- hxxp://evil[.]com is behaving correctly and we want the evidence.
CREATE TABLE indicator (
    entity_id uuid PRIMARY KEY REFERENCES entity (id) ON DELETE CASCADE,
    type      text NOT NULL,
    value     text NOT NULL,
    raw_value text
);

CREATE INDEX indicator_value_idx ON indicator (value);
CREATE INDEX indicator_type_idx ON indicator (type);

-- Fuzzy matching on observable values: "domains that look like ours".
CREATE INDEX indicator_value_trgm_idx ON indicator USING gin (value gin_trgm_ops);

CREATE TABLE cve (
    entity_id       uuid    PRIMARY KEY REFERENCES entity (id) ON DELETE CASCADE,
    cve_id          text    NOT NULL UNIQUE,
    summary         text,
    cvss_score      real,
    cvss_vector     text,
    severity        text,
    epss_score      real,
    known_exploited boolean NOT NULL DEFAULT false,
    cwe             text[],
    published_at    timestamptz,
    modified_at     timestamptz,
    refs            jsonb
);

CREATE INDEX cve_cvss_idx ON cve (cvss_score);
CREATE INDEX cve_published_idx ON cve (published_at);
CREATE INDEX cve_known_exploited_idx ON cve (known_exploited);

CREATE TABLE breach (
    entity_id    uuid    PRIMARY KEY REFERENCES entity (id) ON DELETE CASCADE,
    slug         text    NOT NULL UNIQUE,
    name         text    NOT NULL,
    domain       text,
    description  text,
    breach_date  date,
    disclosed_at timestamptz,
    record_count bigint,
    data_classes text[],
    verified     boolean NOT NULL DEFAULT false
);

CREATE INDEX breach_breach_date_idx ON breach (breach_date);
CREATE INDEX breach_domain_idx ON breach (domain);

-- +goose Down
DROP TABLE IF EXISTS breach;
DROP TABLE IF EXISTS cve;
DROP TABLE IF EXISTS indicator;

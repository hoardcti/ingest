#!/usr/bin/env bash
#
# Runtime for the HoardCTI Ingest composite action.
#
# Lives in a file rather than inline in action.yml for two reasons: shell inside
# YAML inside a `run:` block is three levels of escaping and gets edited wrong,
# and a script can be linted and executed on its own.
#
# Every value it needs arrives through the environment. Nothing is interpolated
# from `${{ }}` into the shell, so a file path or source slug containing a
# backtick is data rather than a command.

set -euo pipefail

: "${MODE:?}"
: "${ENVELOPE:?}"
: "${BIN_DIR:=}"
: "${ENDPOINT:=}"
: "${TOKEN:=}"
: "${TIMEOUT:=120}"
: "${FAIL_ON_DUPLICATE:=false}"
: "${FAIL_ON_DROPPED:=false}"

case "$MODE" in
    submit | direct | validate) ;;
    *)
        echo "::error::mode must be submit, direct or validate; got '$MODE'"
        exit 1
        ;;
esac

if ! command -v jq >/dev/null 2>&1; then
    echo "::error::jq is required by this action and is not on PATH."
    echo "::error::It is preinstalled on GitHub-hosted runners; on a self-hosted"
    echo "::error::runner, install it (apt-get install jq / brew install jq)."
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# --- resolve the envelope files -------------------------------------------
#
# One pattern per line. Newline-separated rather than space-separated on
# purpose: splitting on spaces would make it impossible to name a file that has
# one, and collectors do not get to choose what upstream calls its files. Use a
# YAML block scalar for several patterns:
#
#   envelope: |
#     out/indicators/*.json
#     out/cves/*.json
#
# Unquoted expansion inside the loop is deliberate and is the whole point;
# nullglob makes a pattern that matches nothing vanish so it can be reported
# rather than passed through as a literal filename.
shopt -s nullglob
files=()
missing=()
while IFS= read -r pattern; do
    # Trim surrounding whitespace so an indented YAML block scalar works.
    pattern="${pattern#"${pattern%%[![:space:]]*}"}"
    pattern="${pattern%"${pattern##*[![:space:]]}"}"
    [ -n "$pattern" ] || continue

    # IFS is emptied for the expansion so the pattern is globbed but NOT word
    # split: with the default IFS, a path containing a space would be torn into
    # two patterns that each match nothing. Globbing and word splitting are
    # separate steps, so this keeps the one we want and drops the one we do not.
    #
    # Command substitution does not happen here — backticks inside an expanded
    # variable are data, not syntax — so a hostile filename is inert.
    saved_ifs=$IFS
    IFS=''
    # shellcheck disable=SC2206 # unquoted on purpose: this is the glob. Word
    # splitting is what SC2206 warns about and is precisely what IFS='' above
    # has already disabled.
    matches=($pattern)
    IFS=$saved_ifs

    matched=0
    for f in "${matches[@]}"; do
        if [ -f "$f" ]; then
            files+=("$f")
            matched=1
        fi
    done
    [ "$matched" -eq 1 ] || missing+=("$pattern")
done < <(printf '%s\n' "$ENVELOPE")
shopt -u nullglob

for m in "${missing[@]:-}"; do
    [ -n "$m" ] && echo "::warning::no files matched '$m'"
done

if [ "${#files[@]}" -eq 0 ]; then
    echo "::error::the 'envelope' input matched no files: $ENVELOPE"
    echo "::error::Paths are relative to the workspace, and this action must run"
    echo "::error::in the same job as the step that produced the envelope —"
    echo "::error::separate jobs do not share a filesystem."
    exit 1
fi

echo "Ingesting ${#files[@]} envelope file(s) in mode '$MODE'"

# results.json accumulates one object per file, in a shape that is the same
# whichever mode produced it, so the aggregation below has one code path.
echo '[]' > "$work/results.json"
rc=0

normalise() {
    # $1 = jq program mapping the mode's raw report array to the common shape
    jq "$1" > "$work/results.json"
}

case "$MODE" in
    validate)
        raw="$work/raw.json"
        "$BIN_DIR/ingest" validate -json "${files[@]}" > "$raw" || rc=$?
        normalise 'map({
            path, ok, mode: "validate",
            source: (.source // ""),
            duplicate: false,
            records: .records,
            records_written: 0,
            records_dropped: 0,
            sightings: 0,
            relationships: .relationships,
            message_id: "",
            error: ((.problems // []) | join("; "))
        })' < "$raw"
        ;;

    direct)
        raw="$work/raw.json"
        "$BIN_DIR/ingest" load -json "${files[@]}" > "$raw" || rc=$?
        normalise 'map({
            path, ok, mode: "direct",
            source: (.source // ""),
            duplicate: .duplicate,
            records: .records_written,
            records_written: .records_written,
            records_dropped: .records_dropped,
            sightings: .sightings,
            relationships: .relationships,
            message_id: (.digest // ""),
            error: (.error // "")
        })' < "$raw"
        ;;

    submit)
        base="${ENDPOINT%/}"
        : > "$work/lines.json"

        for f in "${files[@]}"; do
            body="$work/resp.json"
            : > "$body"

            # Retrying a POST is safe here specifically because ingest
            # deduplicates on the digest of the delivered message: a retry after
            # a response was lost in flight is recognised and written once.
            code="$(curl -sS -o "$body" -w '%{http_code}' \
                --max-time "$TIMEOUT" \
                --retry 3 --retry-delay 2 \
                -X POST "$base/v1/envelopes" \
                -H "Authorization: Bearer $TOKEN" \
                -H 'Content-Type: application/json' \
                --data-binary "@$f" 2>"$work/curl.err")" || code="000"

            if [ "$code" = "000" ]; then
                # Connection-level failure. The response body is empty, so the
                # reason is only in curl's stderr.
                err="$(tr -d '\r' < "$work/curl.err" | tr '\n' ' ')"
                jq -nc --arg p "$f" --arg e "could not reach $base: $err" \
                    '{path:$p, ok:false, mode:"submit", source:"", duplicate:false,
                      records:0, records_written:0, records_dropped:0, sightings:0,
                      relationships:0, message_id:"", error:$e}' >> "$work/lines.json"
                rc=1
                continue
            fi

            # A non-JSON body means something in front of the service answered —
            # a proxy, a login page, a 502 from a load balancer.
            if ! jq -e . "$body" >/dev/null 2>&1; then
                snippet="$(head -c 200 "$body" | tr -d '\r' | tr '\n' ' ')"
                jq -nc --arg p "$f" --arg e "HTTP $code with a non-JSON body: $snippet" \
                    '{path:$p, ok:false, mode:"submit", source:"", duplicate:false,
                      records:0, records_written:0, records_dropped:0, sightings:0,
                      relationships:0, message_id:"", error:$e}' >> "$work/lines.json"
                rc=1
                continue
            fi

            ok=false
            [ "$code" = "202" ] && ok=true
            [ "$ok" = "true" ] || rc=1

            jq -c --arg p "$f" --arg code "$code" --argjson ok "$ok" '{
                path: $p,
                ok: $ok,
                mode: "submit",
                source: (.source // ""),
                duplicate: false,
                records: (.records // 0),
                records_written: 0,
                records_dropped: 0,
                sightings: 0,
                relationships: 0,
                message_id: (.message_id // ""),
                error: (if $ok then ""
                        else "HTTP " + $code + ": " + ((.error // "rejected")
                             + (if (.problems // []) | length > 0
                                then " — " + ((.problems | join("; ")))
                                else "" end))
                        end)
            }' "$body" >> "$work/lines.json"
        done

        jq -s '.' "$work/lines.json" > "$work/results.json"
        ;;

    *)
        echo "::error::unknown mode '$MODE'"
        exit 1
        ;;
esac

# --- aggregate ------------------------------------------------------------
results="$(cat "$work/results.json")"

read -r envelopes accepted duplicates records sightings relationships dropped failures <<EOF
$(jq -r '[
    length,
    ([.[] | select(.ok)] | length),
    ([.[] | select(.duplicate)] | length),
    ([.[].records_written] | add // 0),
    ([.[].sightings] | add // 0),
    ([.[].relationships] | add // 0),
    ([.[].records_dropped] | add // 0),
    ([.[] | select(.ok | not)] | length)
] | @tsv' <<<"$results")
EOF

{
    echo "envelopes=$envelopes"
    echo "accepted=$accepted"
    echo "duplicates=$duplicates"
    echo "records=$records"
    echo "sightings=$sightings"
    echo "relationships=$relationships"
    echo "dropped=$dropped"
    echo "result<<HOARDCTI_RESULT_EOF"
    echo "$results"
    echo "HOARDCTI_RESULT_EOF"
} >> "${GITHUB_OUTPUT:-/dev/null}"

# --- job summary ----------------------------------------------------------
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### HoardCTI ingest (\`$MODE\`)"
        echo
        echo "| Envelope | Source | Result | Records | Sightings | Dropped |"
        echo "|---|---|---|---:|---:|---:|"
        jq -r '.[] |
            "| `\(.path)` | \(if .source == "" then "—" else .source end) | " +
            (if (.ok | not) then "❌ " + (.error | gsub("\\|"; "\\\\|") | .[0:160])
             elif .duplicate then "⏭️ already ingested"
             elif .mode == "submit" then "✅ queued"
             elif .mode == "validate" then "✅ valid"
             else "✅ written" end) +
            " | \(.records) | \(.sightings) | \(.records_dropped) |"' <<<"$results"
        echo
        if [ "$MODE" = "submit" ]; then
            echo "> Queued, not yet written. The ingest service canonicalises and writes"
            echo "> these asynchronously; check its logs or \`ingest_dead_letter\` for the outcome."
        fi
    } >> "$GITHUB_STEP_SUMMARY"
fi

# --- exit ------------------------------------------------------------------
if [ "$failures" -gt 0 ]; then
    echo "::error::$failures of $envelopes envelope(s) failed"
    jq -r '.[] | select(.ok | not) | "::error file=\(.path)::\(.error)"' <<<"$results"
    exit 1
fi

if [ "$FAIL_ON_DROPPED" = "true" ] && [ "$dropped" -gt 0 ]; then
    echo "::error::$dropped record(s) were dropped during canonicalisation and fail-on-dropped is set"
    exit 1
fi

if [ "$FAIL_ON_DUPLICATE" = "true" ] && [ "$duplicates" -eq "$envelopes" ] && [ "$envelopes" -gt 0 ]; then
    echo "::error::every envelope was already ingested and fail-on-duplicate is set"
    exit 1
fi

if [ "$dropped" -gt 0 ]; then
    echo "::warning::$dropped record(s) were dropped during canonicalisation; the feed format may have changed"
fi

echo "Done: $accepted/$envelopes accepted, $duplicates duplicate, $records records, $dropped dropped"
exit "$rc"

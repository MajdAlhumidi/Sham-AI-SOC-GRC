# Synthetic comparison experiment

The Comparison panel measures triage over 16 fixed, author-labelled synthetic
evidence packets. It never queries Wazuh, calls investigation tools or writes
production incident/GRC records. It uses a separate SQLite database selected by
`SOC_BENCHMARK_DB_PATH` (default `data/comparison.sqlite3`). Do not point this
variable at a production database.

1. Start a paired review and inspect the displayed evidence. The server starts
   the manual elapsed timer. The analyst enters their own classification,
   rationale and evidence reference IDs. No response is prefilled.
2. Submit the manual review. Optional active seconds are an unverified analyst
   self-report, bounded by server elapsed time; pauses remain in elapsed time.
3. A background worker submits exactly the same stored evidence packet to the
   actual configured Ollama model using the existing structured chat helper.
   The expected label and rubric are never sent to the model. No fallback score
   replaces an unavailable model or invalid output.
4. Once both sides have finished, inspect decisions, the synthetic answer key,
   reference errors, durations and aggregate counts. A model-only run records
   no manual baseline and cannot produce paired time comparisons.

The fixture snapshot, version and SHA-256 are persisted with each trial. Manual
decisions cannot be overwritten. Each AI trial is claimed once. Only one model
run per database is admitted at a time; callers should serialize queued jobs or
retry pending jobs when the active run finishes. A run left running after a
process restart is marked interrupted when polling or a later run notices it is
older than 15 minutes. A late worker cannot overwrite that recovered status.
This is a failure, never a successful generated result.

Report raw completed/correct/incorrect counts, failures, incomplete trials,
fallback count and reference-error counts together with any label agreement
rate. The answer key is a fixture author's rubric, not verified production
truth. Agreement is a **synthetic triage result**, not operational accuracy.
Reference validation checks available IDs; it cannot prove every factual claim
is supported by the cited text.

Manual elapsed minus model elapsed is reported only for completed paired runs
of the same evidence. It does not measure analyst active-time savings, full
investigation time, tool-selection performance or real SOC effectiveness. An
actual effectiveness study needs a separately adjudicated, held-out case set,
independent blinded analysts and predeclared inclusion/scoring rules. Repeated
reviews after seeing model decisions or the answer key are practice, not fresh
blind evidence. The panel reports repeats and unique scenario counts.

Unit tests use temporary storage and mocked model responses to verify isolation,
blinding, state transitions, failure accounting and citation checks. Test
outputs must never be copied into the live comparison database as real model or
human results.

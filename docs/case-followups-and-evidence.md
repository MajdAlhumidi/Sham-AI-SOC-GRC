# Case follow-ups and portable evidence

Open **Investigations → Cases**, select a case, and use **Continue this investigation**.
A submitted question is persisted before a background worker starts. Refreshing or leaving
the page does not delete the question or its result. Repeated delivery of the same request ID
does not create another turn. Queued/running/limited/failed/unavailable states remain visible.
An interrupted or expired job is reported explicitly; no answer is substituted.

The model receives bounded, integrity-checked evidence snapshots and the analyst's question.
Past answers are conversation context, never proof. New tool calls use the existing read-only
allowlist and observed target restrictions. The original report and evidence stay unchanged.
Wazuh manager/collector agent `000` does not authorize endpoint or collector-wide queries
for a remote router. Such cases use saved context and permitted observed-indicator lookups,
and show that limitation. Fresh endpoint queries cover the recent query window, not the
original incident window. A valid citation does not independently establish factual correctness.

**Download evidence pack** exports a ZIP containing `report.html` (printable), structured
case and evidence records, captured follow-up results, relevant audit records and a SHA-256
manifest. Open `report.html` locally and use Print / Save as PDF if required. No external
resource is needed to read the report. Credentials are redacted before export. Review the
remaining operational identifiers and personal data before sharing. Source integrity,
bounded excerpts and exported-file hashes are reported separately; these are not a digital
signature, independent forensic certification or a compliance attestation. Exports that
exceed the declared bounds fail explicitly instead of silently omitting records.

## Access and runtime

These features share the existing Agent dashboard deployment boundary; no pasted workspace
token is required. They do not introduce independent user authentication or roles. Recorded
operator names are not verified identities. Follow-ups never execute response/containment.

Optional limits: `SOC_FOLLOWUP_RUNTIME_SECONDS` (240),
`SOC_FOLLOWUP_MODEL_TIMEOUT_SECONDS` (120), `SOC_FOLLOWUP_TOOL_TIMEOUT_SECONDS` (25),
`SOC_FOLLOWUP_MAX_TOOL_STEPS` (3), `SOC_FOLLOWUP_MAX_PENDING` (4),
`SOC_FOLLOWUP_QUEUE_TTL_SECONDS` (180). Values are bounded by the implementation.
The runtime uses the existing `SOC_OLLAMA_URL` and `SOC_OLLAMA_MODEL`.

For the separate, labelled synthetic comparison exercise, see
[comparison-experiment.md](comparison-experiment.md). AI-only runs do not create a human
baseline. A genuine paired comparison requires an analyst to complete the manual review.

# Investigation workspace

Open **Investigations** inside the Agent dashboard. Unlock it with the existing
`SOC_GRC_API_TOKEN`. The credential stays in browser memory, is sent only in the
`X-GRC-Token` header, and is cleared by Lock or reload. GRC and Investigations
currently have separate unlock forms using the same credential. Use the existing
private network/SSH tunnel or HTTPS deployment for access.

## Cases and correlation

New investigations preserve the original Wazuh alert, report and collected tool
results in a separate SQLite store. Multiple original incident IDs can belong to
one case. No Chroma incident or GRC record is deleted or relabelled.

Version 1 conservatively joins events only when all these conditions hold:

- Same observed asset identity, exact Wazuh rule ID, source IP and account state.
- Valid source timestamps with explicit timezone offsets.
- The entire case spans at most 30 minutes; a chain cannot extend that window.
- Exactly one eligible case. Ambiguous matches remain separate.

Endpoint agent IDs identify endpoints. Remote syslog uses its destination device
address; it does not identify the Wazuh collector as the router. Missing source
IPs or unresolved assets do not auto-correlate. If an account is absent in both
events, the other conditions still apply and the limitation appears in the join
reason. Cross-rule attack chaining and manual case merging/splitting are not
implemented. Related events do not prove a common attacker or compromise.

The timeline links to each original SOC report and related GRC evidence. The
relationship diagram shows observed source, asset and account associations.

## Evidence

For new records, `A1` opens the original Wazuh JSON. `T1`, `T2`, etc. open actual
tool results with arguments, status, timing, truncation metadata and the bounded
view supplied to the reporting model when available. Tool result capture remains
limited to 12,000 characters; omissions are explicit. Validated structured model
findings retain their evidence references. When a validated assessment is absent,
the workspace shows a narrow runtime observation and an explicit limitation.

SHA-256 verifies stored bytes, not the truth of a source or conclusion. An
available citation is **available for analyst review**, never automatically
verified truth. Failed/missing results are labelled. Reports and logs are rendered
as text rather than executable HTML.

Legacy Chroma records are imported as standalone archived reports with `M1`
metadata. Their report creation times are not relabelled as source-event times;
old naive timestamps are known UTC from `IncidentRecord.utcnow()`. Missing raw
alerts and tool results are not reconstructed from prose. Old `A1`/`Tn` references
therefore remain unavailable. Import reads only currently retained Chroma IDs,
not GRC's historical references to deleted incidents.

On the **first import**, optional `--alerts-file /var/ossec/logs/alerts/alerts.json`
recovers only raw events whose exact Wazuh alert ID matches retained Chroma
metadata. Those events can correlate and expose real `A1` evidence; missing tool
results remain explicitly missing. This does not replace already-imported records
or treat report text as an original event.

## Business priority and approved changes

In **Assets & changes**, assess each observed asset's owner, business service,
criticality and data sensitivity. Defaults are unassessed, not invented values.
Legacy identities remain separate from source-verified identities.

Priority v1 uses the highest Wazuh level in a case:

| Rule level | Baseline |
| --- | --- |
| 12+ | 85 |
| 8–11 | 65 |
| 5–7 | 45 |
| 1–4 | 20 |
| Missing / unusable | 40, review required |

Criticality adds 20 (critical), 10 (high), 5 (medium), or 0. Sensitivity adds
10 (restricted), 5 (confidential), or 0. The score caps at 100. Bands are Critical
85+, High 65+, Medium 40+, Low below 40. This is an explainable triage policy,
not an attack probability, CVSS score, or automatic containment decision.
Current operator-entered context is used on refresh. Profile edits record their
previous and new values with a revision check to prevent lost updates.

Approved change context requires an existing approval/ticket reference, named
approver, exact asset/rule/IP/account, approval timestamp and a window of at most
seven days. Dates are entered in the browser's local timezone and stored with UTC
offsets. Approval must precede the window. A match never lowers the score,
suppresses an alert or establishes benign intent. Revoke a record by editing its
status. The shared access token identifies the credential used, not an individual
operator; approver names are recorded assertions, not verified identities.

## Storage and deployment

Both `soc-agent` and `soc-stream` must use the same writable
`SOC_CASE_DB_PATH` (default `data/investigations.sqlite3` relative to their working
directory). Linux database permissions are owner-only. No new external database,
model, or Python dependency is required. Back up this database using SQLite's
backup API, along with the existing GRC and Chroma stores. Workspace audit entries
are append-only through SQLite triggers; this is not an externally signed ledger.

For an existing deployment, run this once from the runtime working directory,
using the service's environment and Python interpreter:

```bash
PYTHONPATH=/path/to/checkout/scripts python -m casework.backfill \
  --chroma-path /home/ubuntu/soc-ai-agent/incident_vector_db
```

The import is idempotent. Keep production data out of the Git repository. New
source events are captured by the agent before Chroma storage; capture failures
are reported as `CASEWORK-ERROR` while the original incident pipeline continues.
Monitor this error: the tool audit JSONL still contains excerpts, but is not a
replacement for the full workspace evidence record. There is no automatic raw
evidence backfill or retention/deletion job in this version.

For a controlled deployment, `SOC_ALERT_RESUME_FILE` can point to an operator-made
JSON cursor containing the alert file's absolute `path`, `inode`, `device`, byte
`offset` at a complete JSONL boundary, and `already_processed_ids`. Startup checks
the file identity and resumes at that boundary; a mismatch fails closed. Remove
the temporary systemd override after the agent is listening. Without this setting,
the existing EOF-only startup behavior remains unchanged. This is a deployment
cutover aid, not a persistent ingestion checkpoint or rotation manager.

Authenticated API base: `/api/investigations`. Routes: `cases`, `cases/{id}`,
`incidents/{id}`, `evidence/{incident}/{ref}`, `context`, `assets/{id}` (PUT),
`changes/{id}` (PUT), and paginated `audit`. Read-only case review never performs
containment. The approval/context form never creates a response approval.

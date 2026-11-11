# SHAM AI GRC Foundation

This package adds Governance, Risk and Compliance APIs to the verified
Wazuh / MikroTik / Ollama SOC workflow. `integration.py` connects persisted SOC
incidents and human review decisions to local GRC evidence without changing
incident classification, overwriting analyst decisions, or executing response.

## Scope

- Risk register with a transparent 5x5 likelihood-impact score.
- Internal control catalogue, seeded once into SQLite.
- Risk-to-control mappings.
- Evidence references from Wazuh and SHAM AI assessments.
- Human approval records for consequential actions.
- Append-only audit events at the application/database-trigger level.
- A compliance implementation indicator that is explicitly not a certification.

The initial control catalogue is an internal starting baseline. It is not a
validated NIST, ISO 27001, or regulatory control mapping. A responsible
security/GRC owner must review and map controls to the selected framework
before using the dashboard for formal compliance reporting.

## Storage

SQLite is used to avoid adding a new runtime dependency. The default database
path is data/grc.sqlite3 relative to the repository root.

Set GRC_DB_PATH to move the database, for example:

    export GRC_DB_PATH=/var/lib/sham-ai/grc.sqlite3

The data directory and SQLite files must be backed up and excluded from Git.

## Dashboard access

The existing Agent dashboard includes a **GRC workspace** tab at
`/#grc/evidence`. Unlock it using the API service's `SOC_GRC_API_TOKEN` over
the deployment's protected connection. The browser sends `X-GRC-Token` only
to the same-origin GRC workspace API. Locking or reloading clears the token
and protected records from page memory; no token is saved in browser storage.

The five sections display risks, controls, evidence, approvals and audit
events. Search and filters query the entire SQLite dataset, with 40 records
per page. Record details include evidence metadata, risk/control references,
decision notes, audit before/after snapshots, and paginated SOC incident
links. Retained evidence stays available when the original SOC incident is
no longer in ChromaDB; opening that link reports the missing source.

This tab is view-only. Existing write APIs remain the way to create risks,
assess controls or record human approval decisions. Empty registers are
shown honestly; incident evidence does not create risks or approvals.
The shared token does not establish individual user identities or roles.

Read endpoints used by the tab (all require the existing GRC token and
return `Cache-Control: no-store`):

- `GET /api/grc/workspace/summary`
- `GET /api/grc/workspace/{section}?q=...&status=...&offset=0&limit=40`
- `GET /api/grc/workspace/{section}/{id}?incident_offset=0&incident_limit=12`

Sections are `risks`, `controls`, `evidence`, `approvals`, and `audit`.
List limits are capped at 100. Search treats wildcard characters literally.
The original API endpoints and response shapes are preserved.

## API integration

The router is mounted by scripts/api_server.py under /api/grc.
All routes require the `X-GRC-Token` header matching `SOC_GRC_API_TOKEN`.
Without a configured token they return 503; invalid credentials return 401.
The database is initialized during API startup, not during module import.

Useful endpoints:

- GET /api/grc/health
- GET, POST /api/grc/risks
- GET, PATCH /api/grc/risks/{risk_id}
- GET, POST, PATCH /api/grc/controls
- POST /api/grc/risks/{risk_id}/controls/{control_id}
- GET /api/grc/risks/{risk_id}/controls
- GET, POST /api/grc/evidence
- GET /api/grc/compliance/summary
- GET, POST /api/grc/approvals
- PATCH /api/grc/approvals/{approval_id}/decision
- GET /api/grc/audit-logs
- POST /api/grc/integrations/wazuh/evidence
- POST /api/grc/integrations/sham-ai/assessment

Write endpoints accept an optional X-Actor header for audit attribution. This
header is an attribution field, not individual identity verification. The
shared API token controls access; do not treat a caller-supplied actor name as
proof of a specific person's identity.

## Integrated SOC evidence

Set `SOC_GRC_ENABLED=true` and the same absolute `GRC_DB_PATH` in the SOC agent
and API service environments to enable automatic local synchronization.
Synchronization is disabled by default. No HTTP call or external service is
used by this bridge.

- After ChromaDB persistence, the SOC workflow records Wazuh event references
  against `SHAM-LOG-001` and AI report provenance against `SHAM-AI-002`.
- After the existing protected human-review endpoint appends a decision to
  JSONL, GRC records a separate `human_review` item against `SHAM-AI-001`.
- Related records carry the SOC incident ID. Human-review items also retain
  their original review ID. An AI assessment remains an AI recommendation even
  after a separate human decision is recorded.
- Identical bridge events are deduplicated transactionally. Modified events
  preserve a new evidence version rather than overwriting earlier evidence.
- Full raw logs and reports are not copied into GRC. A report SHA-256 digest,
  model/provider, fallback status, and containment status preserve provenance.
- Evidence and its audit entry commit together. Failure is visible in agent
  logs or the review response's `grc_sync` field. The existing incident/review
  remains saved, and the normal SOC flow continues. There is no automatic retry
  queue; operators must reconcile failed mirrors from the retained source.

These are internal evidence mappings, not verified framework compliance.
Risk ratings, control implementation states, and approvals remain explicit
human-managed records. The bridge never changes `NOT_EXECUTED` into execution.

## Wazuh evidence example

    {
      "alert_id": "1234567890",
      "rule_id": "100100",
      "rule_level": 10,
      "rule_description": "Repeated failed Winbox logins",
      "agent_id": "001",
      "agent_name": "edge-router",
      "timestamp": "2026-11-06T16:00:00Z",
      "source_ip": "192.0.2.10",
      "summary": "Repeated authentication failures were observed.",
      "control_ids": ["SHAM-LOG-001", "SHAM-IR-001"]
    }

The endpoint stores a concise evidence reference and a SHA-256 fingerprint;
it does not store the complete raw Wazuh event.

## SHAM AI assessment example

    {
      "incident_id": "INC-TEST-001",
      "classification": "SUSPICIOUS",
      "severity": "HIGH",
      "summary": "The agent identified repeated authentication failures.",
      "confidence": 0.82,
      "model_name": "local-model",
      "model_version": "configured-version",
      "recommendations": ["Review source address", "Verify account activity"],
      "control_ids": ["SHAM-AI-001", "SHAM-IR-001"]
    }

This endpoint records an AI-generated assessment as evidence only. It does not
approve, execute, or represent containment. The analyst's final decision must
be recorded separately.

## Risk scoring

Score = likelihood (1-5) x impact (1-5):

- 1-4: Low
- 5-9: Medium
- 10-16: High
- 17-25: Critical

Residual risk is calculated only when both residual likelihood and residual
impact are supplied.

## Security deployment notes

GRC routes require their own API token; the existing human-review route keeps
its separate review token. The existing dashboard, broadcast and WebSocket
routes still rely on the deployment's access layer. Protect the full service
with trusted network access or an authenticated reverse proxy and TLS. Protect
the SQLite directory and tokens, define evidence retention, and back up both
GRC and the original SOC/review stores.

The GRC module does not perform automated response or containment.

"""Opt-in, local SOC evidence bridge. Never executes or approves a response."""

import hashlib
import json
import logging
import os

from .db import db_session, initialize_database
from .evidence import insert_evidence

logger = logging.getLogger(__name__)


def _enabled() -> bool:
    return os.getenv("SOC_GRC_ENABLED", "false").strip().lower() in {"true", "1", "yes"}


def _fingerprint(value) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _persist(entries: list) -> dict:
    """Write evidence and audit together; replaying identical events is idempotent."""
    initialize_database()
    evidence_ids = []
    with db_session() as connection:
        connection.execute("BEGIN IMMEDIATE")
        for entry in entries:
            digest = _fingerprint(entry)
            existing = connection.execute(
                """SELECT id FROM evidence
                   WHERE source = ? AND reference_id = ? AND control_id = ? AND sha256 = ?""",
                (entry["source"], entry["reference_id"], entry["control_id"], digest),
            ).fetchone()
            evidence_ids.append(existing["id"] if existing else insert_evidence(
                connection, risk_id=None, sha256=digest, **entry,
            ))
    return {"status": "recorded", "evidence_ids": evidence_ids}


def sync_incident(record, alert: dict) -> dict:
    """Link a persisted incident to internal logging and AI traceability controls."""
    if not _enabled():
        return {"status": "disabled"}
    try:
        data = record.model_dump() if hasattr(record, "model_dump") else dict(record)
        incident_id = data["incident_id"]
        rule = alert.get("rule") or {}
        agent = alert.get("agent") or {}
        # Raw logs and the full model report stay in the existing incident store.
        entries = [
            {
                "source": "wazuh", "reference_id": incident_id,
                "control_id": "SHAM-LOG-001", "collected_by": "soc-workflow",
                "description": str(rule.get("description") or data["rule_name"])[:2000],
                "metadata": {
                    "incident_id": incident_id, "alert_id": alert.get("id"),
                    "rule_id": rule.get("id"), "rule_level": rule.get("level"),
                    "agent_id": agent.get("id"), "agent_name": agent.get("name"),
                    "timestamp": alert.get("timestamp"),
                },
            },
            {
                "source": "sham_ai", "reference_id": incident_id,
                "control_id": "SHAM-AI-002", "collected_by": "soc-workflow",
                "description": str(data["alert_summary"])[:2000],
                "metadata": {
                    "classification": data["classification"],
                    "llm_provider": data["llm_provider"], "llm_model": data["llm_model"],
                    "fallback_used": data["fallback_used"],
                    "containment_status": data["containment_status"],
                    "report_sha256": hashlib.sha256(data["analyst_notes"].encode("utf-8")).hexdigest(),
                    "human_review_status": "pending",
                    "decision_authority": "recommendation_only_human_analyst_retains_final_decision",
                },
            },
        ]
        return _persist(entries)
    except Exception as exc:
        logger.warning("GRC incident evidence synchronization failed (%s)", type(exc).__name__)
        return {"status": "error", "message": "GRC evidence was not synchronized; the SOC incident is retained."}


def sync_human_review(review: dict) -> dict:
    """Keep the analyst decision separate from the original model assessment."""
    if not _enabled():
        return {"status": "disabled"}
    try:
        return _persist([{
            "source": "human_review", "reference_id": review["review_id"],
            "control_id": "SHAM-AI-001", "collected_by": review["reviewer"],
            "description": "Human review of incident " + review["incident_id"],
            "metadata": {
                **review,
                "decision_authority": "human_review_only_no_response_executed",
            },
        }])
    except Exception as exc:
        logger.warning("GRC human-review synchronization failed (%s)", type(exc).__name__)
        return {"status": "error", "message": "GRC evidence was not synchronized; the original review log is retained."}

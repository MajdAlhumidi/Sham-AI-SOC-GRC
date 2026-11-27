"""Append-only audit records for human review of SHAM AI suggestions."""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

ALLOWED_CLASSIFICATIONS = {
    "true_positive",
    "false_positive",
    "suspicious",
    "benign",
    "unknown",
}
ALLOWED_DECISIONS = {"accepted", "corrected", "escalated"}


def append_human_review(payload: Dict[str, Any], path: Optional[str] = None, *, principal=None) -> Dict[str, Any]:
    """Validate and append one human-review decision without modifying the original incident."""
    if not isinstance(payload, dict):
        raise ValueError("Review payload must be an object.")

    incident_id = str(payload.get("incident_id", "")).strip()
    reviewer = str(payload.get("reviewer", "")).strip()
    agent_classification = str(payload.get("agent_classification", "")).strip().lower()
    decision = str(payload.get("decision", "")).strip().lower()
    final_value = payload.get("final_classification")
    final_classification = str(final_value).strip().lower() if final_value is not None else ""
    notes = str(payload.get("notes", "")).strip()

    if not incident_id or len(incident_id) > 128:
        raise ValueError("incident_id is required and must be at most 128 characters.")
    if not reviewer or len(reviewer) > 128:
        raise ValueError("reviewer is required and must be at most 128 characters.")
    if agent_classification not in ALLOWED_CLASSIFICATIONS:
        raise ValueError("agent_classification is not a supported classification.")
    if decision not in ALLOWED_DECISIONS:
        raise ValueError("decision must be accepted, corrected, or escalated.")
    if len(notes) > 2000:
        raise ValueError("notes must be at most 2000 characters.")
    if final_classification and final_classification not in ALLOWED_CLASSIFICATIONS:
        raise ValueError("final_classification is not a supported classification.")

    if decision == "accepted":
        if final_classification and final_classification != agent_classification:
            raise ValueError("An accepted suggestion must retain the agent classification.")
        final_classification = agent_classification
    elif decision == "corrected":
        if not final_classification:
            raise ValueError("A corrected decision requires final_classification.")
        if final_classification == agent_classification:
            raise ValueError("A corrected decision must differ from the agent classification.")
    else:  # escalated
        if final_classification:
            raise ValueError("An escalated review must not assert a final classification.")
        final_classification = ""

    recommendations = payload.get("agent_recommendations") or []
    if not isinstance(recommendations, list):
        raise ValueError("agent_recommendations must be a list of strings.")
    recommendations = [str(item).strip()[:500] for item in recommendations[:10] if str(item).strip()]

    record = {
        "review_id": "REV-" + uuid.uuid4().hex[:12].upper(),
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "incident_id": incident_id,
        "agent_classification": agent_classification,
        "agent_recommendations": recommendations,
        "human_decision": decision,
        "final_classification": final_classification or None,
        "reviewer": principal.actor_id if principal else reviewer,
        "notes": notes,
    }
    if principal:
        record.update(
            reviewer_display=reviewer, authenticated_subject=principal.subject,
            authenticated_roles=sorted(principal.roles), auth_mode=principal.auth_mode,
        )

    destination = path or os.getenv("SOC_HUMAN_REVIEW_LOG_PATH", "logs/human_reviews.jsonl")
    directory = os.path.dirname(destination)
    if directory:
        os.makedirs(directory, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    try:
        os.chmod(destination, 0o600)
    except OSError:
        pass

    return record


def sync_review_memory(review, vector_path):
    """Update historical metadata after a recorded, authenticated final decision."""
    if review.get("auth_mode") != "token" or not review.get("final_classification"):
        return "not_eligible"
    if not os.path.isdir(vector_path):
        return "unavailable"
    try:
        import chromadb

        collection = chromadb.PersistentClient(path=vector_path).get_collection("security_incidents")
        incident_id = review["incident_id"]
        existing = collection.get(ids=[incident_id], include=["metadatas"])
        if not existing.get("ids"):
            return "incident_unavailable"
        previous = (existing["metadatas"][0] or {}).get("human_review_at", "")
        if previous > review["reviewed_at"]:
            return "newer_review_retained"
        collection.update(ids=[incident_id], metadatas=[{
            "human_review_status": "verified",
            "human_classification": review["final_classification"],
            "classification_source": "authenticated_human_review",
            "human_review_id": review["review_id"],
            "human_review_at": review["reviewed_at"],
        }])
        return "verified"
    except Exception:
        return "unavailable"

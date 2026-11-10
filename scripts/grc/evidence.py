"""Shared transactional evidence storage for the API and local SOC workflow."""

import json
import uuid
from typing import Optional

from .audit import record_audit
from .db import utc_now


def insert_evidence(
    connection, *, risk_id: Optional[str], control_id: Optional[str],
    source: str, reference_id: str, description: str, sha256: Optional[str],
    metadata: dict, collected_by: str,
) -> str:
    evidence_id = "EVD-" + uuid.uuid4().hex[:12].upper()
    connection.execute(
        """INSERT INTO evidence (
            id, risk_id, control_id, source, reference_id, description,
            sha256, metadata_json, collected_by, collected_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (evidence_id, risk_id, control_id, source, reference_id, description,
         sha256, json.dumps(metadata, ensure_ascii=False, default=str), collected_by, utc_now()),
    )
    record_audit(
        connection, collected_by, "evidence.recorded", "evidence", evidence_id,
        after={"source": source, "reference_id": reference_id,
               "risk_id": risk_id, "control_id": control_id},
    )
    return evidence_id

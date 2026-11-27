"""Bounded, redacted, offline case evidence bundles.

The manifest fingerprints the bytes in the ZIP, not unredacted source records.
Source hash comparisons are reported separately and never establish truth.
"""
from __future__ import annotations

from hashlib import sha256
from html import escape
from tempfile import TemporaryFile
import importlib
import json
import os
import re
from zipfile import ZIP_DEFLATED, ZipFile

from . import store

MAX_EVENTS = 200
MAX_EVIDENCE = 1200
MAX_AUDIT = 2000
MAX_FOLLOWUPS = 40
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_COMPRESSED_BYTES = 17 * 1024 * 1024
MAX_FILES = 1600
REDACTED = "[REDACTED]"


class ExportLimitError(ValueError):
    """The complete export cannot fit within its declared safety limits."""


def _key_secret(key):
    normal = re.sub(r"[^a-z0-9]", "", str(key).lower())
    return (any(part in normal for part in ("password", "passwd", "passphrase", "secret", "credential", "privatekey", "apikey", "accesskey", "token"))
            or normal in {"pwd", "authorization", "proxyauthorization", "cookie", "setcookie"})


# Free-text logs may contain nested/escaped JSON or shell quoting. Omit the
# entire remaining credential-bearing line rather than trusting its quoting.
_ASSIGNMENT = re.compile(
    r'''(?im)(\b(?:[a-z0-9_.-]*(?:password|passwd|passphrase|secret|credential|api[_-]?key|access[_-]?key|token)[a-z0-9_.-]*|pwd|authorization|proxy-authorization|cookie|set-cookie)(?:[\\]*["'])?\s*[:=]\s*)[^\r\n]*''')
_AUTH_VALUE = re.compile(r"(?i)\b(Bearer|Basic)\s+[a-z0-9._~+/-]+=*")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_PRIVATE_KEY = re.compile(r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?(?:-----END [^-\r\n]*PRIVATE KEY-----|\Z)", re.S)
_URL_CREDENTIALS = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^\s/@]+(?::[^\s/@]*)?@")
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")


def _known_secrets(value, found=None, depth=0):
    found = set() if found is None else found
    if depth > 50:
        raise ExportLimitError("Export limit: nested record depth exceeds 50.")
    if isinstance(value, dict):
        for key, item in value.items():
            if _key_secret(key):
                def leaves(node, level=0):
                    if level > 50:
                        raise ExportLimitError("Export limit: nested credential depth exceeds 50.")
                    if isinstance(node, str) and len(node) >= 4:
                        found.add(node)
                        auth = re.match(r"(?i)^(?:Bearer|Basic)\s+(.+)$", node)
                        if auth and len(auth[1]) >= 4:
                            found.add(auth[1])
                    elif isinstance(node, dict):
                        for child in node.values():
                            leaves(child, level + 1)
                    elif isinstance(node, list):
                        for child in node:
                            leaves(child, level + 1)
                leaves(item)
            _known_secrets(item, found, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _known_secrets(item, found, depth + 1)
    return found


def _redact(value, known=(), depth=0):
    if depth > 50:
        raise ExportLimitError("Export limit: nested record depth exceeds 50.")
    if isinstance(value, dict):
        return {_redact(str(key), known, depth + 1): REDACTED if _key_secret(key) else _redact(item, known, depth + 1)
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item, known, depth + 1) for item in value]
    if isinstance(value, str):
        text = _PRIVATE_KEY.sub(REDACTED, value)
        text = _URL_CREDENTIALS.sub(lambda m: m[1] + REDACTED + "@", text)
        text = _ASSIGNMENT.sub(lambda m: m[1] + REDACTED, text)
        text = _AUTH_VALUE.sub(lambda m: m[1] + " " + REDACTED, text)
        text = _JWT.sub(REDACTED, text)
        text = _AWS_KEY.sub(REDACTED, text)
        for secret in sorted(known, key=len, reverse=True):
            text = text.replace(secret, REDACTED)
        return text
    return value


def redact_for_output(value):
    """Redact diagnostic or outbound data without altering source evidence."""
    known = _known_secrets(value)
    known.update(_known_secrets({
        name: value for name, value in os.environ.items()
        if name.startswith(("SOC_", "GRC_", "WAZUH_", "THEHIVE_", "GEMINI_", "ABUSEIPDB_", "VIRUSTOTAL_", "GREYNOISE_"))
    }))
    try:
        tokens = json.loads(os.getenv("SOC_API_TOKENS_JSON", "{}"))
        if isinstance(tokens, dict):
            known.update(token for token in tokens if len(token) >= 4)
    except ValueError:
        pass
    return _redact(value, known)


def _json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, default=str) + "\n").encode("utf-8")


def _parse(raw, limitations, label):
    try:
        return json.loads(raw) if raw is not None else None
    except (ValueError, TypeError, RecursionError):
        limitations.append(label + ": stored JSON is invalid; raw bytes omitted.")
        return {"unreadable_record": True, "raw_data_omitted": True}


class _Budget:
    def __init__(self):
        self.total = 0

    def check(self, count, size, largest, maximum, label):
        if count > maximum:
            raise ExportLimitError(f"Export limit: {label} count {count} exceeds {maximum}; no partial export was produced.")
        if largest > MAX_RECORD_BYTES:
            raise ExportLimitError(f"Export limit: a {label} record exceeds {MAX_RECORD_BYTES} source bytes.")
        self.total += size
        if self.total > MAX_SOURCE_BYTES:
            raise ExportLimitError(f"Export limit: source records exceed {MAX_SOURCE_BYTES} bytes; no partial export was produced.")


def _check_query(conn, budget, table, where, args, fields, maximum, label):
    # All identifiers and expressions are internal constants, never user input.
    length = "+".join("COALESCE(length(CAST(" + f + " AS BLOB)),0)" for f in fields)
    row = conn.execute(f"SELECT COUNT(*),COALESCE(SUM({length}),0),COALESCE(MAX({length}),0) FROM {table} WHERE {where}", args).fetchone()
    budget.check(row[0], row[1], row[2], maximum, label)
    return row


def _snapshot(case_id):
    limitations = []
    budget = _Budget()
    with store.db() as conn:
        conn.execute("BEGIN")
        _check_query(conn, budget, "cases", "id=?", (case_id,), ["id", "created_at"], 1, "case headers")
        case_row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not case_row:
            raise KeyError("Case not found")
        _check_query(conn, budget, "events", "case_id=?", (case_id,), ["payload", "id", "asset_key", "rule_key", "source_ip", "account", "received_at", "join_reason"], MAX_EVENTS, "events")
        rows = conn.execute("SELECT * FROM events WHERE case_id=? ORDER BY event_epoch IS NULL,event_epoch,received_at,id", (case_id,)).fetchall()
        if not rows:
            raise KeyError("Case has no retained events")
        ids = [row["id"] for row in rows]
        marks = ",".join("?" for _ in ids)
        _check_query(conn, budget, "evidence", f"incident_id IN ({marks})", ids, ["payload", "incident_id", "ref", "sha256"], MAX_EVIDENCE, "evidence")
        assets = sorted({row["asset_key"] for row in rows})
        amarks = ",".join("?" for _ in assets)
        _check_query(conn, budget, "assets", f"id IN ({amarks})", assets, ["id", "payload"], MAX_EVENTS, "assets")
        _check_query(conn, budget, "changes", f"asset_id IN ({amarks})", assets, ["id", "asset_id", "payload"], MAX_AUDIT, "changes")
        asset_rows = conn.execute(f"SELECT id,payload FROM assets WHERE id IN ({amarks}) ORDER BY id", assets).fetchall()
        change_rows = conn.execute(f"SELECT id,payload FROM changes WHERE asset_id IN ({amarks}) ORDER BY id", assets).fetchall()
        references = [case_id] + ids + assets + [r["id"] for r in change_rows]
        followup_table = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='case_followup_turns'").fetchone()
        followup_count = None
        if followup_table:
            followup_count = _check_query(conn, budget, "case_followup_turns", "case_id=?", (case_id,), ["id", "question", "snapshot_json", "result_json"], MAX_FOLLOWUPS, "follow-up turns")[0]
            references += [r[0] for r in conn.execute("SELECT id FROM case_followup_turns WHERE case_id=?", (case_id,))]
        rmarks = ",".join("?" for _ in references)
        _check_query(conn, budget, "audit", f"reference IN ({rmarks})", references, ["at", "action", "reference", "before_json", "after_json"], MAX_AUDIT, "audit records")
        audit_rows = conn.execute(f"SELECT * FROM audit WHERE reference IN ({rmarks}) ORDER BY id", references).fetchall()
        evidence_rows = conn.execute(f"SELECT * FROM evidence WHERE incident_id IN ({marks}) ORDER BY incident_id,ref", ids).fetchall()
        events = [{"incident_id": r["id"], "asset_id": r["asset_key"], "received_at": r["received_at"], "legacy": bool(r["legacy"]), "join_reason": r["join_reason"],
                   "record": _parse(r["payload"], limitations, "Incident record")} for r in rows]
        profiles = [_parse(r["payload"], limitations, "Asset profile") for r in asset_rows]
        changes = [_parse(r["payload"], limitations, "Change context") for r in change_rows]
        audit = []
        for row in audit_rows:
            item = dict(row)
            item["before"] = _parse(item.pop("before_json"), limitations, "Audit before-state")
            item["after"] = _parse(item.pop("after_json"), limitations, "Audit after-state")
            audit.append(item)
        evidence = []
        for row in evidence_rows:
            actual = sha256(row["payload"].encode("utf-8")).hexdigest()
            evidence.append({"incident_id": row["incident_id"], "ref": row["ref"],
                             "source_integrity": {"expected_stored_sha256": row["sha256"], "observed_stored_sha256": actual,
                                                  "matches_stored_fingerprint": actual == row["sha256"],
                                                  "meaning": "Stored-byte comparison before export redaction; does not verify truth or an external source."},
                             "record": _parse(row["payload"], limitations, "Evidence record")})
        return {"id": case_id, "created_at": case_row["created_at"], "events": events, "asset_profiles": profiles, "approved_change_context": changes}, evidence, audit, limitations, followup_count


def _turns(case_id, limitations, expected_count=None):
    try:
        module = importlib.import_module(__package__ + ".followup")
    except ModuleNotFoundError as exc:
        if exc.name != __package__ + ".followup":
            raise
        limitations.append("Follow-up module is not available in this checkout; no follow-up turns exported.")
        return []
    listed = module.list_turns(case_id, limit=MAX_FOLLOWUPS + 1)
    if len(listed) > MAX_FOLLOWUPS:
        raise ExportLimitError("Export limit: too many follow-up turns; no partial export was produced.")
    if expected_count is not None and len(listed) != expected_count:
        raise ValueError("Follow-up record count changed or was truncated during export; retry to obtain a complete bundle.")
    turns = []
    for item in listed:
        full = module.get_turn(case_id, item["id"])
        if full is None:
            limitations.append("A follow-up turn disappeared during export; its recorded status is retained without inventing an answer.")
            full = {**item, "export_source_missing": True}
        if len(_json_bytes(full)) > MAX_RECORD_BYTES:
            raise ExportLimitError("Export limit: a follow-up turn exceeds the per-record byte limit.")
        turns.append(full)
    return turns


def _followup_source_integrity(entry):
    """Describe a captured copy without equating a bounded excerpt to its source."""
    if not isinstance(entry, dict):
        return {"comparison": "not_recorded", "matches_recorded_fingerprint": None,
                "meaning": "No structured captured source fingerprint is available."}
    fingerprint = entry.get("sha256")
    expected = fingerprint if isinstance(fingerprint, str) and re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint) else None
    if expected:
        expected = expected.lower()
    record = entry.get("record")
    actual = sha256(store.encode(record).encode("utf-8")).hexdigest() if record is not None else None
    bounded = bool(entry.get("snapshot_truncated"))
    comparison = ("not_comparable_bounded_snapshot" if bounded else
                  "not_recorded" if not expected or actual is None else
                  "matches_recorded_fingerprint" if expected == actual else "record_copy_fingerprint_mismatch")
    return {"expected_source_sha256": expected, "observed_input_record_canonical_sha256": actual,
            "recorded_capture_integrity_ok": entry.get("integrity_ok") if isinstance(entry.get("integrity_ok"), bool) else None,
            "matches_recorded_fingerprint": None if bounded or not expected or actual is None else expected == actual,
            "comparison": comparison, "snapshot_truncated": bounded,
            "meaning": "The saved fingerprint describes the captured source before export redaction. A bounded snapshot/excerpt is not byte-equal to that source and cannot revalidate it. Complete copies are compared using canonical UTF-8 JSON before redaction. Recorded capture flags are historical assertions, not a fresh external source check; manifest file hashes describe actual exported bytes."}


def _report(case, evidence_index, turns, limitations, audit):
    def pre(value):
        return "<pre>" + escape(value if isinstance(value, str) else _json_bytes(value).decode("utf-8")) + "</pre>"
    parts = ['<!doctype html><html lang="en"><meta charset="utf-8">',
             '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
             '<title>SHAM AI case evidence report</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:1rem;color:#17232d}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f2f4f6;padding:1rem}h1,h2,h3{break-after:avoid}table{border-collapse:collapse;width:100%}td,th{text-align:left;border:1px solid #ccd3d9;padding:.5rem}.notice{border-left:4px solid #b26900;padding:1rem;background:#fff7e7}@media print{body{margin:0;max-width:none}a{color:inherit}pre{font-size:10pt}}</style>',
             '<body><h1>SHAM AI case evidence report</h1><p>Case: <strong>' + escape(str(case["id"])) + '</strong></p>',
             '<p class="notice">This is a redacted point-in-time case record for analyst review. It does not certify the truth of sources, attribution, a compromise, or regulatory compliance. No containment or external lookup is performed by export. The ZIP manifest fingerprints exported bytes; original stored-record comparisons are reported separately. Use your browser Print command to save this report as PDF.</p>',
             '<h2>Limitations and integrity findings</h2><ul>']
    parts += ['<li>' + escape(str(item)) + '</li>' for item in limitations]
    parts += ['</ul><h2>Asset profiles and approved-change context</h2>', pre({"asset_profiles": case["asset_profiles"], "approved_change_context": case["approved_change_context"]}), '<h2>Incident timeline and assessments</h2>']
    for event in case["events"]:
        record = event.get("record") or {}
        if not isinstance(record, dict):
            record = {"retained_value": record}
        parts += ['<h3>' + escape(str(event["incident_id"])) + '</h3>',
                  pre({k: record.get(k, "not recorded") for k in (
                      "event_time", "time_basis", "classification", "provider", "model", "fallback_used",
                      "report_provenance", "rule_mappings", "limitations", "findings",
                  )}),
                  pre(record.get("report", "Report unavailable.")), '<p>' + escape(str(event.get("join_reason", ""))) + '</p>']
    parts += ['<h2>Captured evidence index</h2><table><thead><tr><th>Source reference</th><th>Recorded status</th><th>Stored-byte integrity</th><th>Exported record</th></tr></thead><tbody>']
    for item in evidence_index:
        match = item["source_integrity"]["matches_stored_fingerprint"]
        parts.append('<tr><td>' + escape(str(item["incident_id"]) + ' / ' + str(item["ref"])) + '</td><td>' + escape(str(item["status"])) + '</td><td>' + ('matches stored fingerprint' if match else 'MISMATCH: stored bytes changed') + '</td><td><a href="' + item["path"] + '">JSON record</a></td></tr>')
    parts += ['</tbody></table><h2>Follow-up investigations</h2><p>Saved follow-up evidence may be a bounded snapshot or excerpt. Its recorded original-source fingerprint is not the hash of that excerpt or of the redacted export. Per-item source-integrity metadata states whether a complete-copy comparison was possible. Historical capture flags are not a fresh external source check; use the manifest to verify the actual exported file bytes.</p>']
    if not turns:
        parts.append('<p>No follow-up turns were retained for this export.</p>')
    for turn in turns:
        parts += ['<h3>' + escape(str(turn.get("id", "Recorded turn"))) + '</h3>', pre(turn)]
    parts += ['<h2>Relevant case and asset audit records</h2>', pre(audit), '<p>Audit entries and operator labels are recorded application data, not proof of a verified individual identity or an externally signed ledger. Credential-like fields and inline assignments were redacted; redaction does not anonymize all personal or organizational data.</p></body></html>']
    return "".join(parts).encode("utf-8")


def open_bundle(case_id, *, credentials=()):
    """Build a bounded ZIP in a temporary file and return it ready to stream."""
    if not isinstance(case_id, str) or not case_id or len(case_id) > 240:
        raise ValueError("Use a retained case ID of at most 240 characters.")
    case, evidence, audit, limitations, followup_count = _snapshot(case_id)
    turns = _turns(case_id, limitations, followup_count)
    turn_integrity = []
    for turn in turns:
        captured = turn.get("evidence") or {}
        iterable = captured.items() if isinstance(captured, dict) else enumerate(captured)
        turn_integrity.append({str(ref): _followup_source_integrity(entry) for ref, entry in iterable})
    known = _known_secrets([case, evidence, audit, turns])
    known.update(value for value in credentials if isinstance(value, str) and len(value) >= 4)
    case, evidence, audit, turns = (_redact(value, known) for value in (case, evidence, audit, turns))
    limitations = _redact(limitations, known)
    limitations += ["Sources are the records captured by this deployment, not independently retrieved originals.",
                    "Original alerts or tool results may have been bounded at capture time. Missing results are not reconstructed from report prose.",
                    "Provider/model/fallback states are retained where recorded; an absent field means not recorded, never inferred success.",
                    "Queued/running follow-up turns have no completed answer. A failed turn is not a completed investigation.",
                    "Asset profiles and approved-change context are current operator-entered records, not independently verified facts."]
    files = {}
    file_metadata = {}
    total = 0

    def add(path, value, *, media_type="application/json", source=None):
        nonlocal total
        if not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\.[a-z0-9]+", path):
            raise ValueError("Unsafe evidence archive entry name.")
        data = value if isinstance(value, bytes) else _json_bytes(value)
        total += len(data)
        if total > MAX_OUTPUT_BYTES or len(files) + 1 > MAX_FILES:
            raise ExportLimitError("Export limit: output bytes or file count exceeded; no partial export was produced.")
        files[path] = data
        file_metadata[path] = {"path": path, "size_bytes": len(data), "sha256": sha256(data).hexdigest(), "media_type": media_type}
        if source is not None:
            file_metadata[path]["source_integrity"] = source

    index = []
    refs = {}
    for n, item in enumerate(evidence, 1):
        path = f"evidence/record-{n:04d}.json"
        add(path, item, source=item["source_integrity"])
        record = item.get("record") or {}
        status = record.get("status", "not recorded") if isinstance(record, dict) else "invalid record"
        entry = {"incident_id": item["incident_id"], "ref": item["ref"], "path": path, "status": status, "source_integrity": item["source_integrity"]}
        index.append(entry)
        refs.setdefault(item["incident_id"], set()).add(item["ref"])
        if not item["source_integrity"]["matches_stored_fingerprint"]:
            limitations.append("Evidence integrity MISMATCH: " + str(item["incident_id"]) + " / " + str(item["ref"]) + ". Stored bytes do not match their earlier fingerprint.")
        if status in {"error", "blocked", "budget_exhausted", "unavailable", "missing"}:
            limitations.append("Captured evidence " + str(item["incident_id"]) + " / " + str(item["ref"]) + " records status: " + str(status) + ".")
    for event in case["events"]:
        record = event.get("record") or {}
        expected = {"M1" if event["legacy"] else "A1"}
        if isinstance(record, dict):
            for finding in record.get("findings", []):
                if isinstance(finding, dict):
                    expected.update(ref for ref in finding.get("evidence", []) if isinstance(ref, str))
        for ref in sorted(expected - refs.get(event["incident_id"], set())):
            limitations.append("Missing source evidence: " + str(event["incident_id"]) + " / " + ref + ". Citation text does not replace the missing record.")
    turn_index = []
    for n, turn in enumerate(turns, 1):
        turn = dict(turn)
        captured = turn.pop("evidence", None)
        paths = []
        if captured:
            iterable = captured.items() if isinstance(captured, dict) else enumerate(captured)
            for j, (ref, record) in enumerate(iterable, 1):
                path = f"followups/turn-{n:04d}-evidence-{j:04d}.json"
                integrity = turn_integrity[n-1][str(ref)]
                add(path, {"turn_id": turn.get("id"), "ref": str(ref), "source_integrity": integrity, "record": record}, source=integrity)
                paths.append({"ref": str(ref), "path": path})
                if integrity["comparison"] in {"not_comparable_bounded_snapshot", "record_copy_fingerprint_mismatch"}:
                    limitations.append("Follow-up source " + str(turn.get("id")) + " / " + str(ref) + ": " + integrity["comparison"] + ". A saved source fingerprint must not be treated as the hash of a bounded or changed copy.")
        turn["exported_evidence"] = paths
        path = f"followups/turn-{n:04d}.json"
        add(path, turn)
        turn_index.append({"id": turn.get("id"), "status": turn.get("status", "not recorded"), "path": path})
    case["evidence_index"] = index
    case["followup_index"] = turn_index
    case["exported_at"] = store.now()
    case["limitations"] = limitations
    add("case.json", case)
    add("audit.json", {"scope": "This case, its incidents, observed assets, change records and follow-up turns; asset edits may affect other cases too.", "items": audit})
    add("report.html", _report(case, index, turns, limitations, audit), media_type="text/html; charset=utf-8")
    manifest = {"format": "SHAM-AI-case-bundle-v1", "case_id": case["id"], "exported_at": case["exported_at"],
                "hash_algorithm": "SHA-256", "hash_scope": "Exact bytes of every listed file after redaction. The manifest itself is not self-hashed or externally signed.",
                "source_hash_scope": "Initial evidence compares retained UTF-8 JSON bytes before redaction. Complete follow-up record copies use canonical JSON comparisons; bounded snapshots explicitly cannot revalidate original-source fingerprints. These comparisons are separate from exported file hashes.",
                "limitations": limitations, "files": [file_metadata[path] for path in sorted(files)]}
    add("manifest.json", manifest)
    output = TemporaryFile(mode="w+b")
    try:
        with ZipFile(output, "w", compression=ZIP_DEFLATED, compresslevel=6) as archive:
            for path in sorted(files):
                archive.writestr(path, files[path])
                if output.tell() > MAX_COMPRESSED_BYTES:
                    raise ExportLimitError("Export limit: compressed bytes exceeded.")
        if output.tell() > MAX_COMPRESSED_BYTES:
            raise ExportLimitError("Export limit: compressed bytes exceeded.")
        output.seek(0)
    except BaseException:
        output.close()
        raise
    slug = re.sub(r"[^A-Za-z0-9_-]", "_", case_id)[:80].strip("_") or "case"
    return output, slug + "-evidence.zip"


def build_bundle(case_id):
    """Return the bounded ZIP as bytes for existing local callers."""
    output, filename = open_bundle(case_id)
    with output:
        return output.read(), filename

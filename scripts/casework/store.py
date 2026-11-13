"""Local, transactional case workspace. No model or response actions run here."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json
import os
import re
import sqlite3

try:
    from ..alert_context import resolve_alert_asset
except ImportError:
    from alert_context import resolve_alert_asset

POLICY = "correlation-v1 / priority-v1"
WINDOW = 30 * 60
EMPTY = {"", "n/a", "unknown", "unknown host", "local-agent", "none"}


def now():
    return datetime.now(timezone.utc).isoformat()


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def clean(value):
    value = str(value or "").strip()
    return "" if value.lower() in EMPTY else value


def epoch(value, *, legacy=False):
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            if not legacy:
                return None
            dt = dt.replace(tzinfo=timezone.utc)  # Old IncidentRecord used utcnow().
        return dt.timestamp()
    except (ValueError, TypeError, OverflowError):
        return None


@contextmanager
def db():
    path = Path(os.getenv("SOC_CASE_DB_PATH", "data/investigations.sqlite3"))
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=20)
    if os.name != "nt":
        path.chmod(0o600)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
      CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS events(
        id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
        asset_key TEXT NOT NULL, rule_key TEXT NOT NULL, source_ip TEXT NOT NULL,
        account TEXT NOT NULL, event_epoch REAL, received_at TEXT NOT NULL,
        legacy INTEGER NOT NULL, join_reason TEXT NOT NULL, payload TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS event_correlation ON events(asset_key,rule_key,event_epoch);
      CREATE INDEX IF NOT EXISTS event_case ON events(case_id);
      CREATE TABLE IF NOT EXISTS evidence(
        incident_id TEXT NOT NULL REFERENCES events(id), ref TEXT NOT NULL,
        payload TEXT NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(incident_id,ref));
      CREATE TABLE IF NOT EXISTS assets(
        id TEXT PRIMARY KEY, payload TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS changes(
        id TEXT PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES assets(id),
        payload TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1);
      CREATE TABLE IF NOT EXISTS audit(
        id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, action TEXT NOT NULL,
        reference TEXT NOT NULL, before_json TEXT, after_json TEXT NOT NULL);
      CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
        BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
      CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
        BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
    """)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def log(conn, action, reference, before, after):
    conn.execute("INSERT INTO audit(at,action,reference,before_json,after_json) VALUES(?,?,?,?,?)",
                 (now(), action, reference, encode(before), encode(after)))


def asset_identity(record, alert):
    if alert:
        asset = resolve_alert_asset(alert)
        agent_id = clean((alert.get("agent") or {}).get("id"))
        if asset["source"] == "remote_syslog":
            key = "syslog:" + asset["ip"]
        elif agent_id and agent_id != "000":
            key = "agent:" + agent_id
        else:
            key = "host:" + clean(asset["name"]).lower() if clean(asset["name"]) else ""
        return key, asset["name"], asset["ip"]
    host = clean(record.get("target_host")) or clean(record.get("destination_ip"))
    return ("legacy:" + host.lower() if host else ""), host or "Unresolved asset", clean(record.get("destination_ip"))


def _evidence(conn, incident_id, ref, payload):
    raw = encode(payload)
    conn.execute("INSERT INTO evidence VALUES(?,?,?,?)", (incident_id, ref, raw, sha256(raw.encode()).hexdigest()))


def capture(record, alert=None, context=None):
    """Idempotent per incident; originals immutable. Old metadata never becomes A1."""
    record = record.model_dump() if hasattr(record, "model_dump") else dict(record)
    alert, context = alert or {}, context or {}
    incident_id = clean(record.get("incident_id"))
    if not incident_id:
        raise ValueError("Incident ID is required")
    legacy = not bool(alert)
    asset_key, host, address = asset_identity(record, alert)
    # Unknown assets are never grouped together or assigned a shared profile.
    asset_key = asset_key or "unresolved:" + incident_id
    rule_key = clean((alert.get("rule") or {}).get("id"))
    data = alert.get("data") or {}
    source = clean(data.get("srcip") or data.get("src_ip")) if alert else clean(record.get("source_ip"))
    account = clean(data.get("dstuser") or data.get("srcuser") or data.get("user")) if alert else clean(record.get("user_account"))
    event_time = alert.get("timestamp") if alert else record.get("timestamp")
    stamp = epoch(event_time, legacy=legacy)
    reason = "Standalone: insufficient observed identifiers or event time."
    case_id = "CASE-" + sha256(incident_id.encode()).hexdigest()[:16].upper()
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute("SELECT case_id FROM events WHERE id=?", (incident_id,)).fetchone()
        if existing:
            return existing["case_id"]
        if not legacy and stamp is not None and rule_key and source and not asset_key.startswith("unresolved:"):
            candidates = conn.execute("""SELECT DISTINCT case_id FROM events WHERE legacy=0
              AND asset_key=? AND rule_key=? AND source_ip=? AND account=?
              AND event_epoch BETWEEN ? AND ?""",
              (asset_key, rule_key, source, account, stamp-WINDOW, stamp+WINDOW)).fetchall()
            eligible = []
            for row in candidates:
                bounds = conn.execute("SELECT MIN(event_epoch), MAX(event_epoch) FROM events WHERE case_id=?", (row[0],)).fetchone()
                if max(bounds[1], stamp)-min(bounds[0], stamp) <= WINDOW:
                    eligible.append(row[0])
            if len(eligible) == 1:
                case_id = eligible[0]
                reason = "Same observed asset, Wazuh rule, source address and account state; entire case spans at most 30 minutes."
                if not account:
                    reason += " Account was unavailable in both events."
            elif len(eligible) > 1:
                reason = "Standalone: multiple eligible cases; no ambiguous automatic merge."
            else:
                reason = "First event for this asset, rule, source and account within a 30-minute case window."
        if legacy:
            reason = "Legacy report: source event/time not recovered; automatic correlation disabled."
        conn.execute("INSERT OR IGNORE INTO cases VALUES(?,?)", (case_id, now()))
        if not asset_key.startswith("unresolved:") and not conn.execute("SELECT 1 FROM assets WHERE id=?", (asset_key,)).fetchone():
            profile = dict(id=asset_key, name=host, address=address, owner="", service="", criticality="unassessed", sensitivity="unassessed", revision=0)
            conn.execute("INSERT INTO assets VALUES(?,?,0)", (asset_key, encode(profile)))
        payload = dict(incident_id=incident_id, source_alert_id=record.get("source_alert_id", ""),
                       host=host, rule_name=record.get("rule_name", "Security alert"), rule_id=rule_key,
                       rule_level=int((alert.get("rule") or {}).get("level", 0) or 0) if alert else int(record.get("rule_level", 0) or 0), classification=record.get("classification", "unknown"),
                       source_ip=source, account=account, event_time=event_time,
                       time_basis="report_created_utc" if legacy else "source_event",
                       report=record.get("analyst_notes", ""), fallback_used=record.get("fallback_used"),
                       findings=[], limitations=[], asset_id=asset_key, captured_at=now())
        if legacy:
            payload["limitations"] = ["Archived report only. Original alert and complete tool responses are unavailable here; report citations are not verified."]
        else:
            assessment = context.get("validated_assessment") or {}
            packet = context.get("report_evidence_packet") or {}
            payload["findings"] = assessment.get("findings", [])
            payload["limitations"] = list(assessment.get("limitations", []))
            if not payload["findings"]:
                payload["findings"] = [{"observation": "Wazuh recorded this rule on the observed asset. Cause and compromise are not established by the alert alone.", "evidence": ["A1"], "origin": "runtime observation"}]
                payload["limitations"].append("No validated structured model findings were recorded. Read the report as preliminary triage.")
            payload["limitations"].extend(context.get("audit_warnings", []))
            if stamp is None:
                payload["limitations"].append("Source timestamp is missing, invalid or lacks a timezone; automatic correlation disabled.")
        conn.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?)", (incident_id, case_id, asset_key, rule_key, source, account, stamp, now(), int(legacy), reason, encode(payload)))
        if legacy:
            _evidence(conn, incident_id, "M1", {"kind": "legacy_metadata", "source": "ChromaDB security_incidents", "status": "archive_only", "value": record, "captured_at": now()})
        else:
            _evidence(conn, incident_id, "A1", {"kind": "incoming_alert", "source": "Wazuh", "status": "observed", "event_time": event_time, "captured_at": now(), "value": alert, "model_view": packet.get("A1")})
            for n, item in enumerate(context.get("tool_results", []), 1):
                _evidence(conn, incident_id, "T"+str(n), {**item, "kind": "tool_result", "source": item.get("tool_name", "unknown"), "captured_at": now(), "model_view": packet.get("T"+str(n)), "capture_limit": "Stored tool result is bounded to 12,000 characters by the investigator; model view may be shorter."})
        log(conn, "incident_linked", incident_id, None, {"case_id": case_id, "reason": reason, "policy": POLICY})
    return case_id


def priority(events, asset, changes):
    level = max((e["rule_level"] for e in events), default=0)
    base = 40 if level <= 0 else 85 if level >= 12 else 65 if level >= 8 else 45 if level >= 5 else 20
    reasons = [f"Wazuh rule level {level}: baseline {base}/100; detection severity is not proof of compromise."]
    if level <= 0:
        reasons[0] = "Usable rule severity is unavailable: review baseline 40/100."
    uplift = {"critical": 20, "high": 10, "medium": 5}.get(asset.get("criticality"), 0)
    reasons.append(f"Asset criticality: {asset.get('criticality', 'unassessed')} (+{uplift}).")
    sensitive = 10 if asset.get("sensitivity") == "restricted" else 5 if asset.get("sensitivity") == "confidential" else 0
    reasons.append(f"Data sensitivity: {asset.get('sensitivity', 'unassessed')} (+{sensitive}).")
    score = min(100, base+uplift+sensitive)
    matches = []
    for change in changes:
        if change["status"] != "approved":
            continue
        for e in events:
            stamp = epoch(e.get("event_time")) if e["time_basis"] == "source_event" else None
            if (stamp is not None and epoch(change["start"]) <= stamp <= epoch(change["end"])
                and epoch(change["approved_at"]) <= stamp and e["rule_id"] == change["rule_id"]
                and e["source_ip"] == change["source_ip"] and e["account"] == change["account"]):
                matches.append({"change_id": change["id"], "incident_id": e["incident_id"], "ticket": change["ticket"]})
    if matches:
        reasons.append("Approved change matches exact asset, rule, source, account and event window. Context only: priority is unchanged and human review remains required.")
    else:
        reasons.append("No exact approved-change match for the available source events.")
    return dict(score=score, band="Critical" if score >= 85 else "High" if score >= 65 else "Medium" if score >= 40 else "Low", reasons=reasons, change_matches=matches, policy=POLICY, calculated_at=now(), basis="Current operator-entered asset profile; rule severity retained. Not a probability or automatic response decision.")


def _case(conn, case_id, detail=False):
    rows = conn.execute("SELECT * FROM events WHERE case_id=? ORDER BY event_epoch IS NULL,event_epoch,received_at,id", (case_id,)).fetchall()
    if not rows:
        return None
    events = [json.loads(r["payload"]) for r in rows]
    asset_row = conn.execute("SELECT payload FROM assets WHERE id=?", (rows[0]["asset_key"],)).fetchone()
    asset = json.loads(asset_row[0]) if asset_row else dict(id=rows[0]["asset_key"], name="Unresolved asset", owner="", service="", criticality="unassessed", sensitivity="unassessed", revision=0)
    changes = [json.loads(x[0]) for x in conn.execute("SELECT payload FROM changes WHERE asset_id=?", (asset["id"],))]
    p = priority(events, asset, changes)
    result = dict(id=case_id, title=events[-1]["rule_name"], asset=asset, priority=p, count=len(events),
                  first_time=events[0]["event_time"], last_time=events[-1]["event_time"],
                  legacy=all(r["legacy"] for r in rows), source_ip=events[-1]["source_ip"], account=events[-1]["account"])
    if detail:
        for event, row in zip(events, rows):
            evidence = conn.execute("SELECT ref,payload,sha256 FROM evidence WHERE incident_id=?", (event["incident_id"],)).fetchall()
            refs = {e["ref"]:json.loads(e["payload"]) for e in evidence}
            event["join_reason"] = row["join_reason"]
            event["evidence"] = [{"ref":e["ref"], "sha256":e["sha256"], "source":refs[e["ref"]].get("source"), "status":refs[e["ref"]].get("status")} for e in evidence]
            for finding in event["findings"]:
                cited = finding.get("evidence", [])
                finding["citation_status"] = "available_for_review" if cited and all(ref in refs and refs[ref].get("status") not in {"error", "blocked", "budget_exhausted"} for ref in cited) else "missing_or_failed_evidence"
        result["events"] = events
        result["changes"] = changes
        result["relationships"] = dict(asset=asset["name"], source=events[-1]["source_ip"], account=events[-1]["account"], incidents=[e["incident_id"] for e in events], meaning="Observed associations, not proof of a shared attacker or compromise.")
    return result


def case_detail(case_id):
    with db() as conn:
        return _case(conn, case_id, True)


def list_cases(q="", band="", offset=0, limit=30):
    with db() as conn:
        records = [_case(conn, r[0]) for r in conn.execute("SELECT id FROM cases")]
        totals = {"cases": len(records), "events": sum(x["count"] for x in records), "correlated": sum(x["count"] > 1 for x in records), "unassessed_assets": conn.execute("SELECT COUNT(*) FROM assets WHERE json_extract(payload,'$.criticality')='unassessed'").fetchone()[0]}
        if q:
            ids = {r[0] for r in conn.execute("SELECT case_id FROM events WHERE instr(lower(id),?)>0", (q.lower(),))}
            records = [x for x in records if q.lower() in " ".join([x["id"], x["title"], x["asset"]["name"], x["source_ip"], x["account"]]).lower() or x["id"] in ids]
        if band:
            records = [x for x in records if x["priority"]["band"] == band]
        records.sort(key=lambda x:(x["priority"]["score"], epoch(x["last_time"], legacy=True) or 0, x["id"]), reverse=True)
        return dict(items=records[offset:offset+limit], total=len(records), offset=offset, limit=limit, summary=totals)


def get_evidence(incident_id, ref):
    with db() as conn:
        row = conn.execute("SELECT * FROM evidence WHERE incident_id=? AND ref=?", (incident_id, ref)).fetchone()
        if not row:
            return None
        return dict(incident_id=incident_id, ref=ref, sha256=row["sha256"], integrity_ok=sha256(row["payload"].encode()).hexdigest()==row["sha256"], record=json.loads(row["payload"]))


def profiles():
    with db() as conn:
        return dict(assets=[json.loads(r[0]) for r in conn.execute("SELECT payload FROM assets ORDER BY id")], changes=[json.loads(r[0]) for r in conn.execute("SELECT payload FROM changes ORDER BY id")])


def save_asset(asset_id, payload):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        if not row:
            raise KeyError("Asset not found")
        if payload["revision"] != row["revision"]:
            raise ValueError("Asset changed since it was loaded. Refresh before saving.")
        before = json.loads(row["payload"])
        after = {**before, **payload, "revision": row["revision"]+1, "updated_at": now(), "updated_by": "shared_workspace_token"}
        conn.execute("UPDATE assets SET payload=?,revision=? WHERE id=?", (encode(after), after["revision"], asset_id))
        log(conn, "asset_updated", asset_id, before, after)
        return after


def save_change(payload):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if not conn.execute("SELECT 1 FROM assets WHERE id=?", (payload["asset_id"],)).fetchone():
            raise KeyError("Asset not found")
        row = conn.execute("SELECT * FROM changes WHERE id=?", (payload["id"],)).fetchone()
        before = json.loads(row["payload"]) if row else None
        revision = row["revision"] if row else 0
        if payload["revision"] != revision:
            raise ValueError("Change record was updated. Refresh before saving.")
        after = {**payload, "revision": revision+1, "recorded_at": now(), "recorded_by": "shared_workspace_token"}
        conn.execute("INSERT INTO changes VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET asset_id=excluded.asset_id,payload=excluded.payload,revision=excluded.revision", (after["id"], after["asset_id"], encode(after), after["revision"]))
        log(conn, "change_recorded", after["id"], before, after)
        return after


def audit_page(offset=0, limit=40):
    with db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        return dict(total=total, items=[dict(r) for r in conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))])

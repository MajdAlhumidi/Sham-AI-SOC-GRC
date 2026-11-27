import os
import json
import re
import requests
import urllib3

# إعدادات الاتصال بـ TheHive (يمكن تمريرها عبر متغيرات البيئة)
THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000").rstrip("/")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")
THEHIVE_VERIFY_TLS = os.getenv("THEHIVE_VERIFY_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}
THEHIVE_API_VERSION = os.getenv("THEHIVE_API_VERSION", "v4").strip().lower()

if not THEHIVE_VERIFY_TLS:
    # Only silence certificate warnings when a lab explicitly disables verification.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _thehive_api_url(resource: str) -> str:
    """Build a version-correct TheHive API URL from a base host URL."""
    api_prefix = "/api/v1" if THEHIVE_API_VERSION in {"v5", "5", "5.x"} else "/api"
    return "{}/{}".format(THEHIVE_URL + api_prefix, str(resource).lstrip("/"))

# خريطة تحويل مستويات الخطورة إلى أرقام TheHive (1: Low, 2: Medium, 3: High, 4: Critical)
SEVERITY_MAP = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

def create_thehive_incident_case(
    title: str,
    severity: str,
    description: str,
    mitre_tags: list = None,
    observables: list = None,
    tasks: list = None,
    *,
    incident_id: str = "",
    approval_id: str = "",
) -> str:
    """Send a case once, using a distinct-actor approval for this incident."""
    if not THEHIVE_API_KEY:
        return json.dumps({"status": "not_configured", "message": "TheHive API key is missing."})
    if not incident_id or not approval_id:
        return json.dumps({"status": "not_attempted", "message": "An authenticated approval for this incident is required."})
    db_session, initialize_database, utc_now = _grc_database()
    initialize_database()
    with db_session() as connection:
        connection.execute("BEGIN IMMEDIATE")
        approval = connection.execute(
            """SELECT requested_actor_id, decided_actor_id FROM approvals
               WHERE id=? AND reference_type='incident' AND reference_id=?
                 AND requested_action='thehive.create_case' AND status='approved'""",
            (approval_id, incident_id),
        ).fetchone()
        if (approval is None or any(not actor or actor.startswith("local-demo:") for actor in approval)
                or approval[0] == approval[1]):
            return json.dumps({"status": "not_attempted", "message": "No qualifying approval covers this incident."})
        existing = connection.execute(
            "SELECT result_json FROM thehive_deliveries WHERE incident_id=?", (incident_id,),
        ).fetchone()
        if existing:
            return existing[0] or json.dumps({
                "status": "pending_confirmation",
                "message": "A previous send must be reconciled before retrying.",
            })
        connection.execute(
            "INSERT INTO thehive_deliveries (incident_id, approval_id, started_at) VALUES (?, ?, ?)",
            (incident_id, approval_id, utc_now()),
        )
    result = _send_case(title, severity, description, mitre_tags, observables, tasks)
    with db_session() as connection:
        connection.execute("UPDATE thehive_deliveries SET result_json=? WHERE incident_id=?", (result, incident_id))
    return result


def _grc_database():
    if __package__:
        from .grc.db import db_session, initialize_database, utc_now
    else:
        from grc.db import db_session, initialize_database, utc_now
    return db_session, initialize_database, utc_now


def _send_case(title, severity, description, mitre_tags, observables, tasks):
    severity_level = SEVERITY_MAP.get(severity.lower(), 2)
    tags = ["AI-SOC-Agent", "Wazuh-RAMv2"]
    if mitre_tags:
        tags.extend(mitre_tags)

    case_payload = {
        "title": title,
        "description": description,
        "severity": severity_level,
        "tags": tags,
        "flag": severity.lower() in ["high", "critical"],
        "tlp": 2, # TLP:AMBER
        "pap": 2
    }

    # الاتصال الفعلي بـ TheHive API (v4 / v5)
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        # 1. إنشاء الـ Case
        endpoint = _thehive_api_url("case")
        res = requests.post(endpoint, headers=headers, json=case_payload, verify=THEHIVE_VERIFY_TLS, timeout=10, allow_redirects=False)

        if res.status_code not in [200, 201]:
            return json.dumps({"status": "error", "message": f"TheHive returned HTTP {res.status_code}."})

        case_data = res.json()
        case_id = case_data.get("_id") or case_data.get("id")
        if not isinstance(case_id, str) or not re.fullmatch(r"[~A-Za-z0-9_-]{1,160}", case_id):
            return json.dumps({
                "status": "error",
                "message": "TheHive returned a successful response without a case identifier; creation could not be verified.",
            })

        followup_errors = []
        observables_created = 0
        tasks_created = 0

        # 2. إضافة الـ Observables إن وجدت; capture failures instead of silently claiming success.
        if observables:
            obs_url = _thehive_api_url("case/{}/observable".format(case_id))
            for obs in observables:
                value = obs.get("value")
                obs_payload = {
                    "dataType": obs.get("type", "other"),
                    "data": [value] if THEHIVE_API_VERSION in {"v5", "5", "5.x"} else value,
                    "message": obs.get("description", "Extracted by SOC Agent"),
                    "tlp": 2,
                }
                try:
                    child_res = requests.post(obs_url, headers=headers, json=obs_payload, verify=THEHIVE_VERIFY_TLS, timeout=10, allow_redirects=False)
                    if child_res.status_code in [200, 201, 204]:
                        observables_created += 1
                    else:
                        followup_errors.append({
                            "resource": "observable",
                            "status_code": child_res.status_code,
                        })
                except Exception as child_exc:
                    followup_errors.append({"resource": "observable", "message": type(child_exc).__name__})

        # 3. إنشاء مهام المتابعة (Tasks)
        if tasks:
            task_url = _thehive_api_url("case/{}/task".format(case_id))
            for task_title in tasks:
                try:
                    child_res = requests.post(task_url, headers=headers, json={"title": task_title}, verify=THEHIVE_VERIFY_TLS, timeout=10, allow_redirects=False)
                    if child_res.status_code in [200, 201, 204]:
                        tasks_created += 1
                    else:
                        followup_errors.append({
                            "resource": "task",
                            "status_code": child_res.status_code,
                        })
                except Exception as child_exc:
                    followup_errors.append({"resource": "task", "message": type(child_exc).__name__})

        result = {
            "status": "partial" if followup_errors else "success",
            "case_id": case_id,
            "title": title,
            "observables_created": observables_created,
            "tasks_created": tasks_created,
            "message": "TheHive case created; {} observables and {} tasks confirmed.".format(observables_created, tasks_created),
        }
        if followup_errors:
            result["followup_errors"] = followup_errors
        return json.dumps(result)

    except Exception as e:
        return json.dumps({"status": "error", "message": f"TheHive result could not be confirmed ({type(e).__name__})."})

if __name__ == "__main__":
    import argparse

    if __package__:
        from .casework import store
        from .casework.export import redact_for_output
        from .report_quality import evaluate_report_quality
    else:
        from casework import store
        from casework.export import redact_for_output
        from report_quality import evaluate_report_quality

    parser = argparse.ArgumentParser(description="Submit a retained SHAM incident covered by a TheHive approval.")
    parser.add_argument("--incident-id", required=True)
    parser.add_argument("--approval-id", required=True)
    args = parser.parse_args()
    with store.db() as connection:
        retained = connection.execute("SELECT payload FROM events WHERE id=?", (args.incident_id,)).fetchone()
    if retained is None:
        parser.error("The incident is not retained in Casework.")
    record = json.loads(retained[0])
    report = record.get("report", "")
    if not evaluate_report_quality(report)[0]:
        parser.error("The retained report has not passed the report format gate.")
    severity = re.search(r"(?im)^\* \*\*Severity Level\*\*:\s*\**(critical|high|medium|low)\b", report)
    result = create_thehive_incident_case(
        title=f"SHAM investigation {args.incident_id}", severity=severity[1].lower() if severity else "medium",
        description=redact_for_output(report), incident_id=args.incident_id, approval_id=args.approval_id,
    )
    print(result)

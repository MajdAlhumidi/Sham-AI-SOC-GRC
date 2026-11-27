import os
import json
import requests
from urllib.parse import urlsplit

if __package__:
    from .indexer_tool import query_process_tree, query_network_activity, query_related_alerts
    from .thehive_tool import create_thehive_incident_case
    from .threat_intel import check_ip_reputation as get_ip_intel, check_file_hash as get_hash_intel
else:
    from vector_store import search_incidents as _script_search_incidents
    from indexer_tool import query_process_tree, query_network_activity, query_related_alerts
    from thehive_tool import create_thehive_incident_case
    from threat_intel import check_ip_reputation as get_ip_intel, check_file_hash as get_hash_intel


def search_incidents(*args, **kwargs):
    """Load embedding storage only for a history query, in either launch mode."""
    if __package__:
        from .vector_store import search_incidents as search
    else:
        search = _script_search_incidents
    return search(*args, **kwargs)

WAZUH_HOST = os.getenv("WAZUH_API_HOST", "https://127.0.0.1:55000")
WAZUH_USER = os.getenv("WAZUH_API_USER", "")
WAZUH_PASS = os.getenv("WAZUH_API_PASS", "")
WAZUH_API_VERIFY_TLS = os.getenv("WAZUH_API_VERIFY_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}


def validate_wazuh_api_config(*, production=False):
    lab_override = os.getenv("SOC_ALLOW_INSECURE_TLS_LAB", "false").strip().lower() == "true"
    if (production or not lab_override) and (not WAZUH_API_VERIFY_TLS or urlsplit(WAZUH_HOST).scheme != "https"):
        raise ValueError("The Wazuh API requires verified HTTPS. Use the explicit override only in a local lab.")
    if production and (not WAZUH_USER.strip() or not WAZUH_PASS.strip()):
        raise ValueError("WAZUH_API_USER and WAZUH_API_PASS are required when the Wazuh API integration is configured.")


def get_wazuh_token() -> str:
    """الحصول على JWT Token من Wazuh API للتوثيق."""
    validate_wazuh_api_config(production=os.getenv("SOC_API_AUTH_MODE") == "token")
    try:
        res = requests.post(
            f"{WAZUH_HOST}/security/user/authenticate",
            auth=(WAZUH_USER, WAZUH_PASS),
            verify=WAZUH_API_VERIFY_TLS,
            timeout=5, allow_redirects=False,
        )
        if res.status_code == 200:
            return res.json().get("data", {}).get("token", "")
        return ""
    except Exception:
        return ""


def search_related_agent_logs(agent_id: str, query: str, time_range_minutes: int = 60,
                              *, source_ip: str = "", location: str = "") -> str:
    """Search recent Wazuh alerts for the incoming agent, not file-integrity scan metadata."""
    try:
        return query_related_alerts(
            agent_id=str(agent_id),
            query_text=str(query or ""),
            time_range_minutes=int(time_range_minutes),
            size=10,
            source_ip=source_ip,
            location=location,
        )
    except Exception as exc:
        return json.dumps({
            "status": "error",
            "message": "Related-alert search failed ({}).".format(type(exc).__name__),
        }, ensure_ascii=False)


def check_ip_reputation(ip: str) -> str:
    """
    Check real threat intelligence databases (AbuseIPDB, VirusTotal)
    for suspicious IP reputation score, abuse history, and malicious activity.
    """
    try:
        intel_report = get_ip_intel(ip.strip())
        # إرفاق الملاحظة التشخيصية الفنية ليقرأها الوكيل
        intel_report["diagnostic_metadata"] = {
            "execution_status": "QUERY_FUNCTION_RETURNED",
            "diagnostic_note": "راجع نتائج كل مزود في التقرير؛ لا يتم افتراض رموز HTTP أو نجاح مزود غير ظاهر في الاستجابة."
        }
        return json.dumps(intel_report, ensure_ascii=False)
    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": f"Threat Intel query failed for IP {ip}: {str(e)}",
            "diagnostic_metadata": {
                "execution_status": "FAILED",
                "diagnostic_note": f"توقف الفحص بسبب خطأ برمجي أثناء التنفيذ: {str(e)}"
            }
        }, ensure_ascii=False)


def inspect_file_hash(file_hash: str) -> str:
    """
    Check VirusTotal v3 for file hash reputation (MD5, SHA1, SHA256) extracted from Wazuh FIM,
    Syscheck, or Sysmon process creation events.
    """
    try:
        hash_report = get_hash_intel(file_hash.strip())
        hash_report["diagnostic_metadata"] = {
            "execution_status": "QUERY_FUNCTION_RETURNED",
            "diagnostic_note": "لا يتم افتراض رمز HTTP أو نتيجة لم تُرجعها دالة مزود التهديدات."
        }
        return json.dumps(hash_report, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Threat Intel query failed for hash {file_hash}: {str(e)}"}, ensure_ascii=False)


def trigger_containment_action(agent_id: str, command: str) -> str:
    """Fail closed: this project has no verified active-response executor configured."""
    return json.dumps({
        "status": "not_executed",
        "action_status": "NOT_CONFIGURED",
        "executed": False,
        "action": command,
        "agent_id": agent_id,
        "message": (
            "No containment action was executed. Configure and verify a real "
            "Wazuh Active Response adapter before enabling automated containment."
        )
    })


def search_historical_incidents(query: str, n_results: int = 2, rule_name: str = None, exclude_source_alert_id: str = None) -> str:
    try:
        limit = max(1, min(int(n_results), 5))
        matches = {}
        for verified in (True, False):
            results = search_incidents(
                query_text=query, n_results=limit + 5, rule_name=rule_name,
                human_review_status="verified" if verified else None,
            ) or {}
            cases = []
            for incident_id, meta, distance in zip(
                (results.get("ids") or [[]])[0], (results.get("metadatas") or [[]])[0],
                (results.get("distances") or [[]])[0],
            ):
                meta = meta or {}
                status = meta.get("human_review_status", "unknown")
                if (status == "verified") != verified:
                    continue
                if exclude_source_alert_id and str(meta.get("source_alert_id") or "") == exclude_source_alert_id:
                    continue
                if rule_name and meta.get("rule_name") != rule_name:
                    continue
                cases.append({
                    "incident_id": incident_id,
                    "classification": meta.get("human_classification") if verified else meta.get("classification"),
                    "human_review_status": status,
                    "classification_source": meta.get("classification_source", "unknown"),
                    "rule_name": meta.get("rule_name"),
                    "similarity_distance": round(distance, 4),
                })
                if len(cases) >= limit:
                    break
            matches[verified] = cases
        return json.dumps({
            "status": "success" if any(matches.values()) else "empty",
            "match_basis": "same_rule_vector_search" if rule_name else "vector_search",
            "matches_count": len(matches[True]),
            "historical_cases": matches[True],
            "unreviewed_cases": matches[False],
            "interpretation_note": "Only authenticated human reviews contribute verified historical labels.",
        }, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Vector DB search failed ({type(e).__name__})."})


def inspect_process_tree(agent_id: str, time_range_minutes: int = 30) -> str:
    try:
        return query_process_tree(agent_id=str(agent_id), time_range_minutes=int(time_range_minutes))
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Process tree query failed: {str(e)}"})


def inspect_network_connections(agent_id: str, time_range_minutes: int = 30) -> str:
    try:
        return query_network_activity(agent_id=str(agent_id), time_range_minutes=int(time_range_minutes))
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Network activity query failed: {str(e)}"})


# Only read-only evidence tools are exposed to the autonomous model loop.
# Containment is not implemented; TheHive creation is orchestrated after investigation.
SOC_TOOLS_LIST = [
    search_historical_incidents,
    inspect_process_tree,
    inspect_network_connections,
    search_related_agent_logs,
    check_ip_reputation,
    inspect_file_hash,
]

AVAILABLE_TOOLS = {tool.__name__: tool for tool in SOC_TOOLS_LIST}


def execute_agent_tool(tool_name: str, tool_args: dict) -> str:
    if tool_name not in AVAILABLE_TOOLS:
        return json.dumps({"status": "error", "message": f"Tool '{tool_name}' is not recognized."})

    try:
        func = AVAILABLE_TOOLS[tool_name]
        return func(**tool_args)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Failed executing {tool_name}: {str(e)}"})

"""Resolve the observed asset without confusing a Syslog collector with a device."""
import ipaddress
import json
import re
from datetime import datetime


_PRIVATE = tuple(ipaddress.ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
_DOCUMENTATION = tuple(ipaddress.ip_network(net) for net in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20",
))
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _ip(value):
    try:
        return str(ipaddress.ip_address(str(value or '').strip()))
    except ValueError:
        return ''


def ip_scope(value):
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return "invalid"
    address = getattr(address, "ipv4_mapped", None) or address
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if any(address in network for network in _PRIVATE):
        return "private"
    if address in _CGNAT:
        return "carrier_grade_nat"
    if any(address in network for network in _DOCUMENTATION):
        return "documentation"
    if address.is_multicast:
        return "multicast"
    if address.is_reserved or address.is_unspecified or not address.is_global:
        return "reserved"
    return "public"


def external_lookup_note(value):
    scope = ip_scope(value)
    if scope != "public":
        address = _ip(value) or "unavailable"
        return f"External reputation lookup skipped for {address} ({scope})."
    return ""


def network_appliance(alert):
    rule = alert.get("rule") or {}
    decoder = str((alert.get("decoder") or {}).get("name") or "").lower()
    return "mikrotik" in decoder or any("mikrotik" in str(group).lower() for group in rule.get("groups") or [])


def collector_type(alert):
    agent_id = str((alert.get("agent") or {}).get("id") or "")
    if (agent_id == "000" and _ip(alert.get("location"))) or (agent_id != "000" and network_appliance(alert)):
        return "remote_syslog"
    if agent_id == "000":
        return "wazuh_manager"
    return "host_agent" if agent_id else "unknown"


def resolve_alert_asset(alert):
    agent = alert.get('agent') or {}
    data = alert.get('data') or {}
    location_ip = _ip(alert.get('location'))
    # Agent 000 is the manager receiving remote Syslog, not an endpoint agent
    # installed on the router. Never use the login source as the target asset.
    if str(agent.get("id", "")) == "000" and location_ip:
        name = ''
        if network_appliance(alert):
            match = re.match(
                r'^[A-Za-z]+(?:,[A-Za-z]+)*\s+([A-Za-z0-9_.-]{1,128}):\s',
                str(alert.get('full_log') or ''),
            )
            if match:
                name = match.group(1)
        if not name:
            name = str((alert.get('predecoder') or {}).get('hostname') or location_ip or 'Unresolved syslog device')
        return {'name': name, 'ip': location_ip or 'N/A', 'source': 'remote_syslog'}
    return {
        'name': str(agent.get('name') or agent.get('ip') or data.get('dstip') or 'Unknown Host'),
        'ip': _ip(data.get('dstip')) or _ip(agent.get('ip')) or 'N/A',
        'source': 'endpoint_agent',
    }


def incident_target_host(metadata):
    """New records carry an asset name; older metadata remains readable."""
    return metadata.get('target_host') or (
        metadata.get('destination_ip') if metadata.get('destination_ip') not in (None, '', 'N/A') else 'local-agent'
    )


def rule_mitre_ids(rule):
    mitre = rule.get('mitre') or {}
    ids = mitre.get('id', []) if isinstance(mitre, dict) else []
    ids = ids if isinstance(ids, list) else [ids]
    return list(dict.fromkeys(
        x for x in ids if isinstance(x, str) and re.fullmatch(r'T\d{4}(?:\.\d{3})?', x)
    ))[:32]


def rule_mappings(rule):
    def tags(value):
        items = value if isinstance(value, list) else [value]
        return list(dict.fromkeys(
            item.strip() for item in items if isinstance(item, str)
            and re.fullmatch(r"[A-Za-z0-9_.:() -]{1,100}", item) and item.strip()
        ))[:32]

    return {
        "mitre": rule_mitre_ids(rule),
        "pci_dss": tags(rule.get("pci_dss")),
        "groups": tags(rule.get("groups")),
        "compliance": {key: tags(rule[key]) for key in ("gdpr", "hipaa", "nist_800_53", "tsc") if key in rule},
    }


def untrusted_data(value, label="ALERT"):
    content = json.dumps(value, ensure_ascii=True, default=str).replace("<", r"\u003c").replace(">", r"\u003e")
    return f"<UNTRUSTED_{label}_DATA>\n{content}\n</UNTRUSTED_{label}_DATA>"


def _stamp(value):
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return stamp.timestamp() if stamp.tzinfo else None
    except ValueError:
        return None


def calibrate_severity(alert, context=None):
    rule = alert.get("rule") or {}
    data = alert.get("data") or {}
    source = _ip(data.get("srcip") or data.get("src_ip"))
    current = _stamp(alert.get("timestamp"))
    try:
        level = int(rule.get("level") or 0)
    except (ValueError, TypeError):
        level = 0
    context = context or {}
    asset = context.get("asset_criticality", "unassessed")
    description = str(rule.get("description") or "").lower()
    failed_login = bool(re.search(r"login fail|auth(?:entication)? fail|failed (?:login|auth)|invalid (?:user|password)", description))
    related = set()
    corroborated = False
    anomalies = False
    for tool in context.get("tool_results", []):
        if tool.get("status") not in {"success", "partial", "returned"}:
            continue
        try:
            result = json.loads(tool["result"])
        except (KeyError, TypeError, ValueError):
            continue
        if not isinstance(result, dict):
            continue
        if tool.get("tool_name") == "check_ip_reputation":
            corroborated |= bool(source and ip_scope(source) == "public" and _ip(result.get("ip")) == source
                                  and result.get("classification") == "MALICIOUS_HOST")
        elif tool.get("tool_name") == "search_related_agent_logs" and source and current is not None:
            for event in result.get("alerts", []):
                seen = _stamp(event.get("timestamp"))
                if seen is None or abs(seen - current) > 1800 or _ip(event.get("source_ip")) != source:
                    continue
                if str(event.get("rule_id")) == str(rule.get("id")):
                    evidence_id = str(event.get("id") or "")
                    if (evidence_id and evidence_id != str(alert.get("id"))) or (not evidence_id and seen != current):
                        related.add(evidence_id or seen)
                elif "success" in str(event.get("rule_description") or "").lower():
                    anomalies = True
    if corroborated:
        return "HIGH", "The observed public source has corroborating reputation evidence."
    if failed_login and len(related) >= 4:
        return "HIGH", f"{len(related) + 1} related failures were observed within the 30-minute case window."
    if failed_login and not related and not anomalies and ip_scope(source) in {"private", "loopback", "link_local", "carrier_grade_nat"}:
        return ("LOW" if level < 7 and asset not in {"critical", "high"} else "MEDIUM",
                "One internal authentication failure was observed without corroborating activity.")
    score = level + {"critical": 2, "high": 1}.get(asset, 0) + int(bool(related or anomalies))
    band = "CRITICAL" if score >= 12 else "HIGH" if score >= 8 else "MEDIUM" if score >= 4 else "LOW"
    return band, f"Wazuh level {level}, asset criticality {asset}, and {len(related)} related same-rule events."

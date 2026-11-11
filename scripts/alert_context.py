"""Resolve the observed asset without confusing a Syslog collector with a device."""
import ipaddress
import re


def _ip(value):
    try:
        return str(ipaddress.ip_address(str(value or '').strip()))
    except ValueError:
        return ''


def resolve_alert_asset(alert):
    agent = alert.get('agent') or {}
    data = alert.get('data') or {}
    location_ip = _ip(alert.get('location'))
    # Agent 000 is the manager receiving remote Syslog, not an endpoint agent
    # installed on the router. Never use the login source as the target asset.
    if str(agent.get('id', '')) == '000' and location_ip:
        rule = alert.get('rule') or {}
        decoder = str((alert.get('decoder') or {}).get('name', '')).lower()
        groups = rule.get('groups') or []
        mikrotik = 'mikrotik' in decoder or 'mikrotik' in groups
        name = ''
        if mikrotik:
            match = re.match(
                r'^[A-Za-z]+(?:,[A-Za-z]+)*\s+([A-Za-z0-9_.-]{1,128}):\s',
                str(alert.get('full_log') or ''),
            )
            if match:
                name = match.group(1)
        if not name:
            name = str((alert.get('predecoder') or {}).get('hostname') or location_ip)
        return {'name': name, 'ip': location_ip, 'source': 'remote_syslog'}
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

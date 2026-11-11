"""Validated Ollama assessments rendered with runtime-owned evidence and status."""
from __future__ import annotations

import json
import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field
if __package__:
    from .alert_context import resolve_alert_asset, rule_mitre_ids
else:
    from alert_context import resolve_alert_asset, rule_mitre_ids

Text = Annotated[str, Field(min_length=15, max_length=1000)]
EvidenceRefs = Annotated[list[str], Field(min_length=1, max_length=4)]


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    observation: Text
    evidence: EvidenceRefs


class Technique(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    technique_id: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")
    rationale: Text
    evidence: EvidenceRefs


class Assessment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    classification: Literal["TRUE POSITIVE", "FALSE POSITIVE", "SUSPICIOUS", "BENIGN"]
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assessment: Text
    findings: list[Finding] = Field(min_length=1, max_length=5)
    # A free-text hypothesis cannot be verified from a citation alone. Require
    # an empty list; keep uncertainty in evidence limitations and next steps.
    hypotheses: list[Text] = Field(max_length=0)
    mitre: list[Technique] = Field(max_length=3)
    limitations: list[Text] = Field(min_length=1, max_length=5)
    recommendations: list[Text] = Field(min_length=2, max_length=5)


def compact_evidence(value, depth=0):
    """Bound context growth while making omissions explicit to the model."""
    if depth > 6:
        return "[nested evidence omitted]"
    if isinstance(value, dict):
        out = {str(k): compact_evidence(v, depth + 1) for k, v in list(value.items())[:25]}
        if len(value) > 25:
            out["_omitted_fields"] = len(value) - 25
        return out
    if isinstance(value, list):
        out = [compact_evidence(v, depth + 1) for v in value[:3]]
        if len(value) > 3:
            out.append({"_omitted_items": len(value) - 3})
        return out
    if isinstance(value, str) and len(value) > 1000:
        return value[:1000] + " [text truncated]"
    return value


def evidence_packet(alert, context):
    # Preserve identifiers and observed activity while bounding large alert envelopes.
    source = {k: alert[k] for k in ("id", "timestamp", "agent", "rule", "data", "full_log", "location", "decoder", "predecoder") if k in alert}
    source = compact_evidence(source)
    # Preserve rule mappings as structured evidence even when the original
    # rule includes many compliance tags or a very large description.
    rule = alert.get('rule') or {}
    source['rule'] = {
        'id': str(rule.get('id', ''))[:128],
        'level': rule.get('level', 0),
        'description': str(rule.get('description', ''))[:600],
        'mitre': {'id': rule_mitre_ids(rule)},
    }
    source['affected_asset'] = resolve_alert_asset(alert)
    for key, value in list(source.items()):
        encoded = json.dumps(value, ensure_ascii=False, default=str)
        if len(encoded) > 1200 and key != 'rule':
            source[key] = {"excerpt": encoded[:1200], "truncated": True}
    packet = {"A1": {"kind": "incoming_alert", "value": source}}
    for index, item in enumerate(context.get("tool_results", []), 1):
        try:
            value = compact_evidence(json.loads(item["result"]))
        except (ValueError, TypeError):
            value = compact_evidence(str(item.get("result", "")))
        encoded = json.dumps(value, ensure_ascii=False, default=str)
        if len(encoded) > 900:
            value = {"excerpt": encoded[:900], "truncated": True}
        packet[f"T{index}"] = {"kind": "tool_result", "tool": item["tool_name"],
                              "status": item["status"], "value": value}
    return packet


def supplied_techniques(packet):
    """Only structured rule mappings can authorize a technique ID in the report."""
    found = {}
    def visit(value, ref):
        if isinstance(value, dict):
            rule = value.get("rule")
            if isinstance(rule, dict) and isinstance(rule.get("mitre"), dict):
                ids = rule["mitre"].get("id", [])
                for technique in ids if isinstance(ids, list) else [ids]:
                    if isinstance(technique, str) and re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
                        found.setdefault(technique, set()).add(ref)
            for child in value.values():
                visit(child, ref)
        elif isinstance(value, list):
            for child in value:
                visit(child, ref)
    for ref, item in packet.items():
        if item.get("status") not in {"blocked", "error", "budget_exhausted"}:
            visit(item.get("value"), ref)
    return found


def assessment_schema(packet):
    schema = Assessment.model_json_schema()
    for name in ["Finding", "Technique"]:
        schema["$defs"][name]["properties"]["evidence"]["items"] = {"type": "string", "enum": list(packet)}
    techniques = supplied_techniques(packet)
    if techniques:
        schema["$defs"]["Technique"]["properties"]["technique_id"]["enum"] = sorted(techniques)
    else:
        schema["properties"]["mitre"]["maxItems"] = 0
    return schema


def validate_assessment(content, packet):
    assessment = Assessment.model_validate_json(content)
    for entry in [*assessment.findings, *assessment.mitre]:
        unknown = set(entry.evidence) - set(packet)
        if unknown:
            raise ValueError("Assessment cited evidence that was not supplied: " + ", ".join(sorted(unknown)))
        if all(packet[ref].get("status") in {"blocked", "error", "budget_exhausted"} for ref in entry.evidence):
            raise ValueError("A failed or blocked tool is a limitation, not affirmative evidence for a finding")
    techniques = supplied_techniques(packet)
    for entry in assessment.mitre:
        if not set(entry.evidence) & techniques.get(entry.technique_id, set()):
            raise ValueError("MITRE mapping was not present in the cited structured rule evidence; use an empty mitre list")
    placeholder = re.compile(r"^(?:n/?a|unknown|none|todo|tbd|not available|insufficient information)[.! ]*$", re.I)
    for text in [assessment.assessment, *[x.observation for x in assessment.findings], *assessment.recommendations]:
        if placeholder.fullmatch(text.strip()):
            raise ValueError("Assessment contains placeholder content rather than an evidence-based analysis")
    return assessment


def _line(value):
    # Untrusted evidence must not inject new report headings or verdict lines.
    return " ".join(str(value).split()).replace("`", "'")


def render_assessment(assessment, alert, context, packet):
    rule, agent, data = alert.get("rule") or {}, alert.get("agent") or {}, alert.get("data") or {}
    asset = resolve_alert_asset(alert)
    findings = [f"- {_line(x.observation)} [{', '.join(x.evidence)}]" for x in assessment.findings]
    # Rule mappings are observed metadata. They must not disappear when the
    # model chooses an empty MITRE list, nor become a claim of compromise.
    techniques = [
        f"- **{technique}** (rule-supplied mapping) [{', '.join(sorted(refs))}]. "
        "Wazuh supplied this detection mapping; it does not confirm an attack or compromise."
        for technique, refs in sorted(supplied_techniques(packet).items())
    ]
    history = [f"- [{ref}] `{item['tool']}`: {item['status']}. Historical labels are context, not verified ground truth."
               for ref, item in packet.items() if item.get("tool") == "search_historical_incidents"]
    intel = [f"- [{ref}] `{item['tool']}`: {item['status']}. Provider details are in the recorded tool response."
             for ref, item in packet.items() if item.get("tool") in {"check_ip_reputation", "inspect_file_hash"}]
    diagnostics = []
    for ref, item in packet.items():
        if ref == "A1":
            continue
        excerpt = _line(json.dumps(item["value"], ensure_ascii=False, default=str))
        diagnostics.append(f"- [{ref}] `{item['tool']}` — runtime status: **{item['status']}**. Response excerpt: {excerpt}")
    if not diagnostics:
        diagnostics.append("- No investigation tool was executed. This report is initial triage based on the incoming alert only.")
    diagnostics.extend(f"- Audit limitation: {_line(w)}" for w in context.get("audit_warnings", []))
    lines = [
        "# Incident Investigation Report", "", "### 1. Incident Classification & Severity Level",
        f"* **Classification**: **{assessment.classification}**",
        f"* **Severity Level**: **{assessment.severity}**",
        f"* **Alert Description**: {_line(rule.get('description', 'Security Alert'))}",
        f"* **Affected Host**: `{_line(asset['name'])}`",
        f"* **Target Address**: `{_line(asset['ip'])}`",
        f"* **User Context**: `{_line(data.get('dstuser') or data.get('srcuser') or data.get('user') or 'N/A')}`",
        f"* **Source Address**: `{_line(data.get('srcip') or data.get('src_ip') or 'N/A')}`",
        f"* **Assessment**: {_line(assessment.assessment)}", "",
        "### 2. Analysis & Technical Findings", *findings, "",
        "**Threat intelligence**", *(intel or ["- Not checked: no reputation/hash tool call was recorded."]), "",
        "### 3. MITRE ATT&CK Mapping", *(techniques or ["- No structured rule mapping was supplied; no MITRE technique is asserted."]), "",
        "### 4. Historical Memory Context (Vector DB)",
        *(history or ["- Not checked: historical memory was not queried; no historical match is claimed."]), "",
        "### 5. Containment & Remediation Status",
        "1. **Host Isolation**: NOT_EXECUTED. Investigation tools are read-only.",
        "2. **External Case Creation**: Not attempted by the model; the orchestrator records any subsequent action separately.", "",
        "### 6. Recommended Next Steps for Human Analysts",
        *[f"{i}. {_line(x)}" for i, x in enumerate(assessment.recommendations, 1)], "",
        "### 7. Diagnostic & Audit Notes",
        "- [A1] Incoming alert is observed evidence, not proof of compromise.",
        *diagnostics, "", "**Evidence limitations**", *[f"- {_line(x)}" for x in assessment.limitations],
        "- Report structure and evidence references were validated; factual conclusions still require analyst review.",
    ]
    return "\n".join(lines) + "\n"

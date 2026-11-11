"""Render retrieved incident identities independently of model availability."""
import json
import math
import re


def compact_history(result):
    """Keep identifiers intact instead of truncating JSON after a long report."""
    if not isinstance(result, dict):
        return {'status': 'error', 'historical_cases': []}
    cases = []
    for item in (result.get('historical_cases') or [])[:5]:
        if not isinstance(item, dict) or not item.get('incident_id'):
            continue
        case = {key: str(item.get(key) or 'unknown')[:160] for key in
                ('incident_id', 'classification', 'human_review_status', 'classification_source')}
        case['rule_name'] = str(item.get('rule_name') or '')[:600]
        distance = item.get('similarity_distance')
        if isinstance(distance, (int, float)) and math.isfinite(distance):
            case['similarity_distance'] = round(distance, 4)
        cases.append(case)
    return {'status': result.get('status', 'error'), 'match_basis': result.get('match_basis', ''),
            'matches_count': len(cases), 'historical_cases': cases}


def _line(value):
    return ' '.join(str(value).split()).replace('`', "'")


def render_historical_memory(context):
    attempts = [(i, x) for i, x in enumerate((context or {}).get('tool_results', []), 1)
                if x.get('tool_name') == 'search_historical_incidents']
    if not attempts:
        return '- **Search**: Not checked; historical memory was not queried. No historical match is asserted.'
    lines = []
    for index, attempt in attempts:
        ref = f'[T{index}]'
        try:
            result = compact_history(json.loads(attempt.get('result', '')))
        except (ValueError, TypeError):
            result = {'status': 'error', 'historical_cases': []}
        if attempt.get('status') in {'error', 'blocked', 'budget_exhausted'} or result['status'] not in {'success', 'empty', 'no_match'}:
            lines.append(f'- **Search**: Unavailable or failed; no historical match is asserted. {ref}')
            continue
        cases = result['historical_cases']
        if not cases:
            lines.append(f'- **Match**: No eligible historical incidents were returned by the vector search. {ref}')
            continue
        ids = ', '.join('`'+_line(x['incident_id'])+'`' for x in cases)
        rules = list(dict.fromkeys(_line(x['rule_name']) for x in cases if x['rule_name']))
        lines.append(f'- **Match**: {ids}. {ref}')
        basis = 'within the same Wazuh rule' if result.get('match_basis') == 'same_rule_vector_search' else 'across stored incidents'
        lines.append(f'- **Search**: Local ChromaDB vector retrieval {basis}; no running Ollama model is required. {ref}')
        if rules:
            lines.append('- **Historical Pattern**: Retrieved rule descriptions: '+ '; '.join('`'+x+'`' for x in rules)+'.')
        for case in cases:
            distance = case.get('similarity_distance')
            distance_text = f'; vector distance: {distance:.4f} (lower is closer)' if distance is not None else ''
            lines.append(f"- `{_line(case['incident_id'])}` — stored classification: {_line(case['classification'])}; review status: {_line(case['human_review_status'])}{distance_text}.")
        lines.append('- **Interpretation**: Shared rules or text similarity do not establish unauthorized access, compromise, or a common actor. Stored classifications are historical context, not a verdict on this alert.')
    return '\n'.join(lines)


def replace_historical_section(report, context):
    replacement = '### 4. Historical Memory Context (Vector DB)\n'+render_historical_memory(context)+'\n\n'
    return re.sub(r'(?ms)^### 4\. Historical Memory Context \(Vector DB\)[^\n]*\n.*?(?=^### 5\.)',
                  lambda _: replacement, report)

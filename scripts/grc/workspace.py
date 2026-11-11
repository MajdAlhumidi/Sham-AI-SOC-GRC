"""Read-only, paginated projections for the protected GRC dashboard."""
import json
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from .db import db_session


def no_store(response: Response):
    response.headers['Cache-Control'] = 'no-store'


# Included under the existing GRC router, which requires X-GRC-Token.
router = APIRouter(prefix='/workspace', dependencies=[Depends(no_store)])
SECTIONS = {
    'risks': ('risks', 'status', ['id', 'title', 'description', 'category', 'asset', 'owner'], 'updated_at DESC, id'),
    'controls': ('controls', 'implementation_status', ['id', 'title', 'description', 'domain', 'framework', 'owner'], 'domain, id'),
    'evidence': ('evidence', 'source', ['id', 'description', 'reference_id', 'risk_id', 'control_id', 'metadata_json'], 'collected_at DESC, id'),
    'approvals': ('approvals', 'status', ['id', 'reference_id', 'requested_action', 'requested_by', 'decided_by', 'decision_note'], 'created_at DESC, id'),
    'audit': ('audit_logs', 'action', ['id', 'actor', 'action', 'entity_type', 'entity_id', 'reason', 'before_json', 'after_json'], 'created_at DESC, id'),
}


def definition(section):
    if section not in SECTIONS:
        raise HTTPException(404, 'GRC section not found')
    return SECTIONS[section]


def decode(row):
    item = dict(row)
    for field in ('metadata_json', 'before_json', 'after_json'):
        if field in item:
            raw = item.pop(field)
            try:
                item[field[:-5]] = json.loads(raw) if raw else None
            except (TypeError, ValueError):
                item[field[:-5]] = {'unavailable': 'Stored JSON could not be decoded'}
    return item


def incident_ids(value):
    found = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {'incident_id', 'reference_id', 'entity_id'} and isinstance(child, str) and re.fullmatch(r'INC-[A-Za-z0-9-]{1,124}', child):
                found.add(child)
            if key in {'metadata', 'before', 'after'}:
                found.update(incident_ids(child))
    return found


def related_incidents(connection, section, record):
    found = incident_ids(record)
    rows = []
    if section == 'risks':
        rows = connection.execute('SELECT * FROM evidence WHERE risk_id = ? OR control_id IN (SELECT control_id FROM risk_controls WHERE risk_id = ?)', (record['id'], record['id'])).fetchall()
    elif section == 'controls':
        rows = connection.execute('SELECT * FROM evidence WHERE control_id = ?', (record['id'],)).fetchall()
    elif section in {'approvals', 'audit'}:
        kind = record.get('reference_type') if section == 'approvals' else record.get('entity_type')
        reference = record.get('reference_id') if section == 'approvals' else record.get('entity_id')
        targets = {'risk': 'risks', 'control': 'controls', 'control_change': 'controls', 'evidence': 'evidence'}
        if section == 'audit':
            targets['approval'] = 'approvals'
        target = targets.get(kind)
        if target:
            linked = connection.execute(f'SELECT * FROM {target} WHERE id = ?', (reference,)).fetchone()
            if linked:
                found.update(related_incidents(connection, target, decode(linked)))
    for row in rows:
        found.update(incident_ids(decode(row)))
    return sorted(found, reverse=True)


@router.get('/summary')
def summary():
    with db_session() as connection:
        counts = {section: connection.execute(f'SELECT COUNT(*) FROM {spec[0]}').fetchone()[0] for section, spec in SECTIONS.items()}
        states = {row[0]: row[1] for row in connection.execute('SELECT implementation_status, COUNT(*) FROM controls GROUP BY implementation_status')}
        open_risks = connection.execute("SELECT COUNT(*) FROM risks WHERE status != 'closed'").fetchone()[0]
        pending = connection.execute("SELECT COUNT(*) FROM approvals WHERE status = 'pending'").fetchone()[0]
    applicable = sum(n for status, n in states.items() if status != 'not_applicable')
    implemented = states.get('implemented', 0)
    return {'counts': counts, 'open_risks': open_risks, 'pending_approvals': pending,
            'control_status_counts': states, 'applicable_controls': applicable, 'implemented_controls': implemented,
            'implementation_rate_percent': round(implemented / applicable * 100, 1) if applicable else 0,
            'notice': 'Internal control implementation indicator; not a compliance certification.'}


@router.get('/{section}')
def list_records(section: str, q: str = Query('', max_length=200), status: Optional[str] = Query(None, max_length=160),
                 offset: int = Query(0, ge=0), limit: int = Query(40, ge=1, le=100)):
    table, state_field, fields, order = definition(section)
    where, params = [], []
    if q.strip():
        # Treat user search as literal text, including SQL LIKE wildcard characters.
        pattern = '%' + q.strip().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        where.append('(' + ' OR '.join(f"COALESCE({field}, '') LIKE ? ESCAPE '\\'" for field in fields) + ')')
        params.extend([pattern] * len(fields))
    if status:
        where.append(f'{state_field} = ?')
        params.append(status)
    clause = ' WHERE ' + ' AND '.join(where) if where else ''
    with db_session() as connection:
        total = connection.execute(f'SELECT COUNT(*) FROM {table}{clause}', params).fetchone()[0]
        rows = connection.execute(f'SELECT * FROM {table}{clause} ORDER BY {order} LIMIT ? OFFSET ?', [*params, limit, offset]).fetchall()
        options = [row[0] for row in connection.execute(f'SELECT DISTINCT {state_field} FROM {table} ORDER BY {state_field}') if row[0]]
    return {'items': [decode(row) for row in rows], 'total': total, 'offset': offset, 'limit': limit, 'status_options': options}


@router.get('/{section}/{record_id}')
def record_detail(section: str, record_id: str, incident_offset: int = Query(0, ge=0), incident_limit: int = Query(12, ge=1, le=100)):
    table = definition(section)[0]
    with db_session() as connection:
        row = connection.execute(f'SELECT * FROM {table} WHERE id = ?', (record_id,)).fetchone()
        if row is None:
            raise HTTPException(404, 'GRC record not found')
        record = decode(row)
        ids = related_incidents(connection, section, record)
        linked_controls = [dict(x) for x in connection.execute('SELECT c.id, c.title FROM controls c JOIN risk_controls r ON r.control_id = c.id WHERE r.risk_id = ? ORDER BY c.id', (record_id,))] if section == 'risks' else []
    return {'record': record, 'linked_controls': linked_controls,
            'related_incidents': {'ids': ids[incident_offset:incident_offset + incident_limit], 'total': len(ids), 'offset': incident_offset, 'limit': incident_limit}}

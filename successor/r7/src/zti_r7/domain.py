"""R7 local messaging projection and effects, deliberately without an ACL.

Original contribution Mohammed Messaoudene, Apache-2.0; AI-assisted.
Only synthetic identities and append-only SQLite events are modeled. This is
not an email implementation, a permission oracle or a remote delivery claim.
"""
from __future__ import annotations

import copy
import json
import re
from collections.abc import Mapping

from ._provider.integration import BusinessRefusal, thaw

TABLE = 'mail_events'
COLUMNS = {
    'event_kind': 'TEXT', 'message_id': 'TEXT', 'message_version': 'INTEGER',
    'obligation_id': 'TEXT', 'occurrence_id': 'TEXT', 'operation_id': 'TEXT',
    'principal_id': 'TEXT', 'payload_json': 'TEXT',
}
ARGUMENT_FIELDS = frozenset({
    'obligation_id', 'kind', 'message_id', 'to', 'cc', 'bcc',
    'expected_message_version', 'expected_directory_version',
    'expected_to', 'expected_cc', 'expected_bcc', 'body', 'set_read', 'expected_read_change',
})
MODES = frozenset({'reply', 'reply_all', 'mark_read'})
FIELDS = ('to', 'cc', 'bcc')
SAFE = (1 << 53) - 1


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False)


def _identity(value):
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,96}', value) is not None


def _version(value):
    return type(value) is int and 1 <= value <= SAFE


def _ids(value, *, sorted_unique=False):
    if (type(value) is not list or len(value) > 16 or
            any(not _identity(item) for item in value) or len(set(value)) != len(value)):
        return False
    return not sorted_unique or value == sorted(value)


def validate_seed(seed):
    """Validate immutable setup data, not permissions or expected outcomes."""
    if type(seed) is not dict or set(seed) != {'self_id', 'messages', 'directory'}:
        raise ValueError('Closed messaging seed required')
    if not _identity(seed['self_id']) or type(seed['messages']) is not dict or not 1 <= len(seed['messages']) <= 16:
        raise ValueError('Invalid seed identities/messages')
    message_fields = {'thread_id', 'sender', 'to', 'cc', 'bcc', 'read', 'version'}
    for key, msg in seed['messages'].items():
        if (not _identity(key) or type(msg) is not dict or set(msg) != message_fields or
                not _identity(msg['thread_id']) or not _identity(msg['sender']) or
                any(not _ids(msg[field]) for field in FIELDS) or
                type(msg['read']) is not bool or not _version(msg['version'])):
            raise ValueError('Invalid seed message')
    directory = seed['directory']
    if (type(directory) is not dict or set(directory) != {'version', 'aliases', 'groups'} or
            not _version(directory['version'])):
        raise ValueError('Invalid seed directory')
    for name in ('aliases', 'groups'):
        entries = directory[name]
        if type(entries) is not dict or len(entries) > 16:
            raise ValueError('Invalid directory mapping')
        for key, values in entries.items():
            if (not _identity(key) or not _ids(values) or not values or
                    (name == 'aliases' and len(values) != 1)):
                raise ValueError('Aliases are one level and groups have explicit members')
    if set(directory['aliases']) & set(directory['groups']):
        raise ValueError('Ambiguous directory selector')
    known = {seed['self_id']}
    for msg in seed['messages'].values():
        known.add(msg['sender'])
        for field in FIELDS:
            known.update(msg[field])
    for entries in (directory['aliases'], directory['groups']):
        for values in entries.values():
            known.update(values)
    if known & (set(directory['aliases']) | set(directory['groups'])):
        raise ValueError('An identity cannot also be an alias/group selector')
    return copy.deepcopy(seed)


def validate_arguments(args):
    """Closed shape and bounded declared plan; no business-state ACL here."""
    if type(args) is not dict or set(args) != ARGUMENT_FIELDS:
        raise BusinessRefusal('UNSUPPORTED_TARGET')
    if (not _identity(args['obligation_id']) or not _identity(args['message_id']) or
            type(args['kind']) is not str or args['kind'] not in MODES or
            type(args['set_read']) is not bool or type(args['expected_read_change']) is not bool or
            not _version(args['expected_message_version']) or
            not _version(args['expected_directory_version'])):
        raise BusinessRefusal('UNSUPPORTED_TARGET')
    if any(not _ids(args[field]) or not _ids(args['expected_' + field], sorted_unique=True)
           for field in FIELDS):
        raise BusinessRefusal('UNSUPPORTED_TARGET')
    if type(args['body']) is not str:
        raise BusinessRefusal('UNSUPPORTED_TARGET')
    try:
        if len(args['body'].encode('utf-8')) > 4096:
            raise BusinessRefusal('UNSUPPORTED_TARGET')
    except UnicodeError as error:
        raise BusinessRefusal('UNSUPPORTED_TARGET') from error
    if args['kind'] == 'mark_read' and (args['body'] or not args['set_read'] or
            any(args[field] or args['expected_' + field] for field in FIELDS)):
        raise BusinessRefusal('UNSUPPORTED_TARGET')
    if args['kind'] == 'reply_all' and any(args[field] for field in FIELDS):
        raise BusinessRefusal('UNSUPPORTED_TARGET')


def footprint(args):
    """Declared bounds are deterministic; apply checks the complete real plan.

    The linked read-change bit is checked against current state before effects.
    A no-op still costs one accepted operation and is not useful work.
    """
    args = thaw(args)
    validate_arguments(args)
    recipients = sorted(set().union(*(set(args['expected_' + field]) for field in FIELDS)))
    facts = ['recipient:' + item for item in recipients]
    if args['expected_read_change']:
        facts.append('read:' + args['message_id'])
    amount = len(args['body'].encode('utf-8')) if args['kind'] != 'mark_read' else 0
    return ({'ops': {'unit': 'operation', 'amount': '1'},
             'bytes': {'unit': 'byte', 'amount': str(amount)}}, sorted(facts))


def _known(seed):
    known = {seed['self_id']}
    for msg in seed['messages'].values():
        known.add(msg['sender'])
        for field in FIELDS:
            known.update(msg[field])
    for entries in (seed['directory']['aliases'], seed['directory']['groups']):
        for members in entries.values():
            known.update(members)
    return known


def project(seed, rows):
    """Reconstruct current simulated state. Not an authorization checker."""
    state = validate_seed(seed)
    state.update(outbox=[], deliveries=[], known_ids=sorted(_known(seed)))
    previous = 0
    for row in rows:
        if set(row) != set(COLUMNS) | {'row_id'} or type(row['row_id']) is not int or row['row_id'] <= previous:
            raise RuntimeError('Malformed/unsorted business event history')
        previous = row['row_id']
        payload = json.loads(row['payload_json'])
        kind = row['event_kind']
        if kind == 'ENV_DIRECTORY':
            _apply_environment(state, payload)
        elif kind == 'ENV_MESSAGE_VERSION':
            _apply_environment(state, payload)
        elif kind == 'OUTBOX':
            message = state['messages'][row['message_id']]
            message['version'] = row['message_version']
            state['outbox'].append({**payload, 'obligation_id': row['obligation_id'],
                'operation_id': row['operation_id'], 'occurrence_id': row['occurrence_id'],
                'row_id': row['row_id']})
        elif kind == 'DELIVERY':
            state['deliveries'].append({**payload, 'operation_id': row['operation_id'],
                'obligation_id': row['obligation_id'], 'occurrence_id': row['occurrence_id'],
                'row_id': row['row_id']})
        elif kind == 'READ':
            message = state['messages'][row['message_id']]
            if payload != {'read': True}:
                raise RuntimeError('Unsupported read event')
            message['read'] = True
            message['version'] = row['message_version']
        else:
            raise RuntimeError('Unknown business event kind')
    return state


def _resolve(state, selectors):
    result = set()
    directory = state['directory']
    known = set(state['known_ids'])
    for selector in selectors:
        if selector in directory['aliases']:
            members = directory['aliases'][selector]
        elif selector in directory['groups']:
            members = directory['groups'][selector]
        elif selector in known:
            members = [selector]
        else:
            raise BusinessRefusal('UNSUPPORTED_TARGET')
        if any(member not in known for member in members):
            raise BusinessRefusal('UNSUPPORTED_TARGET')
        result.update(members)
    return sorted(result)


def plan(state, args):
    """Compute effects from current state; the caller must authorize them."""
    args = thaw(args)
    validate_arguments(args)
    if args['message_id'] not in state['messages']:
        raise BusinessRefusal('UNSUPPORTED_TARGET')
    msg = state['messages'][args['message_id']]
    if args['kind'] == 'mark_read':
        recipients = {field: [] for field in FIELDS}
    elif args['kind'] == 'reply_all':
        everyone = {msg['sender'], *msg['to'], *msg['cc']} - {state['self_id']}
        recipients = {'to': sorted(everyone), 'cc': [], 'bcc': []}
    else:
        recipients = {field: _resolve(state, args[field]) for field in FIELDS}
        if not args['to']:
            recipients['to'] = [msg['sender']]
    sets = [set(recipients[field]) for field in FIELDS]
    if any(sets[i] & sets[j] for i in range(3) for j in range(i + 1, 3)):
        raise BusinessRefusal('UNSUPPORTED_TARGET')
    if args['kind'] != 'mark_read' and not set.union(*sets):
        raise BusinessRefusal('UNSUPPORTED_TARGET')
    read_change = args['set_read'] and not msg['read']
    outbox = args['kind'] != 'mark_read'
    new_version = msg['version'] + int(outbox or read_change)
    if new_version > SAFE:
        raise BusinessRefusal('STALE_STATE')
    return {'message_id': args['message_id'], 'thread_id': msg['thread_id'],
            **recipients, 'body': args['body'], 'read_change': read_change,
            'set_read': args['set_read'], 'outbox': outbox,
            'new_message_version': new_version, 'kind': args['kind'],
            'obligation_id': args['obligation_id']}


def _base_row(args, context, full_plan, kind, occurrence, payload):
    return {'event_kind': kind, 'message_id': args['message_id'],
            'message_version': full_plan['new_message_version'],
            'obligation_id': args['obligation_id'], 'occurrence_id': occurrence,
            'operation_id': context.operation_id,
            'principal_id': getattr(context, 'principal_id', 'service.r7'),
            'payload_json': canonical(payload)}


def insert_plan(writer, context, args, full_plan):
    """Apply an already authorized full plan through the transaction owner.

    No obligation uniqueness check is intentional: repeated obligations under
    new operation IDs must remain observable for the independent oracle.
    """
    args = thaw(args)
    operation = context.operation_id
    outbox_id = operation + ':outbox'
    row_ids = []
    occurrences = []
    if full_plan['outbox']:
        payload = {name: full_plan[name] for name in ('thread_id', 'body', 'to', 'cc', 'bcc')}
        payload['source_message_id'] = args['message_id']
        row_ids.append(writer.insert(TABLE, _base_row(args, context, full_plan,
                                'OUTBOX', outbox_id, payload)))
        occurrences.append(outbox_id)
        for field in FIELDS:
            for index, recipient in enumerate(full_plan[field]):
                delivery_id = f'{operation}:delivery:{field}:{index}'
                payload = {'outbox_occurrence_id': outbox_id, 'field': field, 'recipient': recipient}
                row_ids.append(writer.insert(TABLE, _base_row(args, context, full_plan,
                                        'DELIVERY', delivery_id, payload)))
                occurrences.append(delivery_id)
    if full_plan['read_change']:
        read_id = operation + ':read'
        row_ids.append(writer.insert(TABLE, _base_row(args, context, full_plan,
                                'READ', read_id, {'read': True})))
        occurrences.append(read_id)
    return {'operation_id': operation, 'obligation_id': args['obligation_id'],
            'row_ids': row_ids, 'occurrences': occurrences,
            'outbox_occurrence_id': outbox_id if full_plan['outbox'] else None,
            'to': full_plan['to'], 'cc': full_plan['cc'], 'bcc': full_plan['bcc'],
            'read_changed': full_plan['read_change'],
            'message_version': full_plan['new_message_version'],
            'noop': not row_ids}


def _apply_environment(state, change):
    if type(change) is not dict:
        raise ValueError('Environment change must be closed')
    if change.get('kind') == 'directory' and set(change) == {'kind', 'version', 'groups'}:
        if (not _version(change['version']) or change['version'] <= state['directory']['version'] or
                type(change['groups']) is not dict):
            raise ValueError('Invalid directory change')
        for name, members in change['groups'].items():
            if (name not in state['directory']['groups'] or not _ids(members) or
                    not members or any(item not in state['known_ids'] for item in members)):
                raise ValueError('Unknown group or group identity')
        state['directory']['groups'].update(copy.deepcopy(change['groups']))
        state['directory']['version'] = change['version']
    elif change.get('kind') == 'message_version' and set(change) == {'kind', 'message_id', 'version'}:
        if (change['message_id'] not in state['messages'] or not _version(change['version']) or
                change['version'] <= state['messages'][change['message_id']]['version']):
            raise ValueError('Invalid message version change')
        state['messages'][change['message_id']]['version'] = change['version']
    else:
        raise ValueError('Unsupported environment change')


def environment_row(seed, rows, change):
    state = project(seed, rows)
    _apply_environment(state, change)
    return {'event_kind': 'ENV_DIRECTORY' if change['kind'] == 'directory' else 'ENV_MESSAGE_VERSION',
            'message_id': change.get('message_id', ''), 'message_version': change['version'],
            'obligation_id': '', 'occurrence_id': '', 'operation_id': '',
            'principal_id': 'harness.environment', 'payload_json': canonical(change)}


def observe_state(seed, rows):
    """Authorized current-state view; deliberately no outbox or receipts."""
    state = project(seed, rows)
    return {name: copy.deepcopy(state[name]) for name in ('self_id', 'messages', 'directory')}

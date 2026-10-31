"""Independent R5 oracle: raw SQLite tables and captured SDK wire, no provider import.

SQL surface: SELECT * FROM roots, mandates, reservations, business_effects,
receipts, transitions. Connections use mode=ro, with no writers active for final
readback. Checkpoint files are SQLite backups taken by the harness while idle.
The expected values come only from the frozen scenarios.json beside this file.
This same-team AI-assisted reader is not an independent human certification.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sqlite3

EXT = 'org.example/zti-mcp'
PROFILE = 'zti-mcp/0.1'
VERSION = '2026-07-28'
U64 = 2**64 - 1
SAFE = 2**53 - 1
CHARGED = {'COMMITTED', 'COMPLETED', 'UNKNOWN'}
RESERVED = {'RESERVED'}
STATES = CHARGED | RESERVED | {'CANCELLED', 'EXPIRED', 'REVOKED'}
UNITS = {'ops': 'operation', 'bytes': 'byte'}
FACTS = {'lab.compute': [], 'lab.read_sensitive': ['read_sensitive'], 'lab.export_external': ['export_external']}
RECEIPT_FIELDS = {'profile','tenant_id','root_mandate_id','mandate_id','operation_id','reservation_id','action_hash','effect_boundary','status','state_revision'}
ACTION_FIELDS = {'profile','tenant_id','root_mandate_id','mandate_id','operation_id','executor_id','resource_id','method','tool_name','tool_revision','arguments'}
TABLES = ('roots','mandates','reservations','business_effects','receipts','transitions')
SCENARIOS_SHA256 = '4ff940eb1c9ee00140472953f257026d7dd21eb296fcde10544d5368d868214f'
CONTRACT_SHA256 = '5d85f4ecf6d1e0f0fceffacf3d05e260c5e673abd64bc15c3faf4e6709fc3ad4'


def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def canonical(value):
    """An independently written, deliberately restricted JSON serialization."""
    def visit(v):
        if v is None or type(v) is bool:
            return
        if type(v) is int:
            if abs(v) > SAFE:
                raise ValueError('integer outside declared JSON subset')
        elif type(v) is str:
            v.encode('utf-8', errors='strict')
        elif type(v) is list:
            for item in v:
                visit(item)
        elif type(v) is dict:
            for key, item in v.items():
                if type(key) is not str or not key.isascii():
                    raise ValueError('non-ASCII object key')
                visit(item)
        else:
            raise ValueError('unsupported JSON value')
    visit(value)
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def uint(value):
    if type(value) is not str or not re.fullmatch(r'0|[1-9][0-9]*', value):
        raise ValueError('noncanonical quantity: ' + repr(value))
    number = int(value)
    if number > U64:
        raise ValueError('uint64 overflow')
    return number


def amounts(value):
    if type(value) is not dict or set(value) != set(UNITS):
        raise ValueError('invalid cost dimensions')
    result = {}
    for key, unit in UNITS.items():
        if set(value[key]) != {'unit','amount'} or value[key]['unit'] != unit:
            raise ValueError('invalid cost unit')
        result[key] = uint(value[key]['amount'])
    return result


def quantities(value):
    return {k: {'unit': UNITS[k], 'amount': str(value[k])} for k in UNITS}


def decode_jws(token):
    if type(token) is not str:
        raise ValueError('missing JWS')
    pieces = token.split('.')
    if len(pieces) != 3:
        raise ValueError('malformed compact JWS')
    decoded = []
    for piece in pieces:
        if not re.fullmatch(r'[A-Za-z0-9_-]+', piece):
            raise ValueError('invalid base64url')
        data = base64.urlsafe_b64decode(piece + '=' * (-len(piece) % 4))
        if base64.urlsafe_b64encode(data).decode().rstrip('=') != piece:
            raise ValueError('noncanonical base64url')
        decoded.append(data)
    if len(decoded[2]) != 64:
        raise ValueError('invalid ES256 signature length')
    header, payload = json.loads(decoded[0]), json.loads(decoded[1])
    if header.get('alg') != 'ES256':
        raise ValueError('unexpected signature algorithm')
    return header, payload


def key(row):
    return row['tenant_id'], row['root_mandate_id'], row['operation_id']


def observe_database(path):
    """Return raw base rows and independent derived facts, never provider views."""
    path = Path(path).resolve()
    if not path.is_file():
        raise ValueError('database absent: ' + str(path))
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as conn:
        conn.row_factory = sqlite3.Row
        if conn.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('SQLite integrity check failed')
        rows = {table: [dict(r) for r in conn.execute('SELECT * FROM ' + table)] for table in TABLES}
    violations = []
    def check(ok, detail):
        if not ok:
            violations.append(detail)
    roots = rows['roots']
    check(len(roots) == 1, 'fixture must have one persisted root')
    root_by_id = {(r['tenant_id'],r['root_mandate_id']): r for r in roots}
    mandates = {(m['tenant_id'],m['mandate_id']):m for m in rows['mandates']}
    reservations = {key(r):r for r in rows['reservations']}
    effects = {key(r):r for r in rows['business_effects']}
    receipts = {key(r):r for r in rows['receipts']}
    check(len(reservations) == len(rows['reservations']), 'duplicate reservation identity')
    check(len(effects) == len(rows['business_effects']), 'duplicate effect identity')
    check(len(receipts) == len(rows['receipts']), 'duplicate receipt identity')
    check(len({(r['tenant_id'],r['root_mandate_id'],r['reservation_id']) for r in reservations.values()}) == len(reservations), 'duplicate reservation key')
    D = {k:0 for k in UNITS}
    R = {k:0 for k in UNITS}
    cf, pf = set(), set()
    for m in mandates.values():
        body = json.loads(m['body_json'])
        check(digest(body) == m['mandate_hash'], 'mandate content hash mismatch')
        _, claims = decode_jws(m['jws'])
        check(claims.get('zti_mandate') == body, 'mandate JWS/body mismatch')
        check(body['delegatee_id'] == m['delegatee_id'], 'mandate delegatee mismatch')
        check(body['mandate_id'] == m['mandate_id'] and body['root_mandate_id'] == m['root_mandate_id'], 'mandate identity mismatch')
        root = root_by_id[(m['tenant_id'],m['root_mandate_id'])]
        check(body['policy_hash'] == digest(json.loads(root['policy_json'])), 'root policy hash mismatch')
        if m['parent_id'] is not None:
            parent = mandates.get((m['tenant_id'],m['parent_id']))
            check(parent is not None and parent['mandate_hash'] == m['parent_hash'] == body['parent_hash'], 'parent hash mismatch')
            if parent:
                pb = json.loads(parent['body_json'])
                pc, cc = pb['constraints'], body['constraints']
                for name in ('allowed_executors','allowed_resources','allowed_methods','allowed_tools'):
                    check(set(cc[name]) <= set(pc[name]), 'delegation widens ' + name)
                check(all(amounts(cc['action_caps'])[d] <= amounts(pc['action_caps'])[d] for d in UNITS), 'delegation widens caps')
                check(pb['valid_from'] <= body['valid_from'] < body['valid_until'] <= pb['valid_until'], 'delegation widens time')
    for op, reservation in reservations.items():
        state = reservation['state']
        if state not in STATES:
            raise ValueError('unrecognized reservation state: ' + str(state))
        action = json.loads(reservation['action_json'])
        cost = json.loads(reservation['cost_json'])
        factset = json.loads(reservation['facts_json'])
        check(set(action) == ACTION_FIELDS, 'action fields differ from binding')
        check(digest(action) == reservation['action_hash'], 'reservation action digest mismatch')
        check(key(action) == op and action['mandate_id'] == reservation['mandate_id'], 'reservation action identity mismatch')
        expected_cost = {'ops':uint(action['arguments']['units']), 'bytes':len(action['arguments']['payload'].encode('utf-8'))}
        check(amounts(cost) == expected_cost, 'stored cost differs from actual final action footprint')
        check(factset == FACTS[action['tool_name']], 'stored facts differ from tool catalog')
        mandate = mandates[(reservation['tenant_id'],reservation['mandate_id'])]
        check(reservation['subject'] == mandate['delegatee_id'], 'reservation subject differs from leaf')
        check(reservation['audience'] == action['executor_id'], 'reservation audience differs from executor')
        _, ict = decode_jws(reservation['ict_jws'])
        check(ict == json.loads(reservation['ict_claims_json']), 'stored ICT claims/JWS mismatch')
        check(ict.get('sub') == reservation['subject'] and ict.get('aud') == reservation['audience'], 'ICT subject/audience mismatch')
        zti = ict['zti']
        check(zti['action_hash'] == reservation['action_hash'] and zti['operation_id'] == op[2] and zti['reservation_id'] == reservation['reservation_id'], 'ICT operation/action binding mismatch')
        check(zti['cost_bounds'] == cost and zti['facts'] == factset, 'ICT footprint binding mismatch')
        if state in CHARGED:
            for d in D:
                D[d] += expected_cost[d]
            cf.update(factset)
            pf.update(factset)
            check(op in effects and op in receipts, 'consumed reservation lacks effect or receipt')
        elif state == 'RESERVED':
            for d in R:
                R[d] += expected_cost[d]
            pf.update(factset)
            check(op not in effects and op not in receipts, 'unconsumed reservation has effect/receipt')
        else:
            check(op not in effects and op not in receipts, 'released reservation has effect/receipt')
    for op, effect in effects.items():
        reservation = reservations.get(op)
        check(reservation is not None, 'effect lacks reservation')
        if reservation is None:
            continue
        for name in ('reservation_id','mandate_id','action_hash','action_json','cost_json','facts_json'):
            check(effect[name] == reservation[name], 'effect/reservation differs: ' + name)
        action = json.loads(effect['action_json'])
        check(json.loads(effect['arguments_json']) == action['arguments'], 'business arguments differ from bound action')
        check(digest(action) == effect['action_hash'], 'actual effect action digest mismatch')
        check(type(effect['provider_pid']) is int and effect['provider_pid'] > 0, 'invalid effect provider PID')
        check(op in receipts, 'effect lacks durable receipt')
    for op, stored in receipts.items():
        reservation = reservations.get(op)
        check(reservation is not None and op in effects, 'receipt lacks reservation/effect')
        receipt = json.loads(stored['receipt_json'])
        check(set(receipt) == RECEIPT_FIELDS, 'receipt fields differ from contract')
        check(receipt['status'] == 'COMMITTED' and receipt['effect_boundary'] == 'resource-mutation' and receipt['profile'] == PROFILE, 'receipt semantics invalid')
        if reservation:
            for name in ('tenant_id','root_mandate_id','operation_id','reservation_id','mandate_id','action_hash'):
                check(receipt[name] == reservation[name], 'receipt binding differs: ' + name)
        check(receipt['state_revision'] == stored['state_revision'], 'receipt revision storage mismatch')
        rr = uint(stored['state_revision'])
        root = root_by_id[(op[0],op[1])]
        check(1 <= rr <= uint(root['state_revision']), 'receipt revision outside root history')
        linked = [t for t in rows['transitions'] if t['tenant_id'] == op[0] and t['root_mandate_id'] == op[1] and t['state_revision'] == stored['state_revision']]
        check(len(linked) == 1 and linked[0]['event'] == 'COMMITTED' and linked[0]['operation_id'] == op[2] and linked[0]['reservation_id'] == stored['reservation_id'], 'receipt lacks exact consumption transition')
    for root in roots:
        ts = [t for t in rows['transitions'] if t['tenant_id'] == root['tenant_id'] and t['root_mandate_id'] == root['root_mandate_id']]
        allowed_events = {'ROOT_REGISTERED','CHILD_REGISTERED','RESERVED','COMMITTED','CANCELLED','REVOKED'}
        check(all(t['event'] in allowed_events for t in ts), 'unknown persisted transition event')
        revisions = sorted(uint(t['state_revision']) for t in ts)
        check(revisions == list(range(1,uint(root['state_revision'])+1)), 'root transitions not contiguous 1..revision')
        revocations = [t for t in ts if t['event'] == 'REVOKED']
        check(uint(root['authority_epoch']) == len(revocations), 'authority epoch differs from persisted revocations')
        root_mandates = [m for m in mandates.values() if m['tenant_id'] == root['tenant_id'] and m['root_mandate_id'] == root['root_mandate_id']]
        root_bodies = [m for m in root_mandates if m['parent_id'] is None]
        check(len(root_bodies) == 1 and root_bodies[0]['mandate_id'] == root['root_mandate_id'], 'root row lacks exactly one immutable root mandate')
        if len(root_bodies) == 1:
            check(root['active'] in (0,1) and root['active'] == 1-root_bodies[0]['revoked'], 'root activity differs from root mandate revocation')
            check(json.loads(root_bodies[0]['body_json'])['root_policy'] == json.loads(root['policy_json']), 'root policy differs from immutable root mandate')
        for mandate in root_mandates:
            event = 'ROOT_REGISTERED' if mandate['parent_id'] is None else 'CHILD_REGISTERED'
            registrations = [t for t in ts if t['event'] == event and json.loads(t['detail_json']).get('mandate_id') == mandate['mandate_id']]
            check(len(registrations) == 1, 'persisted mandate lacks exactly one registration transition')
            if event == 'ROOT_REGISTERED' and registrations:
                check(registrations[0]['state_revision'] == '1', 'root registration did not establish revision 1')
            revoked = [t for t in revocations if json.loads(t['detail_json']).get('mandate_id') == mandate['mandate_id']]
            check(len(revoked) == mandate['revoked'] and mandate['revoked'] in (0,1), 'mandate revocation flag/transition mismatch')
        for reservation in reservations.values():
            if reservation['tenant_id'] != root['tenant_id'] or reservation['root_mandate_id'] != root['root_mandate_id']:
                continue
            related = [t for t in ts if t['operation_id'] == reservation['operation_id'] and t['reservation_id'] == reservation['reservation_id']]
            reserved = [t for t in related if t['event'] == 'RESERVED']
            committed = [t for t in related if t['event'] == 'COMMITTED']
            cancelled = [t for t in related if t['event'] == 'CANCELLED']
            check(len(reserved) == 1, 'persisted reservation lacks exactly one reservation transition')
            check(len(committed) == (1 if reservation['state'] in CHARGED else 0), 'reservation consumption transition/state mismatch')
            check(len(cancelled) == (1 if reservation['state'] == 'CANCELLED' else 0), 'reservation cancellation transition/state mismatch')
            if reserved and committed:
                check(uint(reserved[0]['state_revision']) < uint(committed[0]['state_revision']), 'consumption revision did not follow reservation')
            if reserved and cancelled:
                check(uint(reserved[0]['state_revision']) < uint(cancelled[0]['state_revision']), 'cancellation revision did not follow reservation')
        expected_counts = Counter({'ROOT_REGISTERED':len(root_bodies),'CHILD_REGISTERED':len(root_mandates)-len(root_bodies),'REVOKED':sum(m['revoked'] for m in root_mandates),'RESERVED':sum(r['tenant_id'] == root['tenant_id'] and r['root_mandate_id'] == root['root_mandate_id'] for r in reservations.values()),'COMMITTED':sum(r['tenant_id'] == root['tenant_id'] and r['root_mandate_id'] == root['root_mandate_id'] and r['state'] in CHARGED for r in reservations.values()),'CANCELLED':sum(r['tenant_id'] == root['tenant_id'] and r['root_mandate_id'] == root['root_mandate_id'] and r['state'] == 'CANCELLED' for r in reservations.values())})
        observed_counts = Counter(t['event'] for t in ts)
        check(observed_counts == expected_counts, 'transition event counts differ from persisted state changes')
        policy = json.loads(root['policy_json'])
        check(all(D[d]+R[d] <= amounts(policy['budgets'])[d] for d in UNITS), 'cumulative budget exceeded')
        check(not any(set(pair) <= pf for pair in policy['forbidden_sets']), 'forbidden possible-fact combination admitted')
    summary = {'business_effect_rows':len(effects),'durable_receipt_rows':len(receipts),'reservation_rows':len(reservations),'reservation_states':{r['operation_id']:r['state'] for r in reservations.values()},'reservation_state_multiset':sorted(r['state'] for r in reservations.values()),'D':quantities(D),'R':quantities(R),'committed_facts':sorted(cf),'possible_facts':sorted(pf)}
    if len(roots) == 1:
        summary.update({'root_active': bool(roots[0]['active']), 'authority_epoch': roots[0]['authority_epoch'], 'state_revision': roots[0]['state_revision']})
    return {'summary':summary,'tables':rows,'integrity_violations':violations}


def aliases(fixtures):
    return {name: action['operation_id'] for name, action in fixtures['actions'].items()}


def compare_database(observation, expected, fixtures):
    summary, tables = observation['summary'], observation['tables']
    ops = aliases(fixtures)
    errors = []
    for field, value in expected.items():
        if field == 'reservation_states':
            actual = summary[field]
            wanted = {ops[k]:v for k,v in value.items()}
            if actual != wanted:
                errors.append('reservation_states expected ' + repr(wanted) + ', observed ' + repr(actual))
        elif field == 'operation_membership':
            allowed = {ops[x] for x in value['allowed']}
            actual = set(summary['reservation_states'])
            if not actual <= allowed or len(actual) != value['count']:
                errors.append('operation membership differs from one common admitted set')
            if value.get('effects_and_receipts_match_admitted_operations'):
                consumed = {r['operation_id'] for r in tables['reservations'] if r['state'] in CHARGED}
                if consumed != {e['operation_id'] for e in tables['business_effects']} or consumed != {r['operation_id'] for r in tables['receipts']}:
                    errors.append('effects/receipts do not match admitted consumed operations')
        elif field == 'same_winner_relation':
            rs = tables['reservations']
            allowed = {ops[x] for x in value['allowed_operations']}
            if len(rs) != 1 or rs[0]['operation_id'] not in allowed:
                errors.append('same-winner relation requires one common allowed operation')
                continue
            common = json.loads(rs[0]['facts_json'])
            if common not in value['allowed_common_fact_sets']:
                errors.append('winning fact set not permitted')
            if value.get('fact_set_matches_winning_tool') and common != FACTS[json.loads(rs[0]['action_json'])['tool_name']]:
                errors.append('winner fact set differs from winning tool')
            for member in value['must_equal_the_same_set']:
                if member in ('committed_facts','possible_facts'):
                    observed = summary[member]
                elif member == 'reservation.facts':
                    observed = common
                elif member == 'effect.facts':
                    observed = json.loads(tables['business_effects'][0]['facts_json']) if len(tables['business_effects']) == 1 else None
                else:
                    raise ValueError('unknown same-winner field: ' + member)
                if observed != common:
                    errors.append('same-winner relation violated by ' + member)
        elif field in summary:
            observed = summary[field]
            if field == 'reservation_state_multiset':
                value = sorted(value)
            if observed != value:
                errors.append(field + ' expected ' + repr(value) + ', observed ' + repr(observed))
        else:
            raise ValueError('unimplemented frozen database oracle: ' + field)
    return errors


def receipt_of(result):
    if not isinstance(result, dict):
        return None
    return result.get('receipt') or (result.get('_meta') or {}).get(EXT)


def discovery_version(result):
    # SDK v2.3.0 server/discover returns supportedVersions, while each request
    # stamps the actually used revision. The selected fixture advertises exactly
    # one modern version. A legacy protocolVersion/meta field cannot replace a
    # missing or contradictory supportedVersions value in this modern profile.
    versions = result.get('supportedVersions')
    if type(versions) is list and all(type(v) is str for v in versions) and versions == [VERSION]:
        return VERSION
    return None


def check_wire(expected_rows, observation, database, fixtures):
    errors = []
    steps, groups = observation['steps'], observation.get('groups', {})
    stored = {r['operation_id']:json.loads(r['receipt_json']) for r in database['tables']['receipts']}
    ops = aliases(fixtures)
    for row in expected_rows:
        if 'step_group' in row:
            group = [steps[x] for x in groups[row['step_group']]]
            if 'outcomes' in row:
                observed = [s.get('result',{}).get('status') if 'error' not in s else 'REFUSED:'+s['error'].get('data',{}).get('reason','') for s in group]
                if Counter(observed) != Counter(row['outcomes']):
                    errors.append(row['step_group'] + ': concurrent outcome multiset mismatch: ' + repr(observed))
                if 'refusal_code' in row and any(s['error']['code'] != row['refusal_code'] for s in group if 'error' in s):
                    errors.append(row['step_group'] + ': wrong refusal code')
            if 'receipt_status_multiset' in row:
                observed = [receipt_of(s.get('result')) for s in group]
                if Counter(r.get('status') if r else None for r in observed) != Counter(row['receipt_status_multiset']):
                    errors.append(row['step_group'] + ': receipt multiset mismatch')
                if row.get('receipts_equal_stored') and any(r is None or r != stored.get(r['operation_id']) for r in observed):
                    errors.append(row['step_group'] + ': returned receipt differs from stored')
            continue
        sid = row['step']
        step = steps[sid]
        result = step.get('result', {})
        error = step.get('error', {})
        receipt = receipt_of(result)
        for field, wanted in row.items():
            good = True
            if field == 'step':
                continue
            if field == 'code':
                good = error.get('code') == wanted
            elif field == 'data':
                good = all(error.get('data',{}).get(k) == v for k,v in wanted.items())
            elif field in ('resultType','status','authority_epoch'):
                good = not error and result.get(field) == wanted
            elif field == 'receipt_status':
                good = receipt is not None and receipt.get('status') == wanted
            elif field == 'receipt_equals_stored_for':
                good = receipt is not None and receipt == stored.get(ops[wanted])
            elif field in ('receipt_present','ict_present'):
                present = receipt is not None if field == 'receipt_present' else result.get('ict') is not None
                good = present == wanted
            elif field == 'receipt_absent':
                good = not wanted or receipt is None
            elif field == 'same_receipt_as':
                good = receipt is not None and receipt == receipt_of(steps[wanted].get('result'))
            elif field == 'same_ict_as':
                good = result.get('ict') is not None and result.get('ict') == steps[wanted].get('result',{}).get('ict')
            elif field == 'same_reservation_as':
                good = result.get('reservation_id') is not None and result.get('reservation_id') == steps[wanted].get('result',{}).get('reservation_id')
            elif field == 'revision_unchanged':
                good = not wanted or step.get('before_revision') is not None and step.get('before_revision') == step.get('after_revision')
            elif field == 'outer_revision_greater_than_receipt_revision':
                good = receipt is not None and uint(result['state_revision']) > uint(receipt['state_revision'])
            elif field == 'same_mandate_hash':
                body = fixtures['mandates']['agent_a']
                good = result.get('mandate_hash') == digest(body)
            elif field == 'protocol_version':
                good = discovery_version(result) == wanted
            elif field in ('capability','extension_present'):
                caps = result.get('capabilities') or (result.get('_meta') or {}).get('io.modelcontextprotocol/serverCapabilities') or {}
                cap = (caps.get('extensions') or {}).get(EXT)
                good = (cap == fixtures.get('capability', {'revision':'0.1','profile':PROFILE,'mode':'current-online','effect_coupling':'required'})) if field == 'capability' else ((cap is not None) == wanted)
            elif field in ('transport_outcome','client_outcome'):
                good = step.get(field) == wanted
            elif field == 'policy_refusal_claimed':
                good = ('error' in step and step['error'].get('code') == -31001) == wanted
            elif field == 'is_wire_error':
                good = bool(step.get('is_wire_error', 'error' in step)) == wanted
            else:
                raise ValueError('unimplemented frozen wire oracle: ' + field)
            if not good:
                errors.append(sid + ': wire oracle mismatch for ' + field)
    return errors


def verify_variant(variant_dir, scenario_id, variant_id, mutant_id=None):
    """Evaluate unchanged normal oracle and (separately) intended mutant witness."""
    directory = Path(variant_dir)
    scenarios_path = Path(__file__).with_name('scenarios.json')
    if hashlib.sha256(scenarios_path.read_bytes()).hexdigest() != SCENARIOS_SHA256 or hashlib.sha256(Path(__file__).with_name('contract.md').read_bytes()).hexdigest() != CONTRACT_SHA256:
        raise ValueError('frozen R5 contract/oracle identity changed')
    frozen = load(scenarios_path)
    scenario = next(s for s in frozen['scenarios'] if s['id'] == scenario_id)
    variant = next(v for v in scenario['variants'] if v['id'] == variant_id)
    failures, infrastructure = [], []
    try:
        fixtures = load(directory/'fixtures.json')
        observation = load(directory/'observation.json')
        if observation.get('infra_errors'):
            infrastructure.extend(observation['infra_errors'])
        database = observe_database(directory/'provider.sqlite')
        infrastructure.extend(database['integrity_violations'])
        failures.extend(compare_database(database,variant['expected_database'],fixtures))
        failures.extend(check_wire(variant['expected_wire'],observation,database,fixtures))
        checkpoints = {}
        for name, wanted in variant.get('checkpoints',{}).items():
            value = observe_database(directory/'checkpoints'/(name+'.sqlite'))
            checkpoints[name] = value
            infrastructure.extend(name+': '+f for f in value['integrity_violations'])
            failures.extend(name+': '+f for f in compare_database(value,wanted,fixtures))
        # Protocol capture and schedule-specific checks are below; missing evidence
        # is an infrastructure failure, never semantic mutation detection.
        capture = verify_capture(directory,scenario_id,variant_id,variant,fixtures,observation,database,mutant_id)
        infrastructure.extend(capture['infrastructure'])
        failures.extend(capture['failures'])
        matches = not failures and not infrastructure
        detected = None
        if mutant_id is not None:
            mutant = next(m for m in frozen['integration_mutants'] if m['id'] == mutant_id)
            counter = compare_database(database,mutant['expected_counterexample'],fixtures)
            failures_expected = len(failures) > 0
            detected = failures_expected and not infrastructure and not counter and capture['mutant_path_verified']
    except Exception as exc:
        infrastructure.append(type(exc).__name__ + ': ' + str(exc))
        database, checkpoints, matches, detected = None, {}, False, False if mutant_id else None
    return {'status':'PASS' if (detected if mutant_id else matches) else 'FAIL','scenario':scenario_id,'variant':variant_id,'mutant_id':mutant_id,'matches_oracle':matches,'matches_normal_oracle':matches,'mutation_detected':detected,'errors':infrastructure+failures,'semantic_failures':failures,'infrastructure_errors':infrastructure,'observed':database['summary'] if database else None,'database':database,'checkpoints':checkpoints,'limits':'Direct SQLite and captured local stdio evidence only; same-team AI-assisted review, not independent human certification.'}


def verify_capture(directory, scenario_id, variant_id, variant, fixtures, observation, database, mutant_id):
    infrastructure, failures = [], []
    records, requests, responses = [], {}, {}
    lifecycle = []
    for path in sorted((Path(directory)/'wire').glob('*.jsonl')):
        prior = {}
        for line in path.read_text(encoding='utf-8').splitlines():
            record = json.loads(line)
            if record.get('type') in ('provider_start','provider_exit'):
                lifecycle.append(record)
                continue
            if 'direction' not in record:
                continue
            endpoint = record['endpoint_instance_id']
            sequence = record['sequence']
            if endpoint in prior and sequence <= prior[endpoint]:
                infrastructure.append('wire sequence not strictly increasing')
            prior[endpoint] = sequence
            raw = base64.b64decode(record['raw_base64'],validate=True)
            if json.loads(raw) != record['frame']:
                infrastructure.append('raw pipe bytes differ from recorded parsed frame')
            if type(record['provider_pid']) is not int or record['provider_pid'] <= 0 or record['provider_pid'] == record['relay_pid']:
                infrastructure.append('capture does not identify distinct actual provider PID')
            frame = record['frame']
            if frame.get('jsonrpc') != '2.0':
                infrastructure.append('non-JSON-RPC frame')
            if 'id' in frame:
                identity = (endpoint,frame['id'])
                target = requests if record['direction'] == 'client_to_server' else responses
                if identity in target:
                    infrastructure.append('duplicate request/response ID within endpoint instance')
                target[identity] = record
            records.append(record)
    if not records or not lifecycle:
        infrastructure.append('actual pipe records or provider lifecycle absent')
    provider_pids = {r['provider_pid'] for r in records}
    starts = {r['provider_pid'] for r in lifecycle if r['type'] == 'provider_start'}
    if not provider_pids <= starts:
        infrastructure.append('wire provider PIDs lack launch records')
    effect_pids = {r['provider_pid'] for r in database['tables']['business_effects']}
    if not effect_pids <= provider_pids:
        infrastructure.append('effect PID is not an observed SDK provider process')
    expected_crash_instance = None
    if scenario_id == 'S07':
        lost_step = 'call_lost' if variant_id == 'lost_reply_after_commit' else 'call_interrupted'
        expected_crash_instance = observation['steps'][lost_step].get('endpoint_instance_id')
    instances = {r['endpoint_instance_id'] for r in lifecycle} | {r['endpoint_instance_id'] for r in records}
    for instance in instances:
        launched = [r for r in lifecycle if r['endpoint_instance_id'] == instance and r['type'] == 'provider_start']
        exited = [r for r in lifecycle if r['endpoint_instance_id'] == instance and r['type'] == 'provider_exit']
        if len(launched) != 1 or len(exited) != 1:
            infrastructure.append(instance+': endpoint lacks exactly one launch and final exit')
            continue
        wanted_exit = 86 if instance == expected_crash_instance else 0
        if exited[0].get('returncode') != wanted_exit or launched[0]['provider_pid'] != exited[0]['provider_pid']:
            infrastructure.append(instance+': unexpected provider process exit or PID mismatch')
    for identity, record in requests.items():
        frame = record['frame']
        method = frame.get('method')
        if method in ('tools/call',EXT+'.register',EXT+'.reserve',EXT+'.lookup',EXT+'.cancel',EXT+'.revoke'):
            meta = (frame.get('params') or {}).get('_meta') or {}
            if meta.get('io.modelcontextprotocol/protocolVersion') != VERSION:
                infrastructure.append('protected/control raw request lacks exact protocol metadata')
            caps = meta.get('io.modelcontextprotocol/clientCapabilities') or {}
            if (caps.get('extensions') or {}).get(EXT) != {'revision':'0.1','profile':PROFILE,'mode':'current-online','effect_coupling':'required'}:
                infrastructure.append('protected/control raw request has incompatible client capability')
        if method and method.startswith(EXT+'.') and identity in responses and 'result' in responses[identity]['frame']:
            short = method.rsplit('.',1)[1]
            defs = load(Path(__file__).resolve().parents[2]/'schema/zti-control-0.1.schema.json')['$defs']
            schema = defs[short+'Result']
            result = responses[identity]['frame']['result']
            if not set(schema['required']) <= set(result) or not set(result) <= set(schema['properties']):
                failures.append(short+': method-specific control result fields invalid')
            status_schema = schema['properties']['status']
            if result.get('resultType') != 'complete' or result.get('status') not in status_schema.get('enum',[status_schema.get('const')]):
                failures.append(short+': method-specific resultType/status invalid')
            if 'state_revision' in result:
                uint(result['state_revision'])
            if 'authority_epoch' in result:
                uint(result['authority_epoch'])
            if short in ('reserve','lookup','cancel'):
                if ('receipt' in result) != (result.get('status') in CHARGED):
                    failures.append(short+': receipt/state condition invalid')
                if 'ict' in result and (short != 'reserve' or result.get('status') != 'RESERVED' or type(result['ict']) is not str):
                    failures.append(short+': ICT returned outside usable reservation result')
        if identity in responses and responses[identity]['frame'].get('error',{}).get('code') == -31001:
            error = responses[identity]['frame']['error']
            defs = load(Path(__file__).resolve().parents[2]/'schema/zti-control-0.1.schema.json')['$defs']
            data = error.get('data')
            good = set(error) == {'code','message','data'} and type(error.get('message')) is str and type(data) is dict
            if good:
                ed = defs['ztiErrorData']
                good = set(ed['required']) <= set(data) <= set(ed['properties']) and data.get('profile') == PROFILE and data.get('reason') in ed['properties']['reason']['enum'] and data.get('status') in ed['properties']['status']['enum']
                if 'operation_ref' in data:
                    refschema = defs['operationRef']
                    ref = data['operation_ref']
                    good = good and type(ref) is dict and set(refschema['required']) <= set(ref) <= set(refschema['properties']) and all(type(v) is str and v for v in ref.values())
            if not good:
                failures.append('ZTI refusal error shape contains missing/undefined/invalid data or receipt/token material')
        if identity not in responses:
            matched = [s for s in observation['steps'].values() if s.get('endpoint_instance_id') == identity[0] and s.get('request_id') == identity[1]]
            if len(matched) != 1 or matched[0].get('transport_outcome') != 'CONNECTION_CLOSED_WITHOUT_VALID_RESULT':
                infrastructure.append('raw request lacks a response or explicitly expected closed-connection outcome')
    # Raw requests/replies must agree with step data, rather than trusting a
    # harness result dictionary as proof of an exchange.
    for sid, step in observation['steps'].items():
        if not step.get('method'):
            continue
        identity = (step.get('endpoint_instance_id'),step.get('request_id'))
        request = requests.get(identity)
        if request is None:
            infrastructure.append(sid+': no exact raw SDK request identity')
            continue
        if request['frame'].get('method') != step['method']:
            infrastructure.append(sid+': raw request method differs')
        reply = responses.get(identity)
        if 'transport_outcome' in step:
            allowed = next((r.get('transport_outcome') for r in variant['expected_wire'] if r.get('step') == sid), None)
            if step['transport_outcome'] != allowed or step.get('endpoint_instance_id') != expected_crash_instance:
                infrastructure.append(sid+': transport failure is outside explicitly expected crash observation')
            if reply:
                infrastructure.append(sid+': claimed closed-without-result has a captured RPC reply')
        elif reply is None:
            infrastructure.append(sid+': response not captured')
        elif 'error' in step:
            if reply['frame'].get('error') != step['error']:
                infrastructure.append(sid+': recorded error differs from raw response')
        elif 'result' in step:
            if reply['frame'].get('result') != step['result']:
                infrastructure.append(sid+': recorded result differs from raw response')
    # Baseline bootstrap must import signed root/child JWSs through register.
    registered_tokens = []
    for record in requests.values():
        frame = record['frame']
        if frame.get('method') == EXT+'.register':
            token = (frame.get('params') or {}).get('mandate')
            if token is None:
                token = (frame.get('params') or {}).get('signed_mandate')
            if token is None:
                token = (frame.get('params') or {}).get('mandate_jws')
            if not isinstance(token,str):
                infrastructure.append('register raw request does not contain signed JWS')
            else:
                registered_tokens.append(token)
    for mandate in database['tables']['mandates']:
        if mandate['jws'] not in registered_tokens:
            infrastructure.append('persisted mandate did not arrive via actual register request')
    # Every endpoint used for an ordinary protected action must have a prior
    # real discovery; explicit missing-support negative stops at the client.
    discoveries = {}
    for identity, request in requests.items():
        if request['frame'].get('method') != 'server/discover':
            continue
        reply = responses.get(identity)
        if not reply or 'result' not in reply['frame']:
            infrastructure.append('discovery lacks actual result')
            continue
        result = reply['frame']['result']
        protocol = discovery_version(result)
        request_stamp = ((request['frame'].get('params') or {}).get('_meta') or {}).get('io.modelcontextprotocol/protocolVersion')
        if protocol != VERSION:
            failures.append('actual discovery modern supportedVersions is missing, malformed or incompatible')
        if request_stamp != VERSION:
            infrastructure.append('actual discovery request lacks exact protocol metadata')
        discoveries.setdefault(identity[0],[]).append((request,reply))
    for identity, record in requests.items():
        if record['frame'].get('method') in ('tools/call',EXT+'.reserve'):
            prior = [pair for pair in discoveries.get(identity[0],[]) if pair[1]['sequence'] < record['sequence']]
            if not prior:
                infrastructure.append('protected action lacks prior captured discovery')
            else:
                discovered = prior[-1][1]['frame']['result']
                caps = discovered.get('capabilities') or (discovered.get('_meta') or {}).get('io.modelcontextprotocol/serverCapabilities') or {}
                if (caps.get('extensions') or {}).get(EXT) != {'revision':'0.1','profile':PROFILE,'mode':'current-online','effect_coupling':'required'}:
                    failures.append('ordinary protected action followed discovery without exact required server capability')
    for scope, wanted in variant.get('expected_recorded_frames',{}).items():
        if 'action_metadata_revision' in wanted:
            step = observation['steps'][scope]
            rec = requests.get((step.get('endpoint_instance_id'),step.get('request_id')))
            meta = ((rec or {}).get('frame',{}).get('params') or {}).get('_meta') or {}
            if (meta.get(EXT) or {}).get('revision') != wanted['action_metadata_revision']:
                failures.append(scope+': changed action revision not present on actual wire')
            client_cap = ((meta.get('io.modelcontextprotocol/clientCapabilities') or {}).get('extensions') or {}).get(EXT) or {}
            if client_cap.get('revision') != wanted['client_extension_revision']:
                failures.append(scope+': SDK client capability revision did not remain unchanged')
        else:
            endpoint_name = scope.removesuffix('_after_discovery')
            endpoint_ids = {s['endpoint_instance_id'] for s in observation['steps'].values() if s.get('endpoint') == endpoint_name and s.get('endpoint_instance_id')}
            for method, count in wanted.items():
                actual = sum(1 for r in requests.values() if r['endpoint_instance_id'] in endpoint_ids and r['frame'].get('method') == method)
                if actual != count:
                    failures.append(scope+': actual '+method+' count differs')
    if scenario_id == 'S01':
        a,b = observation['steps']['call'],observation['steps']['call_retry']
        if a.get('endpoint_instance_id') != b.get('endpoint_instance_id') or a.get('request_id') == b.get('request_id'):
            failures.append('same-session retry lacks distinct observed SDK IDs')
    if scenario_id in ('S05','S06') and 'after_admission' in variant.get('checkpoints',{}):
        admissions = [observation['steps'][sid] for sid in observation['groups']['admissions']]
        pids = {requests[(s['endpoint_instance_id'],s['request_id'])]['provider_pid'] for s in admissions}
        if len(pids) != 2:
            infrastructure.append('concurrent admissions did not reach two distinct provider processes')
    # Hook/event assertions are verified against persisted trusted hook records
    # and ordered harness acknowledgements, with database revisions as an
    # independent order for actual authority/effect commits.
    hook_records = []
    for path in sorted(Path(directory).rglob('*events*.jsonl')):
        for line in path.read_text(encoding='utf-8').splitlines():
            hook_records.append(json.loads(line))
    events = observation.get('events',[])
    sequences = [e.get('sequence') for e in events]
    if sequences != list(range(1,len(events)+1)):
        infrastructure.append('causal harness journal sequence is not contiguous')
    for event in events:
        if event.get('source') == 'observed_provider_hook':
            raw_hook = event.get('provider_hook')
            if raw_hook not in hook_records:
                infrastructure.append('causal provider milestone lacks exact raw hook evidence')
                continue
            expected_name = raw_hook['event']
            if expected_name == 'call:before_transaction' and raw_hook.get('stage') == 'arrived':
                expected_name = 'call:pause_before_transaction'
            elif expected_name == 'call:commit' and mutant_id == 'M02':
                expected_name = 'call:effect_commit'
            if event.get('kind') != expected_name:
                infrastructure.append('causal provider milestone name differs from actual hook')
    names = [e.get('name') or e.get('kind') or e.get('event') for e in events]
    order = variant.get('required_event_order',[])
    if mutant_id == 'M02':
        order = next(m for m in load(Path(__file__).with_name('scenarios.json'))['integration_mutants'] if m['id'] == 'M02')['required_event_order']
    positions = []
    for name in order:
        if name not in names:
            infrastructure.append('required event absent: '+name)
        else:
            positions.append(names.index(name))
    if positions != sorted(positions) or len(set(positions)) != len(positions):
        failures.append('required event order not established')
    def step_request(name):
        step = observation['steps'][name]
        return requests[(step['endpoint_instance_id'],step['request_id'])]
    if scenario_id == 'S03' and variant_id == 'post_parse_argument_change':
        changed = [h for h in hook_records if h.get('event') == 'after_sdk_validation_before_final_action' and h.get('stage') == 'transformed']
        if len(changed) != 1:
            infrastructure.append('one actual post-SDK argument transformation not observed')
        else:
            h = changed[0]
            original = fixtures['actions']['op_a']
            final = {**original,'arguments':h['after']}
            wire_arguments = step_request('call_changed')['frame']['params']['arguments']
            if wire_arguments != h['before'] or wire_arguments != original['arguments'] or h['before']['payload'] != 'alpha' or h['after']['payload'] != 'bravo':
                failures.append('post-SDK transformation did not alter exact intended payload')
            if digest(original) == digest(final) or len(h['before']['payload'].encode()) != len(h['after']['payload'].encode()):
                failures.append('post-SDK exact-action witness failed equal-footprint/different-hash relation')
    if scenario_id == 'S03' and variant_id == 'invalid_es256_signature':
        issued = observation['steps']['reserve']['result']['ict'].split('.')
        sent = step_request('call_bad_signature')['frame']['params']['_meta'][EXT]['ict'].split('.')
        a = base64.urlsafe_b64decode(issued[2]+'='*(-len(issued[2])%4))
        b = base64.urlsafe_b64decode(sent[2]+'='*(-len(sent[2])%4))
        if issued[:2] != sent[:2] or len(a) != 64 or len(b) != 64 or bytes([a[0]^1])+a[1:] != b:
            failures.append('signature-negative wire witness changed more than specified signature bit')
    if scenario_id == 'S03' and variant_id == 'wrong_trusted_principal':
        request = step_request('call_as_intruder')
        token = request['frame']['params']['_meta'][EXT]['ict']
        sub = decode_jws(token)[1]['sub']
        ready = [h for h in hook_records if h.get('event') == 'endpoint_ready' and h.get('endpoint_instance_id') == request['endpoint_instance_id']]
        if sub != 'urn:r5:agent-a' or len(ready) != 1 or ready[0].get('principal') != 'urn:r5:intruder':
            failures.append('wrong-principal witness not fixed independently at endpoint launch')
    if scenario_id == 'S04' and variant_id == 'sibling_revocation_stales_epoch':
        bodies = fixtures['mandates']
        mandates = {m['mandate_id']:m for m in database['tables']['mandates']}
        if mandates[bodies['agent_a']['mandate_id']]['revoked'] or not mandates[bodies['agent_b']['mandate_id']]['revoked']:
            failures.append('stale-epoch witness revoked wrong execution lineage')
        tokens = [decode_jws(r['ict_jws'])[1] for r in database['tables']['reservations']]
        if len(tokens) != 1 or tokens[0]['zti']['authority_epoch'] != '0' or database['summary']['authority_epoch'] != '1':
            failures.append('stale-epoch witness lacks old ICT/current epoch relation')
    if scenario_id == 'S04' and variant_id == 'ict_expiry_before_effect':
        reservation_rows = database['tables']['reservations']
        if len(reservation_rows) != 1:
            infrastructure.append('expiry witness lacks one persisted original reservation')
        else:
            claims = decode_jws(reservation_rows[0]['ict_jws'])[1]
            expiry = claims['exp']
            clock_events = [e for e in events if e.get('kind') == 'clock_set' and e.get('step') == 'advance_clock']
            clock = int((Path(directory)/'clock.txt').read_text(encoding='utf-8').strip())
            issued_wire = observation['steps']['reserve']['result']['ict']
            if issued_wire != reservation_rows[0]['ict_jws'] or len(clock_events) != 1 or clock_events[0].get('value') != expiry or clock != expiry:
                failures.append('expiry test did not set authoritative fixture clock to exact issued exp')
            if not all(json.loads(m['body_json'])['valid_from'] <= expiry < json.loads(m['body_json'])['valid_until'] for m in database['tables']['mandates']):
                failures.append('mandate validity does not extend beyond exact ICT expiry witness')
    if scenario_id in ('S05','S06') and 'after_admission' in variant.get('checkpoints',{}):
        arrived = [h for h in hook_records if h.get('event') == 'reserve:before_transaction' and h.get('stage') == 'arrived']
        released = [h for h in hook_records if h.get('event') == 'reserve:before_transaction' and h.get('stage') == 'released']
        if len(arrived) != 2 or len(released) != 2 or len({h['provider_pid'] for h in arrived}) != 2:
            infrastructure.append('reservation barrier lacks two actual distinct provider arrivals/releases')
        else:
            # Handshake causality is authoritative. Windows Python 3.12 can
            # assign equal monotonic timestamps to distinct observed events;
            # no strict elapsed-time relation is inferred from those stamps.
            observed_arrivals = [e for e in events if e.get('kind') == 'barrier_arrivals_observed' and len(e.get('arrivals',[])) == 2]
            releases = [e for e in events if e.get('kind') == 'reservation_barrier:released']
            if len(observed_arrivals) != 1 or len(releases) != 1 or observed_arrivals[0]['sequence'] >= releases[0]['sequence']:
                infrastructure.append('two-arrival harness acknowledgement before barrier release not established')
            elif {h['provider_pid'] for h in observed_arrivals[0]['arrivals']} != {h['provider_pid'] for h in arrived} or any(h not in arrived for h in observed_arrivals[0]['arrivals']):
                infrastructure.append('barrier acknowledgement does not contain actual two raw provider arrival records')
    if scenario_id == 'S07':
        lost = 'call_lost' if variant_id == 'lost_reply_after_commit' else 'call_interrupted'
        before = step_request(lost)
        after = step_request('call_retry')
        if before['provider_pid'] == after['provider_pid'] or before['endpoint_instance_id'] == after['endpoint_instance_id']:
            failures.append('restart did not change actual provider process/endpoint instance')
        point = 'call:after_commit' if variant_id == 'lost_reply_after_commit' else 'call:staged_before_commit'
        crashes = [h for h in hook_records if h.get('event') == point and h.get('stage') == 'process_exit']
        if len(crashes) != 1 or crashes[0]['provider_pid'] != before['provider_pid']:
            infrastructure.append('specified actual commit/crash point not reached')
        exits = [h for h in lifecycle if h['type'] == 'provider_exit' and h['provider_pid'] == before['provider_pid']]
        if len(exits) != 1 or exits[0].get('returncode') != 86:
            infrastructure.append('expected fault process exit not observed')
        checkpoint = observe_database(Path(directory)/'checkpoints/after_crash.sqlite')
        reserve_revision = observation['steps']['reserve']['result']['state_revision']
        wanted_revision = uint(reserve_revision)+(1 if variant_id == 'lost_reply_after_commit' else 0)
        if uint(checkpoint['summary']['state_revision']) != wanted_revision:
            failures.append('crash checkpoint root revision did not commit/rollback with effect and receipt')
    mutant_path = mutant_id is None
    if mutant_id == 'M01':
        step = observation['steps']['call_without_ict']
        req = requests.get((step.get('endpoint_instance_id'),step.get('request_id')))
        meta = (((req or {}).get('frame') or {}).get('params') or {}).get('_meta') or {}
        actual_missing = 'ict' not in (meta.get(EXT) or {})
        operation = fixtures['actions']['op_a']['operation_id']
        executed_fallback = [h for h in hook_records if h.get('event') == 'mutant:M01_missing_ict_fallback' and h.get('operation_id') == operation and h.get('provider_pid') == (req or {}).get('provider_pid')]
        mutant_path = actual_missing and database['summary']['business_effect_rows'] == 1 and len(executed_fallback) == 1
    elif mutant_id == 'M02':
        revokes = [uint(t['state_revision']) for t in database['tables']['transitions'] if t['event'] == 'REVOKED']
        commits = [uint(t['state_revision']) for t in database['tables']['transitions'] if t['event'] == 'COMMITTED']
        old_epochs = [decode_jws(r['ict_jws'])[1]['zti']['authority_epoch'] for r in database['tables']['reservations']]
        mutant_path = bool(revokes and commits and min(commits) > max(revokes) and old_epochs == ['0'] and database['summary']['authority_epoch'] == '1' and not any('required event absent' in x for x in infrastructure))
    return {'infrastructure':infrastructure,'failures':failures,'mutant_path_verified':mutant_path,'raw_frame_count':len(records),'provider_pids':sorted(provider_pids)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('variant_directory', type=Path)
    parser.add_argument('scenario')
    parser.add_argument('variant')
    parser.add_argument('--mutant')
    args = parser.parse_args()
    report = verify_variant(args.variant_directory,args.scenario,args.variant,args.mutant)
    print(json.dumps(report,indent=2,ensure_ascii=False))
    raise SystemExit(0 if report['status'] == 'PASS' else 1)

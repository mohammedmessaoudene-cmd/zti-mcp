"""Compare actual independent client calculations to preexecution byte goldens."""
import base64
import hashlib
import json
from primitives import canonical, decoded, demo_effect
from state import need

def read_rows(path):
    value=json.loads(path.read_text(encoding='utf-8'))
    rows=value['rows']
    need(type(rows) is list and len({x['id'] for x in rows})==len(rows),'duplicate/malformed vector IDs')
    return value,{x['id']:x for x in rows}

def check_vector(row,spec):
    if spec['expected'] in ('ACCEPT','CANONICAL_ONLY_TOOL_BINDING_REFUSED'):
        need('result' in row and 'error' not in row,'canonical vector unexpectedly refused '+spec['id'])
        result=row['result']
        need(result['action_hash']==spec['golden_sha256'] and result['canonical_utf8_base64']==spec['golden_canonical_utf8_base64'],'independent client binding differs from golden '+spec['id'])
        raw=base64.b64decode(result['canonical_utf8_base64'],validate=True)
        need(canonical(spec['input'])==raw,'actual canonical bytes differ from frozen input')
        cost,facts=demo_effect(spec['input']['arguments'])
        need(result['costs']==cost and result['facts']==facts,'client cost/facts differ from independent calculation')
        if spec['expected']=='CANONICAL_ONLY_TOOL_BINDING_REFUSED':
            need(row.get('domain_error')=='BINDING_MISMATCH','canonical-only vector lacks its separate tool-domain refusal')
    else:
        need('error' in row and 'result' not in row,'invalid vector accepted '+spec['id'])
        error=row['error']
        need(type(error) is dict and error.get('reason')==spec['expected'].removeprefix('REFUSE_'),'vector refusal differs '+spec['id'])

def audit_vectors(path, specifications, *, client):
    value,rows=read_rows(path)
    need(value['client']==client,'vector client identity')
    need(set(rows)=={x['id'] for x in specifications},'actual vector set differs from frozen set')
    for spec in specifications:check_vector(rows[spec['id']],spec)
    return {'status':'PASS','client':client,'vectors':len(specifications),'ids':sorted(rows)}

def audit_m01(path, specifications):
    value,rows=read_rows(path)
    need(value['client']=='T','M01 must execute TypeScript Number conversion')
    witness=rows['V16']
    need('result' in witness and 'error' not in witness,'M01 did not reach a valid precision-loss calculation')
    result=witness['result']
    golden={x['id']:x for x in specifications}
    raw=base64.b64decode(result['canonical_utf8_base64'],validate=True)
    action=decoded(raw)
    need(hashlib.sha256(raw).hexdigest()==result['action_hash'],'M01 reported hash does not match its actual canonical bytes')
    need(action['arguments']['quantity']=='9007199254740992' and result['costs']['ops']['amount']=='9007199254740992','M01 precision loss not activated')
    need(result['action_hash']==golden['V15']['golden_sha256'] and result['action_hash']!=golden['V16']['golden_sha256'],'M01 witness does not show the intended golden divergence')
    try:check_vector(witness,golden['V16'])
    except ValueError as error:
        need(str(error)=='independent client binding differs from golden V16','M01 normal check failed for an unrelated reason')
    else:raise ValueError('M01 was accepted by the ordinary vector check')
    return {'status':'DETECTED','mutant':'M01','witness':'V16','observed_quantity':'9007199254740992','expected_quantity':'9007199254740993','normal_golden_mismatch':True,'normal_oracle_scope':'Unchanged V16 row predicate, also used by the normal full vector suite','infrastructure_error_is_detection':False}

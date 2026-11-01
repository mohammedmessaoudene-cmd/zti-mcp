"""Independent, side-effect-free audit of exported R6 SQL table snapshots.

Only the published contract and cryptographic primitives are semantic inputs.
This module does not connect to a provider or import its code.
"""
from primitives import action_hash, canonical, decoded, demo_effect, u64, verify_jws

BODY_FIELDS = {'profile','tenant_id','principal_id','root_mandate_id','mandate_id','parent_id','parent_hash','correlation_id','delegatee_id','valid_from','valid_until','constraints','root_policy','policy_hash'}
RECEIPT_FIELDS = {'profile','tenant_id','root_mandate_id','mandate_id','operation_id','reservation_id','action_hash','effect_boundary','status','state_revision'}
ACTION_FIELDS = {'profile','tenant_id','root_mandate_id','mandate_id','operation_id','executor_id','resource_id','method','tool_name','tool_revision','arguments'}
CHARGED = {'COMMITTED','COMPLETED','UNKNOWN'}
EVENTS = {'ROOT_REGISTERED','CHILD_REGISTERED','RESERVED','COMMITTED','CANCELLED','REVOKED'}

def need(condition, message):
    if not condition:
        raise ValueError(message)

def quantities(vector):
    need(type(vector) is dict and set(vector)=={'ops','bytes'}, 'cost vector dimensions')
    values = {}
    for dimension, unit in (('ops','operation'),('bytes','byte')):
        value = vector[dimension]
        need(type(value) is dict and set(value)=={'unit','amount'} and value['unit']==unit, 'cost vector unit/fields')
        values[dimension] = u64(value['amount'])
    return values

def _key(row):
    return row['tenant_id'],row['root_mandate_id'],row['operation_id']

def _unique(rows, key, message):
    out = {}
    for row in rows:
        value = key(row)
        need(value not in out,message)
        out[value] = row
    return out

def audit_snapshot(tables, keys, context):
    """Raises on a violated invariant; returns a compact independently derived projection."""
    required = {'roots','mandates','reservations','business_effects','receipts','transitions','demo_records'}
    need(required <= set(tables), 'missing SQL tables')
    roots = _unique(tables['roots'],lambda r:(r['tenant_id'],r['root_mandate_id']),'duplicate root')
    mandates = _unique(tables['mandates'],lambda r:(r['tenant_id'],r['mandate_id']),'duplicate mandate')
    reservations = _unique(tables['reservations'],_key,'duplicate reservation operation')
    effects = _unique(tables['business_effects'],_key,'duplicate effect operation')
    receipts = _unique(tables['receipts'],_key,'duplicate receipt operation')
    consumer = _unique(tables['demo_records'],_key,'duplicate consumer callback/effect')
    transitions = {}
    for row in tables['transitions']:
        root_key = row['tenant_id'],row['root_mandate_id']
        need(root_key in roots,'transition missing root')
        transitions.setdefault(root_key,[]).append(row)
    for root_key, root in roots.items():
        history = sorted(transitions.get(root_key,[]),key=lambda r:u64(r['state_revision']))
        revisions = [u64(x['state_revision']) for x in history]
        need(revisions==list(range(1,len(history)+1)), 'noncontiguous transition revisions')
        need(u64(root['state_revision'])==len(history),'root revision does not equal durable history')
        need(bool(history) and history[0]['event']=='ROOT_REGISTERED','missing initial root event')
        need(all(x['event'] in EVENTS for x in history),'unknown durable transition event')
        need(u64(root['authority_epoch'])==sum(x['event']=='REVOKED' for x in history),'authority epoch/revocation history')
        policy = decoded(root['policy_json'])
        need(type(policy) is dict and set(policy)=={'budgets','forbidden_sets'},'policy fields')
        budget = quantities(policy['budgets'])
        total = dict.fromkeys(budget,0)
        facts = set()
        for key,reservation in reservations.items():
            if key[:2]!=root_key:
                continue
            if reservation['state'] in CHARGED|{'RESERVED'}:
                cost = quantities(decoded(reservation['cost_json']))
                total = {d:total[d]+cost[d] for d in total}
                facts.update(decoded(reservation['facts_json']))
        need(all(total[d]<=budget[d] for d in total),'consumed plus active reserved exceeds root budget')
        for forbidden in policy['forbidden_sets']:
            need(not set(forbidden)<=facts,'forbidden committed/reserved fact composition')
    bodies = {}
    for key,row in mandates.items():
        claims = verify_jws(row['jws'],keys['KI'],typ='zti-mandate+jwt',kid=context['mandate_kid'],issuer=context['mandate_issuer'],audience=context['registry_id'])
        body = decoded(row['body_json'])
        need(type(body) is dict and set(body)==BODY_FIELDS,'mandate body fields')
        need(claims.get('zti_mandate')==body and action_hash(body)==row['mandate_hash'],'mandate signature/body/hash linkage')
        start,end = body['valid_from'],body['valid_until']
        need(type(start) is int and type(end) is int and 0<=start<end<=9007199254740991,'mandate date domain')
        need(type(claims.get('iat')) is int and type(claims.get('nbf')) is int and type(claims.get('exp')) is int,'JWS date types')
        need(0<=claims['iat']<=claims['nbf']<claims['exp']<=9007199254740991,'mandate JWS date ordering')
        need(claims['nbf']==start and claims['exp']==end and claims['sub']==body['delegatee_id'],'mandate JWS context linkage')
        need(body['tenant_id']==row['tenant_id'] and body['mandate_id']==row['mandate_id'] and body['root_mandate_id']==row['root_mandate_id'],'mandate SQL identity')
        root_key = row['tenant_id'],row['root_mandate_id']
        need(root_key in roots,'mandate missing root')
        need(action_hash(decoded(roots[root_key]['policy_json']))==body['policy_hash'],'mandate root policy hash')
        quantities(body['constraints']['action_caps'])
        need(set(body['constraints'])=={'allowed_executors','allowed_resources','allowed_methods','allowed_tools','action_caps'},'closed constraint fields')
        bodies[key] = body
    for key,body in bodies.items():
        seen = set()
        current = body
        while current['parent_id'] is not None:
            parent_key = key[0],current['parent_id']
            need(parent_key in bodies and parent_key not in seen,'lineage missing/cyclic')
            seen.add(parent_key)
            parent = bodies[parent_key]
            need(current['parent_hash']==action_hash(parent),'child parent hash')
            need(parent['valid_from']<=current['valid_from']<current['valid_until']<=parent['valid_until'],'child widens dates')
            for field in ('tenant_id','root_mandate_id','principal_id','correlation_id','policy_hash'):
                need(current[field]==parent[field],'child changes lineage identity')
            for field in ('allowed_executors','allowed_resources','allowed_methods','allowed_tools'):
                need(set(current['constraints'][field])<=set(parent['constraints'][field]),'child widens allowed set')
            pc,cc = quantities(parent['constraints']['action_caps']),quantities(current['constraints']['action_caps'])
            need(all(cc[d]<=pc[d] for d in pc),'child widens cost cap')
            current = parent
    for key,row in reservations.items():
        action = decoded(row['action_json'])
        need(set(action)==ACTION_FIELDS and action_hash(action)==row['action_hash'],'reservation action binding')
        need(tuple(action[x] for x in ('tenant_id','root_mandate_id','operation_id'))==key,'action SQL identity')
        need(action['profile']=='zti-mcp/0.1' and action['method']=='tools/call' and action['tool_name']=='demo.add_record' and action['tool_revision']=='1','action profile/tool')
        need(action['executor_id']==context['executor_id'] and action['resource_id']==context['resource_id'],'configured executor/resource')
        cost,facts = demo_effect(action['arguments'])
        need(decoded(row['cost_json'])==cost and decoded(row['facts_json'])==facts,'recomputed cost/facts differ')
        mandate_key = row['tenant_id'],row['mandate_id']
        need(mandate_key in bodies,'reservation missing mandate')
        body = bodies[mandate_key]
        need(action['mandate_id']==row['mandate_id'],'action/SQL mandate identity')
        ancestor = body
        actual_cost = quantities(cost)
        while True:
            constraints = ancestor['constraints']
            for field,allowed in (('executor_id','allowed_executors'),('resource_id','allowed_resources'),('method','allowed_methods'),('tool_name','allowed_tools')):
                need(action[field] in constraints[allowed],'accepted action outside lineage allowed set')
            cap = quantities(constraints['action_caps'])
            need(all(actual_cost[d]<=cap[d] for d in cap),'accepted action exceeds lineage cap')
            if ancestor['parent_id'] is None:
                break
            ancestor = bodies[(row['tenant_id'],ancestor['parent_id'])]
        need(body['delegatee_id']==row['subject'] and row['audience']==context['executor_id'],'reservation subject/audience')
        claims = verify_jws(row['ict_jws'],keys['KP'],typ='zti-ict+jwt',kid=context['permit_kid'],issuer=context['permit_issuer'],audience=context['executor_id'])
        need(decoded(row['ict_claims_json'])==claims,'stored ICT claims/JWS mismatch')
        need(claims['sub']==row['subject'],'ICT subject')
        need(all(type(claims.get(f)) is int for f in ('iat','nbf','exp')),'ICT date types')
        need(0<=claims['iat']<=claims['nbf']<claims['exp']<=min(claims['iat']+60,body['valid_until']),'ICT lifetime')
        need(claims['nbf']>=body['valid_from'],'ICT issued before current lineage validity')
        zti = claims['zti']
        expected = {'tenant_id':row['tenant_id'],'root_mandate_id':row['root_mandate_id'],'mandate_id':row['mandate_id'],'operation_id':row['operation_id'],'reservation_id':row['reservation_id'],'action_hash':row['action_hash'],'mandate_hash':action_hash(body),'policy_hash':body['policy_hash'],'correlation_id':body['correlation_id'],'cost_bounds':cost,'facts':facts,'profile':'zti-mcp/0.1','mode':'current-online'}
        need(all(zti.get(f)==v for f,v in expected.items()),'ICT bound fields')
        need(set(zti)==set(expected)|{'authority_epoch'},'closed ICT extension claim fields')
        u64(zti['authority_epoch'])
        need(row['state'] in CHARGED|{'RESERVED','CANCELLED','EXPIRED','REVOKED'},'unknown reservation state')
        committed = row['state'] in CHARGED
        need((key in effects)==committed and (key in receipts)==committed and (key in consumer)==committed,'effect/charge/receipt/consumer cardinality')
        if committed:
            effect, receiptrow, business = effects[key],receipts[key],consumer[key]
            for f in ('reservation_id','mandate_id','action_hash','cost_json','facts_json','action_json'):
                same=decoded(effect[f])==decoded(row[f]) if f.endswith('_json') else effect[f]==row[f]
                need(same,'effect/reservation linkage '+f)
            need(decoded(effect['arguments_json'])==action['arguments'],'effect arguments')
            for field in ('tenant_id','root_mandate_id','operation_id','reservation_id','mandate_id','action_hash'):
                need(business[field]==row[field],'consumer linkage '+field)
            args = action['arguments']
            need(business['quantity']==args['quantity'] and business['label']==args['label'] and decoded(business['tags_json'])==args['tags'],'consumer actual effect differs from authorized arguments')
            receipt = decoded(receiptrow['receipt_json'])
            need(set(receipt)==RECEIPT_FIELDS,'receipt fields')
            need(receipt['profile']=='zti-mcp/0.1' and receipt['effect_boundary']=='resource-mutation' and receipt['status']=='COMMITTED','receipt status/boundary')
            for field in ('tenant_id','root_mandate_id','operation_id','reservation_id','mandate_id','action_hash'):
                need(receipt[field]==row[field],'receipt linkage '+field)
                if field in receiptrow:need(receiptrow[field]==row[field],'receipt SQL linkage '+field)
            need(type(business['provider_pid']) is int and business['provider_pid']==effect['provider_pid'],'actual consumer/provider effect PID differs')
            need(receipt['state_revision']==receiptrow['state_revision'],'receipt revision')
            history = transitions[key[:2]]
            matching = [r for r in history if r['event']=='COMMITTED' and r['operation_id']==row['operation_id']]
            need(len(matching)==1 and matching[0]['state_revision']==receipt['state_revision'],'commit transition/receipt linkage')
    need(set(effects)==set(consumer)==set(receipts),'orphan business/consumer/receipt')
    need(set(effects)<=set(reservations),'orphan effect without reservation')
    # A separate state walk derives authority from ordered durable transitions.
    # Revocation after a commit retains that commit; the inverse order cannot
    # authorize a new effect. It catches M05 even if its final totals balance.
    for root_key, history in transitions.items():
        revoked = set()
        committed = set()
        cancelled = set()
        admitted = set()
        registered = set()
        epoch = 0
        for event in sorted(history,key=lambda x:u64(x['state_revision'])):
            operation = event['operation_id']
            kind = event['event']
            if kind in ('ROOT_REGISTERED','CHILD_REGISTERED'):
                mandate=decoded(event['detail_json'])['mandate_id']
                need(mandate not in registered and (root_key[0],mandate) in bodies,'model missing/duplicate mandate registration')
                body=bodies[(root_key[0],mandate)]
                need((body['parent_id'] is None)==(kind=='ROOT_REGISTERED'),'registration event/body role mismatch')
                if body['parent_id'] is not None:
                    need(body['parent_id'] in registered,'child registered before parent')
                registered.add(mandate)
            elif kind=='REVOKED':
                mandate=decoded(event['detail_json'])['mandate_id']
                need(mandate in registered and mandate not in revoked,'model unknown/duplicate revoke transition')
                revoked.add(mandate)
                epoch+=1
            elif kind=='RESERVED':
                need(operation not in admitted,'model duplicate admission transition')
                row=reservations[(*root_key,operation)]
                need(row['mandate_id'] in registered,'model admission before mandate registration')
                need(u64(decoded(row['ict_claims_json'])['zti']['authority_epoch'])==epoch,'model permit epoch differs at admission')
                admitted.add(operation)
            elif kind=='CANCELLED':
                need(operation in admitted and operation not in committed and operation not in cancelled,'model invalid cancellation transition')
                cancelled.add(operation)
            elif kind=='COMMITTED':
                need(operation in admitted and operation not in committed and operation not in cancelled,'model invalid commit transition')
                row = reservations[(*root_key,operation)]
                need(u64(decoded(row['ict_claims_json'])['zti']['authority_epoch'])==epoch,'model stale permit epoch at commit')
                body = bodies[(root_key[0],row['mandate_id'])]
                while True:
                    need(body['mandate_id'] not in revoked,'model effect committed after lineage revocation')
                    if body['parent_id'] is None:
                        break
                    body = bodies[(root_key[0],body['parent_id'])]
                committed.add(operation)
        need(registered=={b['mandate_id'] for (tenant,_),b in bodies.items() if tenant==root_key[0] and b['root_mandate_id']==root_key[1]},'registered mandate SQL/history mismatch')
    return {'roots':len(roots),'mandates':len(mandates),'reservations':len(reservations),'effects':len(effects),'consumer_rows':len(consumer),'receipts':len(receipts),'transitions':len(tables['transitions']),
            'states':{k[2]:r['state'] for k,r in sorted(reservations.items())},
            'root_revisions':{k[1]:r['state_revision'] for k,r in sorted(roots.items())}}

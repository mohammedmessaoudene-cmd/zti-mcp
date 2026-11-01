"""Derive contract projections independently from raw exported SQL rows."""
from collections import Counter
from primitives import canonical, decoded
from state import CHARGED, need, quantities

def vector(amount):
    return {'ops':{'unit':'operation','amount':str(amount['ops'])},'bytes':{'unit':'byte','amount':str(amount['bytes'])}}

def projection(tables):
    roots=tables['roots']
    need(len(roots)<=1,'bounded fixture must have at most one root')
    states=Counter(r['state'] for r in tables['reservations'])
    consumed={'ops':0,'bytes':0};reserved=dict(consumed)
    possible=set();committed=set()
    for row in tables['reservations']:
        if row['state'] in CHARGED|{'RESERVED'}:
            target=reserved if row['state']=='RESERVED' else consumed
            for key,value in quantities(decoded(row['cost_json'])).items():target[key]+=value
            facts=decoded(row['facts_json']);possible.update(facts)
            if row['state'] in CHARGED:committed.update(facts)
    root=roots[0] if roots else None
    result={'state_revision':root['state_revision'] if root else '0',
            'reservation_states':{k:states.get(k,0) for k in ('RESERVED','COMMITTED','CANCELLED')},
            'consumed':vector(consumed),'reserved':vector(reserved),
            'business_rows':len(tables['demo_records']),'receipts':len(tables['receipts']),
            'authority_epoch':root['authority_epoch'] if root else '0',
            'mandates':len(tables['mandates']),'roots':len(roots),
            'committed_facts':sorted(committed),'possible_facts':sorted(possible),
            'committed_receipt_revisions_multiset':sorted([decoded(x['receipt_json'])['state_revision'] for x in tables['receipts']],key=int),
            'leafA_revoked':any(x['mandate_id'].endswith('0000000000000000000000000000000a') and x['revoked']==1 for x in tables['mandates'])}
    return result

def compare_projection(actual, expected, *, observation=None):
    """Compare declared projections; special causal assertions are handled elsewhere."""
    special={'receipt_equality','callback_insert_count'}
    for field,value in expected.items():
        if field in special:continue
        need(field in actual,'unknown frozen projection field '+field)
        need(canonical(actual[field])==canonical(value),'frozen projection differs: '+field)

def immutable_history(previous, current):
    for name in ('receipts','business_effects','demo_records'):
        def key(row):return row['tenant_id'],row['root_mandate_id'],row['operation_id']
        old={key(r):r for r in previous[name]};new={key(r):r for r in current[name]}
        for identity,row in old.items():
            need(identity in new and canonical(new[identity])==canonical(row),'historical '+name+' deleted/changed')
    old={r['operation_id']:r for r in previous['reservations']}
    new={r['operation_id']:r for r in current['reservations']}
    for operation,row in old.items():
        need(operation in new,'historical reservation deleted')
        for field in row:
            if field!='state':need(canonical(row[field])==canonical(new[operation][field]),'historical reservation binding changed')
        if row['state'] in CHARGED:
            need(new[operation]['state']==row['state'],'historical consumed state changed')
    oldhistory={r['state_revision']:r for r in previous['transitions']}
    newhistory={r['state_revision']:r for r in current['transitions']}
    for revision,row in oldhistory.items():
        need(revision in newhistory and canonical(row)==canonical(newhistory[revision]),'durable history rewritten')

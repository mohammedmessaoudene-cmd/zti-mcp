"""Structural activation witnesses, separate from the unchanged ordinary audit.

A failed import, timeout, flag or parser error is never a detection witness.
"""
import json
from pathlib import Path
from evidence_io import snapshot
from causality import audit_causality
from input_contract import request_input
from primitives import canonical, decoded
from state import need
from wire import audit_wire, jsonl, safe_child

def audit_mutant(case_dir, ordinary_report, corpus):
    case_dir=Path(case_dir)
    manifest=json.loads((case_dir/'manifest.json').read_text(encoding='utf-8'))
    observations=json.loads((case_dir/'observation.json').read_text(encoding='utf-8'))
    name=manifest['mutant_id']
    need(name in {'M02','M03','M04','M05','M06'},'unknown provider mutation')
    need(ordinary_report['status']=='VIOLATION','mutant not rejected by the ordinary semantic oracle')
    expected_reasons={'M02':('effect arguments','consumer actual effect differs'),'M03':('effect/charge/receipt/consumer cardinality',),'M04':('duplicate consumer callback/effect',),'M05':('model stale permit epoch at commit','model effect committed after lineage revocation'),'M06':('forbidden committed/reserved fact composition',)}
    need(any(text in ordinary_report.get('reason','') for text in expected_reasons[name]),'ordinary mutant rejection did not identify the intended violated property')
    need(not observations['infrastructure_errors'],'infrastructure failure is not mutant detection')
    events=[]
    for connection in observations['connections']:
        lifecycle=jsonl(safe_child(case_dir,connection['lifecycle']))
        starts=[e for e in lifecycle if e['type']=='provider_start']
        exits=[e for e in lifecycle if e['type']=='provider_exit']
        need(len(starts)==len(exits)==1 and exits[0]['returncode']==0,'targeted provider mutant requires normal process termination')
        for index,event in enumerate(jsonl(safe_child(case_dir,connection['provider_events']))):
            need(event.get('provider_pid')==starts[0]['provider_pid'] and event.get('endpoint_instance_id')==connection['endpoint_instance_id'],'mutant producer identity differs from observed process')
            events.append({**event,'_index':index,'_event_index':index,'_connection':connection['connection']})
    def checkpoint(label):
        found=[x for x in observations['checkpoints'] if x['label']==label]
        need(len(found)==1,'mutant required checkpoint missing '+label)
        return snapshot(safe_child(case_dir,found[0]['database']))
    final=checkpoint('final')
    need(manifest.get('context')==corpus['context']['key_contexts'],'mutant trust context differs')
    wire=audit_wire(case_dir,observations,final,manifest['public_keys'],manifest['context'],corpus['tool']['input_schema'])
    need(bool(wire['totals']['frames']) and len(wire['processes'])==len(observations['connections']),'mutant actual SDK capture/lifecycle missing')
    causal=audit_causality(manifest,observations,events,wire,corpus,[],structural_only=True)
    def rows(value):return {table:sorted(canonical(r).decode('utf-8') for r in records) for table,records in value.items()}
    need(rows(snapshot(case_dir/'provider.sqlite'))==rows(final),'mutant stopped-writer database differs from final checkpoint')
    frozen=next(m for m in corpus['mutants'] if m['id']==name)
    witness_id=frozen['witness']
    spec=next(s for s in corpus['histories' if witness_id.startswith('I') else 'causal_plans'] if s['id']==witness_id)
    fixtures=json.loads((case_dir/'fixtures.json').read_text(encoding='utf-8'))
    for alias in ('root','leafA','leafB'):
        sid='bootstrap.'+alias
        request_input({'id':sid,'method':'org.example/zti-mcp.register','args':{'mandate_ref':alias}},observations['steps'][sid],corpus,spec,observations['steps'],manifest['public_keys'],fixtures)
    def rpc_specs(steps):
        for step in steps:
            if step['kind']=='rpc':yield step
            elif step['kind']=='start_async':yield from rpc_specs([step['step']])
            elif step['kind']=='concurrent_group':yield from rpc_specs(step['steps'])
    if witness_id.startswith('I'):
        for step in rpc_specs(spec['steps']):
            request_input(step,observations['steps'][step['id']],corpus,spec,observations['steps'],manifest['public_keys'],fixtures)
    markers=[e for e in events if e.get('event')=='mutant:'+name]
    need(bool(markers),'actual mutation branch marker missing')
    for marker in markers:
        key=marker['endpoint_instance_id'],json.dumps(marker.get('request_id'),sort_keys=True)
        need(key in wire['pairs'] and wire['pairs'][key]['provider_pid']==marker['provider_pid'],'mutation activation is not tied to an actual SDK request/process')
    witness={}
    if name=='M02':
        need(len(final['demo_records'])==1 and final['demo_records'][0]['label']=='bravo','M02 callback mutation did not reach the real business row')
        need(decoded(final['reservations'][0]['action_json'])['arguments']['label']=='alpha','M02 original authorized action was not alpha')
        marker=markers[0]
        original=decoded(final['reservations'][0]['action_json'])
        changed={**original,'arguments':{**original['arguments'],'label':'bravo'}}
        import hashlib
        need(marker.get('original_action_hash')==hashlib.sha256(canonical(original)).hexdigest() and marker.get('final_action_hash')==hashlib.sha256(canonical(changed)).hexdigest(),'M02 activation hashes do not describe the frozen mutation')
        same=[e for e in events if e['endpoint_instance_id']==marker['endpoint_instance_id'] and canonical(e.get('request_id'))==canonical(marker.get('request_id'))]
        validated=[e['_index'] for e in same if e.get('event')=='call:validated']
        inserted=[e['_index'] for e in same if e.get('event')=='call:business_inserted' and 'stage' not in e]
        need(bool(validated) and bool(inserted) and min(validated)<marker['_index']<max(inserted),'M02 did not mutate between completed validation and callback INSERT')
        witness={'authorized_label':'alpha','actual_business_label':'bravo','consumer_rows':1,'callback_reached':True}
    elif name=='M03':
        state=checkpoint('after_rollback')
        need(len(state['demo_records'])==1 and not state['business_effects'] and not state['receipts'],'M03 has no durable orphan consumer INSERT')
        need(len(state['reservations'])==1 and state['reservations'][0]['state']=='RESERVED' and state['roots'][0]['state_revision']=='4','M03 changed charge/revision rather than isolating business commit')
        commits=[e for e in events if e.get('event')=='mutant:M03_business_commit']
        need(bool(commits) and observations['steps']['bad'].get('error',{}).get('data',{}).get('reason')=='EXECUTION_FAILED','M03 durable business commit/fault path not reached')
        bad=observations['steps']['bad']
        committed=[e for e in commits if e['endpoint_instance_id']==bad['endpoint_instance_id'] and canonical(e.get('request_id'))==canonical(bad['request_id'])]
        need(len(committed)==1 and committed[0].get('table')=='demo_records' and committed[0].get('row_id')==state['demo_records'][0]['row_id'] and committed[0]['provider_pid']==state['demo_records'][0]['provider_pid'],'M03 durable orphan does not match the actual failed request INSERT')
        raised=[e for e in events if e['endpoint_instance_id']==bad['endpoint_instance_id'] and canonical(e.get('request_id'))==canonical(bad['request_id']) and e.get('event')=='call:business_inserted' and e.get('stage')=='raised']
        need(len(raised)==1 and committed[0]['_index']<raised[0]['_index'],'M03 callback fault did not follow the separate business commit')
        witness={'checkpoint':'after_rollback','orphan_business_rows':1,'receipts':0,'reservation':'RESERVED','root_revision':'4'}
    elif name=='M04':
        rows=final['demo_records']
        need(len(rows)==2 and len({r['operation_id'] for r in rows})==1 and len({r['row_id'] for r in rows})==2,'M04 duplicate callback is not observable as two durable rows')
        need(len(final['business_effects'])==len(final['receipts'])==1 and final['roots'][0]['state_revision']=='5','M04 did not isolate duplicate callback from original immutable charge/receipt')
        need(final['reservations'][0]['state']=='COMMITTED','M04 original operation not consumed')
        witness={'same_operation_consumer_rows':2,'distinct_row_ids':[r['row_id'] for r in rows],'historical_receipts':1,'root_revision':'5'}
    elif name=='M05':
        need(len(final['demo_records'])==1 and len(final['receipts'])==1,'M05 did not actually commit a business effect')
        marker=markers[0]
        own=[e for e in events if e['endpoint_instance_id']==marker['endpoint_instance_id'] and canonical(e.get('request_id'))==canonical(marker.get('request_id'))]
        finished=[e for e in own if e.get('event')=='call:validation_transaction_finished']
        arrived=[e for e in own if e.get('event')=='call:pause_after_validation' and e.get('stage')=='arrived']
        released=[e for e in own if e.get('event')=='call:pause_after_validation' and e.get('stage')=='released']
        inserted=[e for e in own if e.get('event')=='call:business_inserted' and 'stage' not in e]
        need(len(finished)==len(arrived)==len(released)==1 and bool(inserted),'M05 required completed-check/pause/release/callback events missing')
        need(finished[0]['_index']<arrived[0]['_index']<released[0]['_index']<min(e['_index'] for e in inserted),'M05 provider-local order does not isolate stale authorization')
        journal=observations['events']
        hook=[e for e in journal if e.get('kind')=='hook_observed' and e.get('provider_event_index')==arrived[0]['_index'] and e.get('endpoint_instance_id')==marker['endpoint_instance_id']]
        release=[e for e in journal if e.get('kind')=='release_written' and e.get('rule_id')==arrived[0]['rule_id']]
        revoke=[e for e in journal if e.get('kind')=='request_observed' and e.get('step')=='revoke']
        need(len(hook)==len(release)==len(revoke)==1 and hook[0]['sequence']<revoke[0]['sequence']<release[0]['sequence'],'M05 revoke response not causally between actual pause arrival and release')
        need(observations['steps']['revoke'].get('result',{}).get('status')=='REVOKED','M05 revoke did not return committed authority change')
        after=checkpoint('after_revocation_before_release')
        need(not after['demo_records'] and any(r['revoked']==1 for r in after['mandates']),'M05 authority change checkpoint absent before effect')
        history=sorted(final['transitions'],key=lambda r:int(r['state_revision']))
        revoked=[i for i,r in enumerate(history) if r['event']=='REVOKED'];committed=[i for i,r in enumerate(history) if r['event']=='COMMITTED']
        need(len(revoked)==len(committed)==1 and revoked[0]<committed[0],'M05 durable effect did not follow committed revocation')
        witness={'validation_transaction_finished_before_pause':True,'revocation_ack_before_release':True,'revocation_checkpoint_effects':0,'final_effects_after_revocation':1,'cross_process_timestamp_sort_used':False}
    else:
        state=checkpoint('after_admission')
        rows=state['reservations']
        need(len(rows)==2 and all(r['state']=='RESERVED' for r in rows),'M06 did not admit two held commitments')
        facts=set().union(*(set(decoded(r['facts_json'])) for r in rows))
        need({'red','blue'}<=facts and not state['demo_records'] and not state['receipts'],'M06 required admission-only composition violation not present')
        actual_ids={r['reservation_id'] for r in rows}
        need(any(e.get('omitted_reservations') and set(e['omitted_reservations'])<=actual_ids and all(r['operation_id']!=e.get('operation_id') for r in rows if r['reservation_id'] in e['omitted_reservations']) for e in markers),'M06 did not activate omission of another actual reservation')
        actions={canonical(s['request']['params']['action']) for s in observations['steps'].values() if s['method']=='org.example/zti-mcp.reserve'}
        need(actions=={canonical(corpus['action_templates'][a]) for a in ('red','blue')},'M06 admissions differ from frozen red/blue actors')
        try:audit_causality(manifest,observations,events,wire,corpus,[])
        except ValueError as error:
            need(str(error)=='prescribed losing admission did not refuse cumulatively','M06 actual selected overlap failed for another reason')
        else:raise ValueError('M06 did not diverge at the prescribed second admission')
        witness={'simultaneous_reserved_commitments':2,'forbidden_facts':sorted(facts),'business_effects_required':False,'observed_business_effects':0}
    return {'status':'DETECTED','mutant':name,'ordinary_semantic_rejection':ordinary_report['reason'],'activation_witness':witness,'wire':wire['totals'],'causal_structure':causal,'infrastructure_error_is_detection':False}

"""Selected schedule assertions from correlated wire, producer and coordinator data.

No cross-process timestamp sorting supplies a causal edge here.
"""
import json
from primitives import b64, canonical, decoded
from state import need

def audit_causality(manifest, observations, producer_events, wire, corpus, checkpoint_projections, *, structural_only=False):
    journal=observations['events'];steps=observations['steps']
    need([e['sequence'] for e in journal]==list(range(1,len(journal)+1)),'noncontiguous coordinator causal journal')
    def event_index(kind, *, step=None, rule=None, label=None):
        matches=[e['sequence'] for e in journal if e.get('kind')==kind and (step is None or e.get('step')==step) and (rule is None or e.get('rule_id')==rule) and (label is None or e.get('label')==label)]
        need(len(matches)==1,'missing/duplicate causal event '+kind+' '+str(step or rule or label))
        return matches[0]
    def source_event(observed):
        found=[e for e in producer_events if e['_connection']==observed['connection'] and e['_event_index']==observed['provider_event_index'] and e.get('endpoint_instance_id')==observed['endpoint_instance_id']]
        need(len(found)==1,'observed causal event missing from producer capture')
        source=found[0]
        need(source.get('event')==observed['event'],'observed event type differs from producer')
        key=(observed['endpoint_instance_id'],json.dumps(source.get('request_id'),sort_keys=True))
        need(key in wire['pairs'] and source.get('provider_pid')==wire['pairs'][key]['provider_pid'],'observed producer PID/request is not the actual wire provider')
        return source
    def observation_of_hook(step_id, hook):
        step=steps[step_id]
        found=[]
        for e in journal:
            if e.get('kind')!='hook_observed' or e.get('event')!=hook:continue
            source=source_event(e)
            if source.get('endpoint_instance_id')==step['endpoint_instance_id'] and canonical(source.get('request_id'))==canonical(step['request_id']):
                need(source.get('stage')=='arrived','barrier hook did not actually arrive')
                found.append((e,source))
        need(len(found)==1,'actual request-correlated barrier arrival missing '+step_id)
        return found[0]
    def observe_commit(step_id, hook):
        found=[e for e in journal if e.get('kind')=='commit_observed' and e.get('step')==step_id and e.get('event')==hook]
        need(len(found)==1,'actual postcommit observation missing '+step_id)
        e=found[0];source=source_event(e);step=steps[step_id]
        need(canonical(source.get('request_id'))==canonical(step['request_id']) and source.get('endpoint_instance_id')==step['endpoint_instance_id'],'commit observation is not tied to actual MCP request')
        return e['sequence']
    def overlap(ids,hook,ordered=None):
        need(len(ids)==2 and len(set(ids))==2,'overlap requires two distinct RPC requests')
        arrivals={step_id:observation_of_hook(step_id,hook) for step_id in ids}
        releases={step_id:event_index('release_written',rule=arrivals[step_id][0]['rule_id']) for step_id in ids}
        first_release=min(releases.values())
        processes=set()
        for step_id in ids:
            step=steps[step_id];entry,source=arrivals[step_id]
            pair=wire['pairs'][(step['endpoint_instance_id'],json.dumps(step['request_id'],sort_keys=True))]
            need(source.get('provider_pid')==pair['provider_pid'],'barrier PID differs from actual wire provider')
            processes.add(pair['provider_pid'])
            need(event_index('request_dispatched',step=step_id)<entry['sequence']<first_release,'both actual requests did not arrive before any release')
            need(releases[step_id]<event_index('request_observed',step=step_id),'RPC response predates its barrier release')
        need(len(processes)==2,'selected overlap must use distinct actual provider processes')
        if ordered:
            winner,loser=ordered
            need(set(ordered)==set(ids),'ordered overlap actor set')
            need(releases[winner]<event_index('request_observed',step=winner)<releases[loser],'loser released before winner response')
            committed=observe_commit(winner,'reserve:commit' if hook.startswith('reserve:') else 'call:commit')
            need(releases[winner]<committed<releases[loser],'winner commit not observed before loser release')
        return {'steps':ids,'hook':hook,'actual_provider_processes':2,'both_arrived_before_first_release':True,'ordered':ordered}
    history=manifest.get('history_id');plan=manifest.get('plan_id');category=manifest['category']
    evidence=[]
    for entry in journal:
        if entry.get('kind') in ('hook_observed','commit_observed'):
            source=source_event(entry)
            for field in ('stage','rule_id'):
                if field in entry:need(entry[field]==source.get(field),'journal hook field differs from producer '+field)
            if entry.get('step') is not None:
                step=steps[entry['step']]
                need(source.get('endpoint_instance_id')==step['endpoint_instance_id'] and canonical(source.get('request_id'))==canonical(step['request_id']),'journal source differs from indexed actual RPC')
    for step_id,step in steps.items():
        dispatched=[e for e in journal if e.get('kind')=='request_dispatched' and e.get('step')==step_id]
        observed=[e for e in journal if e.get('kind')=='request_observed' and e.get('step')==step_id]
        need(len(dispatched)==len(observed)==1,'each indexed RPC needs exactly one dispatch and response observation')
        sent,received=dispatched[0],observed[0]
        need(sent['sequence']<received['sequence'],'RPC observed before dispatch')
        need(sent.get('endpoint_instance_id')==step['endpoint_instance_id'] and sent.get('connection')==step['connection'],'dispatch journal endpoint differs from actual RPC')
        pair=wire['pairs'][(step['endpoint_instance_id'],json.dumps(step['request_id'],sort_keys=True))]
        expected_outcome='expected_fault' if 'response' not in pair else ('result' if 'result' in pair['response'] else 'error')
        need(canonical(received.get('request_id'))==canonical(step['request_id']) and received.get('wire_sequence')==pair.get('response_sequence') and received.get('outcome')==expected_outcome and received.get('connection')==step['connection'],'RPC observation journal differs from raw request/response identity')
    saved={}
    for checkpoint in observations['checkpoints']:
        label=checkpoint['label']
        need(label not in saved,'duplicate checkpoint label')
        index=event_index('checkpoint_saved',label=label)
        need(checkpoint['event_cursor']==index-1,'checkpoint cursor not anchored to its actual saved event')
        saved[label]=index
    if structural_only:
        return {'structural_journal':'PASS','checkpoints':len(saved),'ordinary_schedule_verdict_performed':False}
    if category=='base':
        spec=next(x for x in corpus['histories'] if x['id']==history)
        for group in spec['steps']:
            if group['kind']=='concurrent_group':
                ids=[s['id'] for s in group['steps']]
                evidence.append(overlap(ids,group['event'],group.get('release_order')))
    if plan in ('C01','C02','C03','C04'):
        admission=[name for name,step in steps.items() if step['method']=='org.example/zti-mcp.reserve']
        need(len(admission)==2,'selected plan requires exactly two admission RPCs')
        winner_alias,loser_alias={'C01':('o1','o2'),'C02':('o2','o1'),'C03':('red','blue'),'C04':('blue','red')}[plan]
        ordered=[]
        for alias in (winner_alias,loser_alias):
            matches=[name for name in admission if canonical(steps[name]['request']['params']['action'])==canonical(corpus['action_templates'][alias])]
            need(len(matches)==1,'causal admission input differs from frozen actor/action')
            ordered.append(matches[0])
        evidence.append(overlap(admission,'reserve:before_transaction',ordered))
        need(steps[ordered[0]].get('result',{}).get('status')=='RESERVED','prescribed admission winner did not reserve')
        error=steps[ordered[1]].get('error',{})
        need(error.get('code')==-31001 and error.get('data')=={'profile':'zti-mcp/0.1','reason':'CUMULATIVE_VIOLATION','status':'REFUSED'},'prescribed losing admission did not refuse cumulatively')
        checkpoint=next((x for x in observations['checkpoints'] if x['label']=='after_admission'),None)
        need(checkpoint is not None,'admission-only durable checkpoint missing')
        need(event_index('request_observed',step=ordered[1])<=checkpoint['event_cursor'],'admission checkpoint precedes losing response')
        if plan in ('C01','C02'):
            calls=[name for name,step in steps.items() if step['method']=='tools/call']
            need(len(calls)==1 and event_index('request_dispatched',step=calls[0])>saved['after_admission'],'winner effect did not follow admission-only checkpoint')
    elif plan in ('C05','C06'):
        ids=[name for name,step in steps.items() if step['method']=='tools/call']
        expected_order=['c1','c2'] if plan=='C05' else ['c2','c1']
        evidence.append(overlap(ids,'call:before_transaction',expected_order))
        values=[steps[x]['result'].get('_meta',{}).get('org.example/zti-mcp') for x in ids]
        need(values[0] is not None and values[0]==values[1],'same-operation overlapping calls returned different receipts')
    if history=='I14' or plan in ('C07','C09'):
        call_id='c1';control_id='cancel' if plan=='C09' else 'revoke'
        hook,source=observation_of_hook(call_id,'call:before_transaction')
        release=event_index('release_written',rule=hook['rule_id'])
        need(event_index('request_dispatched',step=call_id)<hook['sequence']<event_index('request_dispatched',step=control_id),'authority change was not dispatched during the actual pending effect')
        need(event_index('request_observed',step=control_id)<release<event_index('request_observed',step=call_id),'effect not released after authority change response')
        label='after_cancellation_before_release' if plan=='C09' else ('after_revoke_before_release' if history=='I14' else 'after_revocation_before_release')
        checkpoint=next((c for c in observations['checkpoints'] if c['label']==label),None)
        need(checkpoint is not None and event_index('request_observed',step=control_id)<=checkpoint['event_cursor']<release,'current authority SQL checkpoint not taken before effect release')
        need(steps[call_id].get('error',{}).get('data',{}).get('reason')=='REVOKED','pending call not refused after authority change')
        evidence.append({'pending_effect':call_id,'authority_change':control_id,'checkpoint_before_release':label})
    if history in ('I15','I17') or plan in ('C08','C10'):
        control='cancel' if history=='I17' or plan=='C10' else 'revoke'
        call='c1'
        need(event_index('request_observed',step=call)<event_index('request_dispatched',step=control),'authority change did not follow committed effect response')
    if history=='I18' and category=='base':
        bad=steps['bad'];pair=wire['pairs'][(bad['endpoint_instance_id'],json.dumps(bad['request_id'],sort_keys=True))]
        own=[e for e in producer_events if e.get('endpoint_instance_id')==bad['endpoint_instance_id'] and canonical(e.get('request_id'))==canonical(bad['request_id']) and e.get('event')=='call:business_inserted']
        inserted=[e for e in own if 'stage' not in e]
        arrived=[e for e in own if e.get('stage')=='arrived']
        raised=[e for e in own if e.get('stage')=='raised']
        need(len(inserted)==len(arrived)==len(raised)==1,'post-INSERT exception path missing actual INSERT/arrival/raise records')
        need(inserted[0]['_event_index']<arrived[0]['_event_index']<raised[0]['_event_index'],'exception did not follow actual staged business INSERT')
        raw_meta=bad['request']['params']['_meta']['org.example/zti-mcp']
        ict_claims=decoded(b64(raw_meta['ict'].split('.')[1]))['zti']
        for record in own:
            need(record.get('provider_pid')==pair['provider_pid'] and record.get('operation_id')==raw_meta['operation_id'],'post-INSERT fault has wrong provider/request/operation')
            need(record.get('reservation_id')==ict_claims['reservation_id'],'post-INSERT fault has wrong actual reservation')
            need(record.get('table')=='demo_records' and record.get('row_id')==1 and type(record.get('row_id')) is int,'post-INSERT fault has no actual demo table row identifier')
        need(arrived[0].get('rule_id')==raised[0].get('rule_id'),'INSERT fault rule changed between arrival and raise')
        armed=[e for e in journal if e.get('kind')=='rule_armed' and e.get('rule_id')==arrived[0]['rule_id']]
        need(len(armed)==1 and armed[0].get('event')=='call:business_inserted' and armed[0].get('behavior')=='raise','post-INSERT exception not selected by the trusted rule')
        need(event_index('request_observed',step='bad')<saved['after_rollback']<event_index('request_dispatched',step='good'),'rollback SQL checkpoint not between failed INSERT and retry')
        evidence.append({'post_insert_exception':True,'actual_table':'demo_records','actual_staged_row_id':1,'rollback_checkpoint_before_retry':True})
    if plan in ('C11','C12') or history in ('I19','I20'):
        after=next((x for x in checkpoint_projections if x['label']=='after_crash'),None)
        need(after is not None,'durable stopped-writer crash checkpoint missing')
        committed=plan=='C12' or history=='I20';state=after['projection']
        need(state['business_rows']==int(committed) and state['receipts']==int(committed) and state['state_revision']==('5' if committed else '4'),'crash checkpoint does not distinguish before/after commit')
        need(state['reservation_states']['RESERVED']==int(not committed) and state['reservation_states']['COMMITTED']==int(committed),'crash checkpoint reservation state')
        crashed={x['provider_pid'] for x in wire['processes'] if x['exitcode']==86}
        retry_id='retry' if plan in ('C11','C12') or history=='I20' else 'good'
        retry=steps[retry_id]
        pair=wire['pairs'][(retry['endpoint_instance_id'],json.dumps(retry['request_id'],sort_keys=True))]
        need(pair['provider_pid'] not in crashed,'recovery did not use a new observed provider PID')
        checkpoint_sequence=saved['after_crash']
        need(event_index('request_observed',step='crash')<checkpoint_sequence,'crash checkpoint was recorded before actual lost reply')
        prior_ready=[e for e in journal if e.get('kind')=='connection_ready' and e['sequence']<checkpoint_sequence]
        for connection in prior_ready:
            exits=[e for e in journal if e.get('kind')=='bridge_exit' and e.get('endpoint_instance_id')==connection['endpoint_instance_id']]
            need(len(exits)==1 and exits[0]['sequence']<checkpoint_sequence,'a previously ready writer was not stopped before crash checkpoint')
        ready=[e for e in journal if e.get('kind')=='connection_ready' and e.get('endpoint_instance_id')==retry['endpoint_instance_id']]
        need(len(ready)==1 and checkpoint_sequence<ready[0]['sequence']<event_index('request_dispatched',step=retry_id),'recovery process/retry did not follow the stopped-writer checkpoint')
        evidence.append({'crash_checkpoint':after['label'],'effect_committed_before_crash':committed,'new_actual_provider_pid':pair['provider_pid']})
    return {'selected_order_assertions':evidence,'cross_process_timestamp_sort_used':False}

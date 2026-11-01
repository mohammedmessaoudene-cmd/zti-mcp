#!/usr/bin/env python3
"""Audit captured R6 data using this checkout's frozen contract, never pack code."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from cryptography.exceptions import InvalidSignature
from attribution import audit_attribution
from causality import audit_causality
from evidence_io import snapshot
from input_contract import request_input
from primitives import canonical, decoded, verify_jws
from projections import compare_projection, immutable_history, projection
from state import audit_snapshot, need
from wire import audit_wire, jsonl, receipt_of, safe_child
from mutants import audit_mutant
from raw_jws import audit_raw_jws
from synthetic import audit_synthetics
from vectors import audit_vectors, audit_m01

R6=Path(__file__).resolve().parents[1]

def load(path):return json.loads(Path(path).read_text(encoding='utf-8'))
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def frozen():
    seal=load(R6/'preexecution.json')
    for name,expected in seal['files'].items():
        need(sha(R6/name)==expected,'frozen contract changed: '+name)
    implementation=load(R6/'oracle-implementation-seal.json')
    need(implementation.get('format')=='zti-r6-oracle-implementation-seal/1' and implementation.get('status')=='FROZEN_BEFORE_QUALIFICATION','reader implementation is not sealed')
    need(implementation.get('preexecution_sha256')==sha(R6/'preexecution.json'),'reader code seal refers to another frozen contract')
    expected_names={p.relative_to(R6).as_posix() for p in (R6/'oracle').glob('*.py')}|{'ORACLE_IMPLEMENTATION_ERRATA.json','DEPENDENCY_ENTRY_POINTS.json'}
    need(set(implementation['files'])==expected_names,'reader code seal has a different closed file set')
    for name,expected in implementation['files'].items():
        need(sha(R6/name)==expected,'sealed reader implementation changed: '+name)
    return load(R6/'fixtures/scenarios.json'),seal

def rpc_specs(steps):
    result=[]
    for step in steps:
        if step['kind']=='rpc':result.append(step)
        elif step['kind']=='start_async':result.extend(rpc_specs([step['step']]))
        elif step['kind']=='concurrent_group':result.extend(rpc_specs(step['steps']))
    return result

def compare_rpc(step_id, actual, expected, observations):
    if expected.get('state_unchanged') and actual.get('before_revision') is not None:
        need(actual.get('after_revision')==actual['before_revision'],'sequential refusal/retry changed root revision: '+step_id)
    if 'jsonrpc_error' in expected:
        need('error' in actual and 'result' not in actual,'expected refusal missing: '+step_id)
        error=actual['error'];target=expected['jsonrpc_error']
        need(error.get('code')==target['code'] and error.get('data')==target.get('data'),'wrong semantic refusal: '+step_id)
        need(error.get('message')=='ZTI-MCP authorization refused','wrong refusal envelope: '+step_id)
    elif 'transport_outcome' in expected:
        need('transport_outcome' in actual and 'result' not in actual and 'error' not in actual,'expected crash incorrectly classified: '+step_id)
    else:
        need('result' in actual and 'error' not in actual,'expected result missing: '+step_id)
        result=actual['result'];receipt=receipt_of(result)
        if 'status' in expected:
            status=result.get('status',receipt.get('status') if receipt else None)
            need(status==expected['status'],'unexpected result status: '+step_id)
        if 'state_revision' in expected:
            need(result.get('state_revision')==expected['state_revision'],'unexpected response revision: '+step_id)
        for field,getter in (('receipt_equal',receipt_of),('ict_equal',lambda r:r.get('ict'))):
            if field in expected:
                prior=observations[expected[field]]
                need(getter(result) is not None and getter(result)==getter(prior['result']),'retry historical identity differs: '+step_id)

def _canonical_rows(tables):
    return {name:sorted([canonical(row).decode('utf-8') for row in rows]) for name,rows in tables.items()}

def _provider_events(case_dir, observations):
    result=[]
    for connection in observations['connections']:
        path=safe_child(case_dir,connection['provider_events'])
        for index,event in enumerate(jsonl(path)):
            result.append({**event,'_connection':connection['connection'],'_event_index':index})
    return result

def _check_causal_journal(observations, provider_events):
    events=observations.get('events',[])
    sequences=[e['sequence'] for e in events]
    need(sequences==sorted(set(sequences)),'causal coordinator sequence missing/duplicate')
    for event in events:
        if event.get('kind')=='hook_observed':
            matches=[e for e in provider_events if e['_connection']==event['connection'] and e['_event_index']==event['provider_event_index'] and e.get('endpoint_instance_id')==event['endpoint_instance_id']]
            need(len(matches)==1,'causal observed hook missing from actual provider events')
            actual=matches[0]
            for field in ('endpoint_instance_id','event','stage','rule_id'):
                if field in event:need(event[field]==actual.get(field),'causal hook does not match capture '+field)
    return events

def client_matrix(manifest, observations, corpus):
    """Check actual loaded-client labels against the frozen role/generation map."""
    generations={};plan=manifest.get('plan_id');history=manifest.get('history_id')
    for connection in observations['connections']:
        alias=connection['connection'];generations[alias]=generations.get(alias,0)+1
        principal_alias='A' if alias=='A2' else alias
        need(principal_alias in corpus['context']['principals'],'unknown trusted connection alias')
        need(connection['principal']==corpus['context']['principals'][principal_alias],'connection principal differs from frozen trusted launch identity')
        if plan:
            pair=manifest['pair']
            need(type(pair) is str and len(pair)==2 and set(pair)<={'P','T'},'invalid SDK pair')
            if plan in ('C11','C12'):
                need(alias in ('A','admin') and generations[alias]<=(2 if alias=='A' else 1),'unexpected crash matrix connection')
                expected=pair[generations[alias]-1] if alias=='A' else 'P'
            elif plan in ('C07','C08','C09','C10'):
                need(alias in ('A','admin'),'unexpected authority-change matrix connection')
                # Bootstrap is performed by P; the actual authority-changing
                # actor is then reconnected with pair[1] when needed.
                expected=pair[0] if alias=='A' else ('P' if generations[alias]==1 else pair[1])
            else:
                second='A2' if plan in ('C05','C06') else 'B'
                need(alias in ('admin','A',second),'unexpected concurrent matrix connection')
                expected='P' if alias=='admin' else pair[0 if alias=='A' else 1]
        else:
            expected=manifest['client']
            if history=='I08' and alias=='A' and generations[alias]==2:expected='T' if expected=='P' else 'P'
        need(connection['client']==expected,'actual client/role/generation differs from frozen SDK matrix')
    if plan in ('C07','C08','C09','C10'):
        actor='revoke' if plan in ('C07','C08') else 'cancel'
        instance=observations['steps'][actor]['endpoint_instance_id']
        actors=[c for c in observations['connections'] if c['endpoint_instance_id']==instance]
        need(len(actors)==1 and actors[0]['client']==manifest['pair'][1],'actual authority-changing actor differs from frozen second SDK')

def audit_case(case_dir, corpus):
    case_dir=Path(case_dir)
    manifest=load(case_dir/'manifest.json');observations=load(case_dir/'observation.json')
    fixtures=load(case_dir/'fixtures.json')
    need(manifest['format']=='zti-r6-evidence/1','unknown evidence format')
    need(manifest['context']==corpus['context']['key_contexts'],'evidence changed configured trust context')
    keys=manifest['public_keys'];context=manifest['context']
    need(set(keys)=={'KI','KP'} and (keys['KI'].get('x'),keys['KI'].get('y'))!=(keys['KP'].get('x'),keys['KP'].get('y')),'missing or identical signing key roles')
    need(all('d' not in key and key.get('kty')=='EC' and key.get('crv')=='P-256' for key in keys.values()),'private/wrong public keys in evidence')
    need(not observations.get('infrastructure_errors'),'unexpected infrastructure errors retained')
    history_id=manifest.get('history_id') or manifest.get('diagnostic_id') or manifest['case_id'].split('__',1)[0]
    plan_id=manifest.get('plan_id')
    category=manifest['category']
    client_matrix(manifest,observations,corpus)
    specification=next((x for x in corpus['histories'] if x['id']==history_id),None)
    positive_subrun=category=='positive_subrun'
    if positive_subrun:
        need(history_id=='I12' and manifest.get('isolated_fact') in ('red','blue'),'unknown isolated positive subrun')
        fact=manifest['isolated_fact']
        isolated=next(x for x in specification['isolated_positive_subruns'] if x['action']==fact)
        specification={'id':'I12','fixture_overrides':{},'steps':[{'id':'reserve','kind':'rpc','channel':isolated['channel'],'method':'org.example/zti-mcp.reserve','args':{'action_ref':fact},'expect':{'status':'RESERVED'}},{'id':'call','kind':'rpc','channel':isolated['channel'],'method':'tools/call','args':{'action_ref':fact,'ict_from':'reserve:'+fact},'expect':{'status':'COMMITTED'}}],
                       'final':{'state_revision':'5','business_rows':1,'receipts':1,'reservation_states':{'RESERVED':0,'COMMITTED':1,'CANCELLED':0},'authority_epoch':'0','committed_facts':[fact],'possible_facts':[fact]}}
    plan=next((x for x in corpus['causal_plans'] if x['id']==plan_id),None)
    if category=='base':need(specification is not None,'unknown frozen base story')
    if category=='causal':need(plan is not None,'unknown frozen causal plan')
    checkpoints=observations['checkpoints']
    need(bool(checkpoints) and checkpoints[-1]['label']=='final','final durable checkpoint missing')
    all_tables=[];derived=[];previous=None
    for checkpoint in checkpoints:
        tables=snapshot(safe_child(case_dir,checkpoint['database']))
        exported=load(safe_child(case_dir,checkpoint['tables_json']))
        exported=exported.get('tables',exported)
        need(_canonical_rows(tables)==_canonical_rows(exported),'SQLite checkpoint differs from raw exported table JSON')
        model=audit_snapshot(tables,keys,context)
        actual=projection(tables)
        if previous is not None:immutable_history(previous,tables)
        previous=tables;all_tables.append(tables)
        derived.append({'label':checkpoint['label'],'projection':actual,'model':model})
        if specification:
            target=next((x['expect'] for x in specification['steps'] if x['kind']=='checkpoint' and x['id']==checkpoint['label']),None)
            if target:compare_projection(actual,target)
        if plan and checkpoint['label'] in plan.get('checkpoint_expectations',{}):
            compare_projection(actual,plan['checkpoint_expectations'][checkpoint['label']])
    final=all_tables[-1];actual=derived[-1]['projection']
    need(_canonical_rows(snapshot(case_dir/'provider.sqlite'))==_canonical_rows(final),'final stopped-writer database differs from final checkpoint')
    if specification:
        compare_projection(actual,specification['final'])
    elif plan:
        compare_projection(actual,plan['expected'])
    elif category=='date':
        date=next(x for x in corpus['date_diagnostics'] if x['id']==history_id)
        positive=date['expected']=='ACTIVE'
        expected_mandates=(1 if date['target']=='root' else 2) if positive else (0 if date['target']=='root' else 1)
        need(actual['mandates']==expected_mandates and actual['state_revision']==str(expected_mandates),'date diagnostic persisted wrong authority')
    elif category=='regression':
        need(actual['business_rows']==1 and actual['receipts']==1,'malformed identifier prevents valid followup or created extra effect')
    wire=audit_wire(case_dir,observations,final,keys,context,corpus['tool']['input_schema'])
    provider_events=_provider_events(case_dir,observations)
    causal_events=_check_causal_journal(observations,provider_events)
    causal_verdict=audit_causality(manifest,observations,provider_events,wire,corpus,derived)
    if category not in {'date'} and (specification or plan or category=='regression'):
        source_spec=specification or plan or {}
        for alias in ('root','leafA','leafB'):
            step_id='bootstrap.'+alias
            need(step_id in observations['steps'],'required bootstrap register missing '+alias)
            request_input({'id':step_id,'method':'org.example/zti-mcp.register','args':{'mandate_ref':alias}},observations['steps'][step_id],corpus,source_spec,observations['steps'],keys,fixtures)
            compare_rpc(step_id,observations['steps'][step_id],{'status':'ACTIVE'},observations['steps'])
    if specification:
        for step in rpc_specs(specification['steps']):
            need(step['id'] in observations['steps'],'missing required frozen RPC step '+step['id'])
            request_input(step,observations['steps'][step['id']],corpus,specification,observations['steps'],keys,fixtures)
            compare_rpc(step['id'],observations['steps'][step['id']],step['expect'],observations['steps'])
        for step in specification['steps']:
            if step['kind']=='checkpoint':
                need(any(x['label']==step['id'] for x in checkpoints),'required intermediate durable checkpoint missing')
                target=step['expect']
                if 'receipt_equality' in target:
                    values=[receipt_of(observations['steps'][x]['result']) for x in target['receipt_equality']]
                    need(all(x==values[0] for x in values),'concurrent retry receipts differ')
                if 'callback_insert_count' in target:
                    count=sum(e.get('event')=='call:business_inserted' and 'stage' not in e for e in provider_events)
                    need(count==target['callback_insert_count'],'actual callback insert event count differs')
    if category=='date':
        date=next(x for x in corpus['date_diagnostics'] if x['id']==history_id)
        step=observations['steps']['date.target']
        claims=verify_jws(step['request']['params']['mandate'],keys['KI'],typ='zti-mandate+jwt',kid=context['mandate_kid'],issuer=context['mandate_issuer'],audience=context['registry_id'])
        need(all(canonical(claims[field])==canonical(date['jwt'][field]) for field in ('iat','nbf','exp')),'date diagnostic does not isolate the prescribed integer JWS dates')
        body=claims['zti_mandate']
        need(canonical(body['valid_from'])==canonical(date['body_valid_from']) and canonical(body['valid_until'])==canonical(date['body_valid_until']),'date diagnostic changed prescribed body date/type')
        target={'status':'ACTIVE'} if date['expected']=='ACTIVE' else {'jsonrpc_error':{'code':-31001,'data':{'profile':'zti-mcp/0.1','reason':date['expected'],'status':'REFUSED'}}}
        compare_rpc('date.target',step,target,observations['steps'])
        if date['expected']!='ACTIVE':
            before=next(t for c,t in zip(checkpoints,all_tables) if c['label']=='before_target')
            after=next(t for c,t in zip(checkpoints,all_tables) if c['label']=='after_target')
            need(_canonical_rows(before)==_canonical_rows(after),'invalid mandate body date changed durable SQL')
    if category=='regression':
        regression=next(x for x in corpus['malformed_regressions']['cases'] if x['id']==history_id)
        compare_rpc('bad',observations['steps']['bad'],regression['expected'],observations['steps'])
        actual_bad=observations['steps']['bad']['request']['params']['action']
        need(all(canonical(actual_bad[k])==canonical(v) for k,v in regression['override'].items()),'malformed identifier test changed its intended input')
        before=next(t for c,t in zip(checkpoints,all_tables) if c['label']=='after_bad')
        need(projection(before)['state_revision']=='3' and not before['reservations'] and not before['demo_records'],'malformed bound identifier mutated state')
    for connection in observations['connections']:
        ready=[e for e in provider_events if e['_connection']==connection['connection'] and e.get('endpoint_instance_id')==connection['endpoint_instance_id'] and e.get('event')=='endpoint_ready']
        need(len(ready)==1 and ready[0].get('principal')==connection['principal'],'trusted endpoint readiness principal missing/different')
    # Crash classification requires actual process exit and actual fault hook.
    crashed=[x for x in wire['processes'] if x['exitcode']==86]
    crash_event={'I19':'call:staged_before_commit','I20':'call:after_commit','C11':'call:staged_before_commit','C12':'call:after_commit'}.get(plan_id or history_id)
    for process in crashed:
        events=[e for e in provider_events if e.get('endpoint_instance_id')==process['endpoint_instance_id']]
        need(crash_event is not None,'exit86 is not prescribed for this frozen case')
        fault=[e for e in events if e.get('stage')=='process_exit' and e.get('exitcode')==86 and e.get('event')==crash_event]
        need(len(fault)==1,'exit86 has no exact prescribed trusted fault event')
        crash_step=observations['steps'].get('crash')
        need(crash_step is not None and crash_step['endpoint_instance_id']==process['endpoint_instance_id'] and 'transport_outcome' in crash_step and 'result' not in crash_step and 'error' not in crash_step,'expected crash request did not lose its reply')
        need(fault[0].get('request_id')==crash_step['request_id'],'crash hook is not tied to the actual expected MCP request')
    if crash_event is not None:need(len(crashed)==1,'expected process crash missing/duplicated')
    return {'status':'PASS','case_id':manifest['case_id'],'category':category,'history_id':history_id,'plan_id':plan_id,'mutant_id':manifest.get('mutant_id'),'checkpoints':derived,'wire':{k:v for k,v in wire.items() if k!='pairs'},'causality':causal_verdict,'provider_events':len(provider_events),'coordinator_events':len(causal_events),'source_attribution':{'commit':manifest.get('source',{}).get('commit'),'git_status':manifest.get('source',{}).get('git_status'),'declared_freeze_sha256':manifest.get('source',{}).get('preexecution_sha256',manifest.get('source',{}).get('input_sha256',{}).get('successor/r6/preexecution.json')),'notice':'Single-case semantic audit; exact clean source and aggregate qualification are separate gates.'}}

def classify_case(case_dir, corpus):
    try:return audit_case(case_dir,corpus)
    except (ValueError,InvalidSignature) as error:
        return {'status':'VIOLATION','case_id':Path(case_dir).name,'reason':str(error) or 'Invalid ES256 signature'}
    except Exception as error:
        return {'status':'INFRASTRUCTURE_ERROR','case_id':Path(case_dir).name,'reason':type(error).__name__+': '+str(error)}

def guarded(function):
    try:return function()
    except (ValueError,InvalidSignature) as error:
        return {'status':'FAIL','reason':str(error) or 'Invalid ES256 signature'}
    except Exception as error:
        return {'status':'INFRASTRUCTURE_ERROR','reason':type(error).__name__+': '+str(error)}

def audit_campaign(directory, corpus, *, expected_sha=None):
    root=Path(directory)
    paths=sorted((root/'cases').glob('*/*/manifest.json'))
    manifests=[(p.parent,load(p)) for p in paths]
    expected={
        'base':{h['id']+'__'+c for h in corpus['histories'] for c in ('P','T')},
        'causal':{p['id']+'__'+pair for p in corpus['causal_plans'] for pair in ('PP','PT','TP','TT')},
        'date':{d['id']+'__'+c for d in corpus['date_diagnostics'] for c in ('P','T')},
        'regression':{r['id']+'__'+c for r in corpus['malformed_regressions']['cases'] for c in ('P','T')},
        'positive_subrun':{'I12__'+c+'__'+f+'-alone' for c in ('P','T') for f in ('red','blue')},
        'mutant':{m['id']+'__P' for m in corpus['mutants'] if m['id']!='M01'},
        'synthetic':{s['id'] for s in corpus['synthetics']}}
    def inventory():
        actual={key:set() for key in expected}
        for case,manifest in manifests:
            category=case.parent.name
            need(category in expected and manifest['category']==category,'case category/path differs')
            need(manifest['case_id']==case.name,'case identity differs from directory')
            need(case.name not in actual[category],'duplicate aggregate case identity')
            actual[category].add(case.name)
            if category=='causal':need(manifest.get('pair')==case.name.split('__')[1],'causal client matrix identity differs')
            elif category not in {'synthetic'}:need(manifest.get('client')==('P' if category=='mutant' else case.name.split('__')[1]),'actual case client identity differs')
            if category=='mutant':need(manifest.get('mutant_id')==case.name.split('__')[0],'mutant identity differs')
            elif category!='synthetic':need(manifest.get('mutant_id') is None,'ordinary case marked as a mutant')
            prefix=case.name.split('__')[0]
            identity={'history_id':None,'plan_id':None,'diagnostic_id':None}
            if category in {'base','positive_subrun'}:identity['history_id']=prefix
            elif category=='causal':identity['plan_id']=prefix
            elif category=='date':identity['diagnostic_id']=prefix
            elif category=='mutant':
                witness=next(m['witness'] for m in corpus['mutants'] if m['id']==prefix)
                identity['history_id' if witness.startswith('I') else 'plan_id']=witness
            elif category=='synthetic':
                identity['history_id']='I01'
                need(manifest.get('synthetic_id')==case.name and manifest.get('source_case_id')=='I01__P' and manifest.get('actual_sdk_execution') is False,'synthetic origin/identity differs')
            need(all(manifest.get(k)==v for k,v in identity.items()),'case frozen story/plan/diagnostic identity differs from its path')
            if category=='positive_subrun':need(manifest.get('isolated_fact')==case.name.rsplit('__',1)[-1].removesuffix('-alone'),'isolated positive fact differs from its path')
        need(actual==expected,'aggregate case set differs from frozen matrix')
        return {'status':'PASS','counts':{key:len(values) for key,values in actual.items()}}
    checks={'inventory':guarded(inventory)}
    reports={case.relative_to(root).as_posix():classify_case(case,corpus) for case,_ in manifests}
    normal_categories=set(expected)-{'mutant','synthetic'}
    normals={path:r for path,r in reports.items() if path.split('/')[1] in normal_categories}
    checks['ordinary_cases']={'status':'PASS' if len(normals)==112 and all(r['status']=='PASS' for r in normals.values()) else 'FAIL',
        'cases_checked':len(normals),'failures':{p:r for p,r in normals.items() if r['status']!='PASS'}}
    for group,field in [('vectors','binding_vectors'),('binding_auxiliary','binding_diagnostics')]:
        for client in ('P','T'):
            checks[group+'_'+client]=guarded(lambda group=group,field=field,client=client:audit_vectors(root/group/(client+'.json'),corpus[field],client=client))
    mutations={'M01':guarded(lambda:audit_m01(root/'vectors/M01.json',corpus['binding_vectors']))}
    for case,manifest in manifests:
        if manifest['category']=='mutant':
            mutations[manifest['mutant_id']]=guarded(lambda case=case:audit_mutant(case,reports[case.relative_to(root).as_posix()],corpus))
    checks['mutations']={'status':'PASS' if set(mutations)=={m['id'] for m in corpus['mutants']} and all(r['status']=='DETECTED' for r in mutations.values()) else 'FAIL','mutants':mutations}
    synthetic_reports={path.split('/')[-1]:r for path,r in reports.items() if '/synthetic/' in path}
    checks['synthetics']=guarded(lambda:audit_synthetics(root,synthetic_reports,corpus))
    checks['raw_jws']=guarded(lambda:audit_raw_jws(root/'raw_jws',R6/'fixtures/raw_jws.json'))
    checks['exact_source_and_runtime']=guarded(lambda:audit_attribution(root,manifests,expected_sha=expected_sha))
    if (root/'EXPORT_MANIFEST.json').exists():
        def export_integrity():
            export=load(root/'EXPORT_MANIFEST.json');files=export['files']
            actual={p.relative_to(root).as_posix():p for p in root.rglob('*') if p.is_file() and p.name!='EXPORT_MANIFEST.json'}
            need(set(files)==set(actual),'export manifest path set differs from data archive')
            for name,path in actual.items():
                need(files[name]['sha256']==sha(path) and files[name]['size']==path.stat().st_size,'exported file hash/size differs '+name)
            return {'status':'PASS','files':len(files),'notice':'Internal archive consistency, not authenticity.'}
        checks['export_integrity']=guarded(export_integrity)
    passed=all(check['status']=='PASS' for check in checks.values())
    return {'format':'zti-r6-independent-audit/1','status':'PASS' if passed else 'FAIL',
        'preexecution_sha256':sha(R6/'preexecution.json'),'oracle_implementation_seal_sha256':sha(R6/'oracle-implementation-seal.json'),'checks':checks,'cases':reports,
        'separate_counts':{'base_stories':20,'base_sdk_executions':40,'causal_plans':12,'causal_matrix_replays':48,
            'core_binding_vectors_per_sdk':24,'auxiliary_binding_vectors_per_sdk':4,'date_executions':16,
            'malformed_identifier_executions':4,'isolated_positive_I12_executions':4,'mutants':6,
            'synthetic_discovery_copies':3,'synthetic_other_copies':3,'raw_jws_negative_inputs':1,'raw_jws_positive_controls':1,'raw_jws_sdk_executions':0},
        'limits':['One provider, local SQLite business effect, trusted launch/plugin/OS administrator.',
            'Selected finite schedules, not an exhaustive interleaving proof or a security percentage.',
            'Cryptographic/wire/SQL/model readback is separate from provider code; team review is AI-assisted, not outside human reproduction.',
            'Rollback or precommit crash may require a callback retry; only one durable business effect is required for a committed operation.']}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-dir',type=Path)
    parser.add_argument('--evidence-dir',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--expected-source-sha',default=os.environ.get('EXPECTED_SOURCE_SHA'))
    args=parser.parse_args()
    if args.output.exists():raise ValueError('Use a fresh audit report file')
    corpus,seal=frozen()
    if args.case_dir:
        report=classify_case(args.case_dir,corpus)
    elif args.evidence_dir:
        report=audit_campaign(args.evidence_dir,corpus,expected_sha=args.expected_source_sha)
    else:raise ValueError('Supply --case-dir or --evidence-dir')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'status':report['status'],'report':str(args.output)}))
    return 0 if report['status']=='PASS' else 1

if __name__=='__main__':
    raise SystemExit(main())

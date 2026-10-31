#!/usr/bin/env python3
from __future__ import annotations
import argparse, copy, hashlib, json, multiprocessing as mp, os, sys, traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT));sys.dont_write_bytecode=True
from authority import *
import cryptography

CTX=mp.get_context('spawn'); TIMEOUT=25

def invoke(fn,*args,**kw):
    try:return fn(*args,**kw)
    except Fault as e:return {'status':e.code}

def actor_entry(db,mutant,job,args,barrier,wait_event,set_event,pipe):
    try:
        a=Authority(db,mutant)
        pipe.send({'phase':'READY','pid':os.getpid(),'job':job})
        if barrier is not None:barrier.wait(TIMEOUT)
        if wait_event is not None and not wait_event.wait(TIMEOUT):raise RuntimeError('Directed order timeout')
        result=invoke(getattr(a,job),*args)
        if set_event is not None:set_event.set()
        pipe.send({'phase':'RESULT','pid':os.getpid(),'job':job,'result':result})
    except BaseException:
        pipe.send({'phase':'ERROR','pid':os.getpid(),'traceback':traceback.format_exc()});raise
    finally:pipe.close()

def spawn_job(db,mutant,job,args,barrier=None,wait=None,done=None):
    receive,send=CTX.Pipe(duplex=False)
    p=CTX.Process(target=actor_entry,args=(str(db),mutant,job,args,barrier,wait,done,send))
    p.start();send.close();return p,receive

def finish_job(handle,actors):
    p,pipe=handle;messages=[];result=None
    while result is None:
        if not pipe.poll(TIMEOUT):raise RuntimeError('Worker timeout')
        msg=pipe.recv();messages.append(msg)
        if msg['phase']=='ERROR':raise RuntimeError(msg)
        if msg['phase']=='RESULT':result=msg['result']
    p.join(TIMEOUT)
    if p.is_alive() or p.exitcode!=0:raise RuntimeError('Worker exit failure')
    pipe.close();actors.append({'pid':p.pid,'exitcode':p.exitcode,'messages':messages});return result

def drop_ack_worker(db,token,actor,action,pipe):
    pipe.send({'phase':'BEFORE_COMMIT','pid':os.getpid()})
    result=Authority(db).commit(token,actor,action)
    if result['status']!='COMMITTED':raise RuntimeError(result)
    pipe.close()
    os._exit(0)  # Deliberately lose only the client acknowledgement, AFTER durable commit.

def exercise(case,outdir,mutant=None):
    db=outdir/'ledger.sqlite';a=Authority(db,mutant);a.initialize()
    cid=case['id'];trace=[];actors=[];verdicts=[];aux={}
    def call(fn,*args,**kw):
        r=invoke(fn,*args,**kw);trace.append({'method':fn.__name__,'result':r});return r
    def require(r,status):
        if r['status']!=status:raise RuntimeError({'unexpected_setup':r,'required':status})
        return r
    def child(parent,who='agent-b',constraints=None):
        return require(call(a.delegate,parent['mandate_id'],parent['delegatee_id'],who,constraints),'REGISTERED')['mandate']
    def reserve(body,cmd):return require(call(a.reserve,body['mandate_id'],body['delegatee_id'],cmd),'RESERVED')
    def consume(body,cmd):
        r=reserve(body,cmd);return call(a.commit,r['token'],body['delegatee_id'],cmd),r
    def attempt_then_commit(body,cmd):
        r=call(a.reserve,body['mandate_id'],body['delegatee_id'],cmd)
        return call(a.commit,r['token'],body['delegatee_id'],cmd) if r['status']=='RESERVED' else r
    if cid=='C35_unknown_policy_rule':
        r=call(a.register_root,policy_override={'budgets':quant(3,10),'forbidden_sets':[{'not':'read_sensitive'}]})
        verdicts=[r['status']];root=None
    else:
        config={}
        if cid=='C03_tool_widening':config['tools']=['lab.compute']
        if cid=='C16_uint64_boundary_no_wrap':config={'budget':quant(U64,10),'caps':quant(U64,10)}
        if cid=='C37_concurrent_positive_budget_four':config={'budget':quant(4,10)}
        root=require(call(a.register_root,**config),'REGISTERED')['mandate']
    if cid=='C01_root_positive_exact_budget':
        cmd=command(root,units='3',payload='ok');r,p=consume(root,cmd);verdicts=[r['status']]
        aux['positive_example']={'root':root,'command':cmd,'permit':p}
    elif cid=='C02_narrowed_child_positive':
        cs=copy.deepcopy(root['constraints']);cs['allowed_tools']=['lab.compute'];cs['action_caps']=quant(1,5)
        b=child(root,constraints=cs);r,p=consume(b,command(b));verdicts=[r['status']]
        aux['child_example']={'root':root,'child':b,'command':command(b),'permit':p}
    elif cid in ['C03_tool_widening','C04_action_cap_widening','C05_validity_widening']:
        cs=copy.deepcopy(root['constraints']);kw={}
        if cid=='C03_tool_widening':cs['allowed_tools']=TOOLS.copy()
        elif cid=='C04_action_cap_widening':cs['action_caps']=quant(4,10)
        else:kw['valid_until']=root['valid_until']+1
        r=call(a.delegate,root['mandate_id'],'agent-a','agent-b',cs,**kw)
        if r['status']=='REGISTERED':
            b=r['mandate'];r=attempt_then_commit(b,command(b,tool='lab.read_sensitive'))
        verdicts=[r['status']]
    elif cid=='C06_ancestor_prohibition_not_omitted':
        b=child(root);r,_=consume(b,command(b,tool='lab.read_sensitive'))
        s=attempt_then_commit(b,command(b,op='operation-2',tool='lab.export_external'));verdicts=[r['status'],s['status']]
    elif cid=='C07_missing_ancestor':
        b=child(root)
        with a.tx() as c:c.execute('DELETE FROM mandates WHERE mid=?',(root['mandate_id'],))
        verdicts=[call(a.reserve,b['mandate_id'],b['delegatee_id'],command(b))['status']]
    elif cid=='C08_parent_digest_mismatch':
        verdicts=[call(a.delegate,root['mandate_id'],'agent-a','agent-b',parent_hash='0'*64)['status']]
    elif cid=='C09_root_rebinding':
        cmd=command(root);cmd['root_mandate_id']='caller-selected-unregistered-root'
        verdicts=[call(a.reserve,root['mandate_id'],'agent-a',cmd)['status']]
    elif cid=='C10_immutable_identifier_replacement':
        changed=copy.deepcopy(root);changed['delegatee_id']='someone-else'
        verdicts=[call(a.replace,root['mandate_id'],changed)['status']]
    elif cid in ['C11_bad_es256_signature','C12_wrong_authenticated_delegatee','C13_wrong_audience_or_token_type','C14_changed_execution_command','C17_wrong_quantity_unit','C18_false_signed_fact_assertion']:
        cmd=command(root,tool='lab.read_sensitive' if cid=='C18_false_signed_fact_assertion' else 'lab.compute')
        p=reserve(root,cmd);token=p['token']
        if cid=='C11_bad_es256_signature':
            h,b,s=token.split('.');sig=unb64(s);token=h+'.'+b+'.'+b64(bytes([sig[0]^1])+sig[1:])
            verdicts=[call(a.commit,token,'agent-a',cmd)['status']]
        elif cid=='C12_wrong_authenticated_delegatee':verdicts=[call(a.commit,token,'authenticated-agent-b',cmd)['status']]
        elif cid=='C13_wrong_audience_or_token_type':
            first=call(a.commit,token,'agent-a',cmd,audience='urn:lab:other-executor')
            c=connect(db);m=c.execute('SELECT jwt FROM mandates WHERE mid=?',(root['mandate_id'],)).fetchone()[0];c.close()
            second=call(a.commit,m,'agent-a',cmd);verdicts=[first['status'],second['status']]
        elif cid=='C14_changed_execution_command':
            changed=copy.deepcopy(cmd);changed['arguments']['units']='2';aux['original_and_changed']=[cmd,changed]
            verdicts=[call(a.commit,token,'agent-a',changed)['status']]
        else:
            claims=copy.deepcopy(p['claims'])
            if cid=='C17_wrong_quantity_unit':claims['zti']['cost_bounds']['ops']['unit']='wrong-unit'
            else:claims['zti']['facts']=[]
            verdicts=[call(a.commit,sign(claims,'zti-ict+jwt'),'agent-a',cmd)['status']]
    elif cid=='C15_negative_or_boolean_quantity':
        verdicts=[call(a.reserve,root['mandate_id'],'agent-a',command(root,units=v))['status'] for v in ['-1',True]]
    elif cid=='C16_uint64_boundary_no_wrap':
        first,_=consume(root,command(root,units=str(U64)));second=attempt_then_commit(root,command(root,op='operation-2'))
        verdicts=[first['status'],second['status']]
    elif cid=='C19_sequential_siblings_budget':
        b,c=child(root),child(root,'agent-c');first,_=consume(b,command(b,units='2'))
        second=attempt_then_commit(c,command(c,op='operation-2',units='2'));verdicts=[first['status'],second['status']]
    elif cid in ['C20_concurrent_siblings_budget','C23_concurrent_reserved_forbidden_pair','C37_concurrent_positive_budget_four']:
        bs=[child(root),child(root,'agent-c')]
        if cid=='C23_concurrent_reserved_forbidden_pair':
            cmds=[command(bs[0],tool='lab.read_sensitive'),command(bs[1],op='operation-2',tool='lab.export_external')]
        else:cmds=[command(bs[0],units='2'),command(bs[1],op='operation-2',units='2')]
        barrier=CTX.Barrier(3)
        hs=[spawn_job(db,mutant,'reserve',(b['mandate_id'],b['delegatee_id'],cmd),barrier) for b,cmd in zip(bs,cmds)]
        aux['concurrency']={'pids':[p.pid for p,_ in hs],'all_alive_before_release':all(p.is_alive() for p,_ in hs),'barrier_parties':3}
        if len(set(aux['concurrency']['pids']))!=2 or not aux['concurrency']['all_alive_before_release']:raise RuntimeError('No concurrent actors')
        barrier.wait(TIMEOUT);rs=[finish_job(h,actors) for h in hs]
        verdicts=sorted(r['status'] for r in rs)
        for b,cmd,r in zip(bs,cmds,rs):
            if r['status']=='RESERVED':verdicts.append(call(a.commit,r['token'],b['delegatee_id'],cmd)['status'])
    elif cid=='C21_individual_sensitive_fact_positive':
        r,_=consume(root,command(root,tool='lab.read_sensitive'));verdicts=[r['status']]
    elif cid=='C22_sequential_forbidden_pair':
        r,_=consume(root,command(root,tool='lab.read_sensitive'))
        s=attempt_then_commit(root,command(root,op='operation-2',tool='lab.export_external'));verdicts=[r['status'],s['status']]
    elif cid=='C24_precommit_cancel_releases_only_pending':
        cmd=command(root,tool='lab.read_sensitive');p=reserve(root,cmd)
        r=call(a.cancel,TENANT,root['root_mandate_id'],p['reservation_id'],'agent-a')
        s=attempt_then_commit(root,command(root,op='operation-2',tool='lab.export_external'));verdicts=[r['status'],s['status']]
    elif cid in ['C25_cancel_wins_serialization','C26_commit_wins_serialization']:
        cmd=command(root);p=reserve(root,cmd);barrier=CTX.Barrier(3);done=CTX.Event()
        cancel=('cancel',(TENANT,root['root_mandate_id'],p['reservation_id'],'agent-a'))
        commit=('commit',(p['token'],'agent-a',cmd))
        first,second=(cancel,commit) if cid=='C25_cancel_wins_serialization' else (commit,cancel)
        h1=spawn_job(db,mutant,first[0],first[1],barrier,done=done)
        h2=spawn_job(db,mutant,second[0],second[1],barrier,wait=done)
        aux['directed_concurrency']={'pids':[h1[0].pid,h2[0].pid],'first':first[0],'barrier_parties':3}
        barrier.wait(TIMEOUT);verdicts=[finish_job(h1,actors)['status'],finish_job(h2,actors)['status']]
    elif cid in ['C27_unknown_retains_consumed_charge','C28_unknown_retains_committed_facts','C29_unknown_not_cancelled_or_repeated']:
        cost='2' if cid=='C27_unknown_retains_consumed_charge' else '1'
        tool='lab.read_sensitive' if cid=='C28_unknown_retains_committed_facts' else 'lab.compute'
        cmd=command(root,units=cost,tool=tool);_,p=consume(root,cmd)
        u=call(a.unknown,TENANT,root['root_mandate_id'],p['reservation_id'])
        if cid=='C27_unknown_retains_consumed_charge':
            r=attempt_then_commit(root,command(root,op='operation-2',units='2'));verdicts=[u['status'],r['status']]
        elif cid=='C28_unknown_retains_committed_facts':
            r=attempt_then_commit(root,command(root,op='operation-2',tool='lab.export_external'));verdicts=[u['status'],r['status']]
        else:
            r=call(a.cancel,TENANT,root['root_mandate_id'],p['reservation_id'],'agent-a')
            s=call(a.commit,p['token'],'agent-a',cmd);verdicts=[r['status'],s['status']]
    elif cid=='C30_expired_permit_no_automatic_release':
        cmd=command(root);p=reserve(root,cmd);a.advance_clock(61)
        verdicts=[call(a.commit,p['token'],'agent-a',cmd)['status']]
    elif cid=='C31_ancestor_revoked_before_consumption':
        b=child(root);cmd=command(b);p=reserve(b,cmd);call(a.revoke,root['mandate_id'])
        verdicts=[call(a.commit,p['token'],b['delegatee_id'],cmd)['status']]
    elif cid=='C32_changed_authority_epoch':
        cmd=command(root);p=reserve(root,cmd);a.bump_epoch(root['root_mandate_id'])
        verdicts=[call(a.commit,p['token'],'agent-a',cmd)['status']]
    elif cid=='C33_revocation_after_commit_retains_history':
        cmd=command(root);r,p=consume(root,cmd);call(a.revoke,root['mandate_id'])
        s=call(a.commit,p['token'],'agent-a',cmd);verdicts=[r['status'],s['status']]
    elif cid=='C34_second_dimension_cumulative_limit':
        r,_=consume(root,command(root,units='0',payload='abcdef'))
        s=attempt_then_commit(root,command(root,op='operation-2',units='0',payload='abcdef'));verdicts=[r['status'],s['status']]
    elif cid=='C36_lost_acknowledgement_after_commit':
        cmd=command(root);p=reserve(root,cmd);receive,send=CTX.Pipe(duplex=False)
        proc=CTX.Process(target=drop_ack_worker,args=(str(db),p['token'],'agent-a',cmd,send))
        proc.start();send.close();messages=[]
        while True:
            if not receive.poll(TIMEOUT):raise RuntimeError('Dropped-ack worker timeout')
            try:messages.append(receive.recv())
            except EOFError:break
        proc.join(TIMEOUT)
        if proc.is_alive() or proc.exitcode!=0:raise RuntimeError('Ack-loss child failed')
        receive.close();actors.append({'pid':proc.pid,'exitcode':proc.exitcode,'messages':messages,'intentional_ack_loss':True})
        result=call(a.lookup,TENANT,root['root_mandate_id'],cmd['operation_id'],'agent-a');verdicts=['CLIENT_UNKNOWN',result['status']]
    elif cid=='C38_resigned_same_ict_is_same_operation':
        cmd=command(root);r,p=consume(root,cmd);other=sign(p['claims'],'zti-ict+jwt')
        if other==p['token']:raise RuntimeError('Unexpected identical randomized ECDSA signature; no claimed entropy inference')
        s=call(a.commit,other,'agent-a',cmd);verdicts=[r['status'],s['status']];aux['distinct_signed_bytes']=True
        aux['same_claims_resigned']={'original':p['token'],'second':other,'jti':p['claims']['jti']}
    elif cid=='C39_depth_eight_boundary':
        b=root
        for i in range(7):b=child(b,'depth-agent-'+str(i))
        r,_=consume(b,command(b));s=call(a.delegate,b['mandate_id'],b['delegatee_id'],'depth-nine')
        verdicts=[r['status'],s['status']]
    elif cid=='C40_canonical_subset_boundary':
        try:canonical({'é':'valid Unicode key outside executable subset'});verdicts=['UNEXPECTED_ACCEPT']
        except Fault as e:verdicts=[e.code]
    elif cid=='C35_unknown_policy_rule':pass
    else:raise RuntimeError('Case not implemented: '+cid)
    snap=a.snapshot();actual={k:snap[k] for k in ['effect_rows','consumed','reserved','committed_facts','possible_facts']}
    actual['verdicts']=verdicts
    if 'distinct_signed_bytes' in aux:actual['distinct_signed_bytes']=aux['distinct_signed_bytes']
    expected=case['expected'];check=copy.deepcopy(expected);oneof=check.pop('facts_one_of',None)
    compared=copy.deepcopy(actual)
    if oneof is not None:
        facts_ok=actual['committed_facts']==actual['possible_facts'] and actual['committed_facts'] in oneof
        for k in ['committed_facts','possible_facts']:check.pop(k);compared.pop(k)
    else:facts_ok=True
    matches=compared==check and facts_ok
    return {'id':cid,'mutant':mutant,'actual':actual,'expected':expected,'matches_oracle':matches,
            'facts_alternative_satisfied':facts_ok,'trace':trace,'actors':actors,'aux':aux,'database_snapshot':snap}

def main():
    p=argparse.ArgumentParser();p.add_argument('--output-dir',required=True);args=p.parse_args()
    out=Path(args.output_dir).resolve()
    if out.exists() and any(out.iterdir()):raise RuntimeError('Use a new output directory to preserve evidence')
    out.mkdir(parents=True,exist_ok=True)
    manifest=json.loads((ROOT/'preexecution_manifest.json').read_text())
    for name,expected in manifest['sha256'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=expected:raise RuntimeError('Frozen input changed: '+name)
    data=json.loads((ROOT/'cases.json').read_text());runs=[];mutants=[]
    try:
        for case in data['cases']:
            d=out/case['id'];d.mkdir();r=exercise(case,d)
            (d/'result.json').write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');runs.append(r)
            if not r['matches_oracle']:raise AssertionError({'id':r['id'],'actual':r['actual'],'expected':r['expected']})
        cases={c['id']:c for c in data['cases']}
        for m in data['mutants']:
            d=out/('mutant_'+m['id']);d.mkdir();r=exercise(cases[m['witness']],d,m['id'])
            r['mutation_detected']=not r['matches_oracle']
            (d/'result.json').write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');mutants.append(r)
            if not r['mutation_detected']:raise AssertionError('Mutation survived: '+m['id'])
    except BaseException as e:
        (out/'FAILURE.json').write_text(json.dumps({'error':repr(e),'traceback':traceback.format_exc(),
             'completed_cases':len(runs),'completed_mutants':len(mutants)},indent=2)+'\n')
        for child in mp.active_children():child.terminate();child.join()
        raise
    summary={'scenario_count':len(runs),'expected_observations_matched':sum(r['matches_oracle'] for r in runs),
      'targeted_mutants':len(mutants),'mutants_detected':sum(r['mutation_detected'] for r in mutants),
      'child_processes':sum(len(r['actors']) for r in runs+mutants),'errors':0,
      'source_sha256':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in ['authority.py','run_r4.py']},
      'frozen_inputs':manifest['sha256'],'runtime':{'python':sys.version,'cryptography':cryptography.__version__,
      'sqlite':sqlite3.sqlite_version,'start_method':'spawn'},'network_calls':0,'llm_calls':0,
      'notes':['One current-online architecture only.','Facts and costs are a trusted symbolic catalog fixture.',
        'Real ES256 signatures; JCS-compatible ASCII-key/safe-integer executable subset only.',
        'SQLite transaction binds current authorization to the local effect row, not a remote side effect.',
        'Finite expected observations are not a general conformance or safety rate.']}
    (out/'SUMMARY.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    (out/'all_results.json').write_text(json.dumps({'runs':runs,'mutants':mutants},indent=2,sort_keys=True)+'\n')
    print(json.dumps(summary,indent=2))

if __name__=='__main__':main()

"""Independent wire-to-SQL binding and modern discovery checks."""
import base64
import json
from pathlib import Path
from primitives import action_hash, b64, canonical, decoded, u64, verify_jws
from state import need

EXT='org.example/zti-mcp'
PROTOCOL='2026-07-28'
CAP={'revision':'0.1','profile':'zti-mcp/0.1','mode':'current-online','effect_coupling':'required'}

def safe_child(root, name):
    need(type(name) is str and '\\' not in name and ':' not in name,'nonportable evidence path')
    path = Path(root)/name
    need(not path.is_symlink() and path.resolve().is_relative_to(Path(root).resolve()),'evidence path escapes case')
    return path

def jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding='utf-8').splitlines() if line]

def receipt_of(result):
    if type(result) is not dict:
        return None
    if 'receipt' in result:
        return result['receipt']
    meta = result.get('_meta',{}).get(EXT)
    if type(meta) is dict and meta.get('status')=='COMMITTED':
        return meta
    return result.get('structuredContent',{}).get('receipt')

def control_result(method,params,result,tables):
    """Closed profile result shapes plus identities, independently of provider code."""
    short=method.rsplit('.',1)[-1]
    common={'resultType','status','tenant_id','root_mandate_id','state_revision'}
    if short=='register':
        required=common|{'mandate_id','mandate_hash','policy_hash'};optional={'_meta'}
        body=decoded(b64(params['mandate'].split('.')[1]))['zti_mandate']
        identity=body
        need(result.get('status') in {'ACTIVE','REVOKED'},'register result status')
        need(result.get('mandate_id')==body['mandate_id'] and result.get('mandate_hash')==action_hash(body) and result.get('policy_hash')==body['policy_hash'],'register result binding differs')
    elif short=='revoke':
        required=common|{'mandate_id','authority_epoch'};optional={'_meta'};identity=params
        need(result.get('status')=='REVOKED' and result.get('mandate_id')==params['mandate_id'],'revoke result identity/status')
        u64(result['authority_epoch'])
    else:
        need(short in {'reserve','lookup','cancel'},'unknown control result method')
        required=common|{'operation_id','reservation_id'};optional={'_meta','receipt'}|({'ict'} if short=='reserve' else set())
        identity=params['action'] if short=='reserve' else params
        rows=[r for r in tables['reservations'] if r['tenant_id']==identity['tenant_id'] and r['root_mandate_id']==identity['root_mandate_id'] and r['operation_id']==identity['operation_id']]
        need(len(rows)==1,'control result missing stored operation')
        row=rows[0]
        need(result.get('operation_id')==row['operation_id'] and result.get('reservation_id')==row['reservation_id'],'control result operation/reservation binding differs')
        need(result.get('status') in {'RESERVED','COMMITTED','COMPLETED','UNKNOWN','CANCELLED','EXPIRED','REVOKED'},'control result state vocabulary')
        charged=result['status'] in {'COMMITTED','COMPLETED','UNKNOWN'}
        need(('receipt' in result)==charged,'receipt presence differs from control state')
        if 'receipt' in result:
            stored=[r for r in tables['receipts'] if r['tenant_id']==row['tenant_id'] and r['root_mandate_id']==row['root_mandate_id'] and r['operation_id']==row['operation_id']]
            need(len(stored)==1 and result['receipt']==decoded(stored[0]['receipt_json']),'control historical receipt differs')
        if 'ict' in result:need(result['status']=='RESERVED' and result['ict']==row['ict_jws'],'control ICT/state differs')
    need(type(result) is dict and required<=set(result)<=required|optional,'closed control result fields')
    need(result['resultType']=='complete','control resultType')
    need(result['tenant_id']==identity['tenant_id'] and result['root_mandate_id']==identity['root_mandate_id'],'control result root/tenant binding differs')
    revision=u64(result['state_revision'])
    roots=[r for r in tables['roots'] if r['tenant_id']==identity['tenant_id'] and r['root_mandate_id']==identity['root_mandate_id']]
    need(len(roots)==1 and 1<=revision<=u64(roots[0]['state_revision']),'control result revision outside durable history')
    history=[r for r in tables['transitions'] if r['tenant_id']==identity['tenant_id'] and r['root_mandate_id']==identity['root_mandate_id'] and u64(r['state_revision'])<=revision]
    if short=='revoke':
        need(u64(result['authority_epoch'])==sum(r['event']=='REVOKED' for r in history),'revoke result epoch differs from durable history')
        need(any(r['event']=='REVOKED' and decoded(r['detail_json']).get('mandate_id')==params['mandate_id'] for r in history),'revoke result precedes actual target revocation')
    elif short in {'reserve','lookup','cancel'}:
        events=sorted([r for r in history if r['operation_id']==identity['operation_id'] and r['event'] in {'RESERVED','COMMITTED','CANCELLED'}],key=lambda r:u64(r['state_revision']))
        need(bool(events) and result['status']==events[-1]['event'],'control result status differs from operation state at reported revision')

def audit_wire(case_dir, observation, tables, keys, context, frozen_tool_schema):
    reservations={r['operation_id']:r for r in tables['reservations']}
    receipts={r['operation_id']:decoded(r['receipt_json']) for r in tables['receipts']}
    pairs={}
    process_records=[]
    totals={'frames':0,'discover_responses':0,'successful_tool_calls':0,'successful_reserves':0}
    for connection in observation['connections']:
        records=jsonl(safe_child(case_dir,connection['wire']))
        lifecycle=jsonl(safe_child(case_dir,connection['lifecycle']))
        starts=[r for r in lifecycle if r['type']=='provider_start']
        exits=[r for r in lifecycle if r['type']=='provider_exit']
        need(len(starts)==1 and len(exits)==1,'actual provider lifecycle missing/duplicate')
        start,end=starts[0],exits[0]
        need(start['provider_pid']==end['provider_pid'] and start['endpoint_instance_id']==connection['endpoint_instance_id'],'provider lifecycle identity')
        need(type(start['provider_pid']) is int and start['provider_pid']>0,'actual provider PID')
        need(end['returncode'] in (0,86),'unexpected provider exit')
        pending={}
        discovered=0
        previous=0
        for record in records:
            totals['frames']+=1
            need(record['sequence']>previous,'wire sequence is not increasing')
            previous=record['sequence']
            need(record['provider_pid']==start['provider_pid'] and record['endpoint_instance_id']==connection['endpoint_instance_id'],'wire/process identity differs')
            raw=base64.b64decode(record['raw_base64'],validate=True)
            frame=decoded(raw)
            need(canonical(frame)==canonical(record['frame']),'raw bytes differ from recorded parsed frame')
            need(frame.get('jsonrpc')=='2.0','JSON-RPC envelope')
            if record['direction']=='client_to_server':
                if 'method' not in frame or 'id' not in frame:
                    continue
                request_id=json.dumps(frame['id'],sort_keys=True)
                need(request_id not in pending,'duplicate outstanding wire request ID')
                params=frame.get('params',{})
                meta=params.get('_meta',{})
                need(meta.get('io.modelcontextprotocol/protocolVersion')==PROTOCOL,'missing actual modern protocol metadata')
                need(meta.get('io.modelcontextprotocol/clientCapabilities',{}).get('extensions',{}).get(EXT)==CAP,'missing actual client extension capability')
                if frame['method']!='server/discover':
                    need(discovered>0,'no discovery on actual active connection before use')
                pending[request_id]={'request':frame,'request_sequence':record['sequence'],'provider_pid':start['provider_pid']}
            elif record['direction']=='server_to_client' and 'id' in frame and ('result' in frame or 'error' in frame):
                request_id=json.dumps(frame['id'],sort_keys=True)
                need(request_id in pending,'response has no captured outstanding request')
                pair=pending.pop(request_id)
                pair.update(response=frame,response_sequence=record['sequence'])
                key=connection['endpoint_instance_id'],request_id
                need(key not in pairs,'reused completed request ID in a connection')
                pairs[key]=pair
                method=pair['request']['method']
                params=pair['request'].get('params',{})
                if 'error' in frame:
                    continue
                result=frame['result']
                if method.startswith(EXT+'.'):
                    control_result(method,params,result,tables)
                if method=='server/discover':
                    need(result.get('supportedVersions')==[PROTOCOL],'modern supportedVersions incompatible/missing')
                    need(type(result.get('capabilities')) is dict and result['capabilities'].get('extensions',{}).get(EXT)==CAP,'modern extension capabilities incompatible/missing')
                    discovered+=1;totals['discover_responses']+=1
                elif method=='tools/list':
                    tools=[x for x in result.get('tools',[]) if x.get('name')=='demo.add_record']
                    need(len(tools)==1 and tools[0].get('inputSchema')==frozen_tool_schema,'external tool catalog/schema differs from contract')
                elif method==EXT+'.register':
                    claims=verify_jws(params['mandate'],keys['KI'],typ='zti-mandate+jwt',kid=context['mandate_kid'],issuer=context['mandate_issuer'],audience=context['registry_id'])
                    body=claims['zti_mandate']
                    matches=[r for r in tables['mandates'] if r['mandate_id']==body['mandate_id']]
                    need(len(matches)==1 and decoded(matches[0]['body_json'])==body,'accepted registered mandate missing/different in SQL')
                elif method==EXT+'.reserve':
                    totals['successful_reserves']+=1
                    action=params['action'];row=reservations.get(action['operation_id'])
                    need(row is not None and canonical(action)==canonical(decoded(row['action_json'])),'accepted reserve request differs from durable action')
                    need(action_hash(action)==row['action_hash'],'reserve request canonical binding')
                    if 'ict' in result:
                        need(result['ict']==row['ict_jws'],'emitted permit differs from SQL')
                        verify_jws(result['ict'],keys['KP'],typ='zti-ict+jwt',kid=context['permit_kid'],issuer=context['permit_issuer'],audience=context['executor_id'])
                    receipt=receipt_of(result)
                    if receipt:
                        need(receipt==receipts.get(action['operation_id']),'reserve historical receipt differs')
                elif method=='tools/call':
                    totals['successful_tool_calls']+=1
                    meta=params.get('_meta',{}).get(EXT)
                    need(type(meta) is dict and set(meta)=={'revision','operation_id','ict'} and meta['revision']=='0.1','accepted call missing exact ICT metadata')
                    row=reservations.get(meta['operation_id'])
                    need(row is not None,'accepted call missing reservation')
                    action=decoded(row['action_json'])
                    need(params.get('name')==action['tool_name'] and canonical(params.get('arguments'))==canonical(action['arguments']),'accepted raw tools/call differs from authorized action')
                    need(meta['ict']==row['ict_jws'],'accepted call permit differs from stored permit')
                    claims=verify_jws(meta['ict'],keys['KP'],typ='zti-ict+jwt',kid=context['permit_kid'],issuer=context['permit_issuer'],audience=context['executor_id'])
                    need(claims['sub']==connection['principal'],'accepted permit subject differs from configured channel')
                    receipt=receipt_of(result)
                    need(receipt==receipts.get(meta['operation_id']),'successful call receipt differs from durable receipt')
                    structured=result.get('structuredContent')
                    need(type(structured) is dict and structured.get('receipt')==receipt,'structured tool receipt missing/different')
                    effect=next((x for x in tables['business_effects'] if x['operation_id']==meta['operation_id']),None)
                    need(effect is not None and structured.get('result')==decoded(effect['result_json']),'structured business result differs from committed result')
        for request_id,pair in pending.items():
            need(end['returncode']==86,'unanswered RPC without expected process crash')
            pairs[(connection['endpoint_instance_id'],request_id)]=pair
        if connection.get('client')=='T':
            need(discovered>=2,'TypeScript explicit active discovery not distinguished from negotiation probe')
        need(discovered>=1,'no actual modern discovery')
        process_records.append({'connection':connection['connection'],'endpoint_instance_id':connection['endpoint_instance_id'],'provider_pid':start['provider_pid'],'exitcode':end['returncode']})
    # Observation records are convenience indexes, checked against raw capture.
    # They cannot manufacture a successful response, an error or a request.
    for step_id,step in observation['steps'].items():
        key=step['endpoint_instance_id'],json.dumps(step['request_id'],sort_keys=True)
        need(key in pairs,'step missing raw request '+step_id)
        pair=pairs[key]
        need(pair['request']['method']==step['method'],'step method differs from wire')
        if 'request' in step:
            request=step['request']
            need(canonical(request)==canonical(pair['request']),'indexed request including metadata differs from raw wire')
        response=pair.get('response')
        if response is None:
            need('transport_outcome' in step,'unanswered request lacks explicit transport outcome')
        else:
            for field in ('result','error'):
                need((field in response)==(field in step),'indexed response classification differs')
                if field in response:
                    need(canonical(response[field])==canonical(step[field]),'indexed response differs from raw bytes')
            if 'result' in response and pair['request']['method'].startswith(EXT+'.'):
                revision=u64(response['result']['state_revision'])
                if step.get('before_revision') is not None:need(revision>=u64(step['before_revision']),'control response revision predates actual pre-dispatch SQL read')
                if step.get('after_revision') is not None:need(revision<=u64(step['after_revision']),'control response revision exceeds actual post-response SQL read')
        pair['step_id']=step_id
    return {'totals':totals,'processes':process_records,'pairs':pairs}

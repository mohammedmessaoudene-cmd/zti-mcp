"""Reconstruct frozen test inputs without importing the fixture generator."""
import copy
from cryptography.exceptions import InvalidSignature
from primitives import action_hash, b64, canonical, decoded, verify_signature_only
from state import need
EXT='org.example/zti-mcp'

def mandates_for(corpus, specification):
    bodies=copy.deepcopy(corpus['mandate_templates'])
    root=bodies['root']
    overrides=specification.get('fixture_overrides',specification.get('overrides',{}))
    if 'root_budget' in overrides:root['root_policy']['budgets']=copy.deepcopy(overrides['root_budget'])
    root['policy_hash']=action_hash(root['root_policy'])
    for alias,body in bodies.items():
        if alias=='root':continue
        body['parent_hash']=action_hash(root)
        body['policy_hash']=root['policy_hash']
    return bodies

def request_input(spec, actual, corpus, specification, all_steps, keys, fixtures):
    args=spec.get('args',{})
    request=actual['request']
    need(request['method']==spec['method'],'frozen request method mismatch')
    params=request.get('params',{})
    method=spec['method']
    if 'claimed_principal' in args:
        need(params.get('_meta',{}).get(EXT+'/claimedPrincipal')==args['claimed_principal'],'identity experiment omitted its permitted metadata hint')
    announced=specification.get('fixture_overrides',{}).get('announced_client_name_by_channel',{}).get(actual.get('connection'))
    if announced:
        need(params.get('_meta',{}).get('io.modelcontextprotocol/clientInfo',{}).get('name')==announced,'identity experiment did not announce its frozen misleading client identity')
    if method==EXT+'.register':
        body=mandates_for(corpus,specification)[args['mandate_ref']]
        if 'constraint_override' in args:body['constraints'].update(copy.deepcopy(args['constraint_override']))
        segments=params['mandate'].split('.')
        header,claims=decoded(b64(segments[0])),decoded(b64(segments[1]))
        need(canonical(claims['zti_mandate'])==canonical(body),'signed mandate input differs from frozen experiment')
        ctx=corpus['context']['key_contexts']
        signer=args.get('sign_with','KI');kid_role=args.get('kid_role','KI')
        expected_header={'alg':'ES256','typ':args.get('typ','zti-mandate+jwt'),'kid':ctx['mandate_kid' if kid_role=='KI' else 'permit_kid']}
        expected_header.update(args.get('header',{}))
        expected_claims={'iss':ctx['mandate_issuer'],'sub':body['delegatee_id'],'aud':ctx['registry_id'],'iat':body['valid_from'],'nbf':body['valid_from'],'exp':body['valid_until'],'jti':body['mandate_id'],'zti_mandate':body}
        expected_claims.update(args.get('claims_overrides',{}))
        need(canonical(header)==canonical(expected_header),'protected header does not isolate the frozen JWS fault')
        need(canonical(claims)==canonical(expected_claims),'JWS claims do not isolate the frozen context fault')
        if args.get('signature_xor'):
            record=fixtures['request_mandates'][spec['id']]
            original=record['original_jws'];oh,op,os=original.split('.')
            need(segments[:2]==[oh,op],'signature mutation changed protected header or payload')
            signature=bytearray(b64(os));mutation=args['signature_xor']
            need(len(signature)==64 and len(b64(segments[2]))==64,'signature mutation width')
            signature[mutation['byte_offset']]^=mutation['mask']
            need(bytes(signature)==b64(segments[2]),'signature mutation is not the frozen one-bit XOR')
            verify_signature_only(original,keys[signer])
            try:verify_signature_only(params['mandate'],keys[signer])
            except InvalidSignature:pass
            else:raise ValueError('altered signature unexpectedly verifies')
        else:
            verify_signature_only(params['mandate'],keys[signer])
    elif method in (EXT+'.reserve','tools/call'):
        action=copy.deepcopy(corpus['action_templates'][args['action_ref']])
        if 'arguments_override' in args:action['arguments']=copy.deepcopy(args['arguments_override'])
        if 'action_override' in args:action.update(copy.deepcopy(args['action_override']))
        if method.endswith('.reserve'):
            need(canonical(params.get('action'))==canonical(action),'reserve input differs from frozen experiment')
        else:
            need(params.get('name')==action['tool_name'] and canonical(params.get('arguments'))==canonical(action['arguments']),'tools/call input differs from frozen experiment')
            meta=params.get('_meta',{}).get(EXT,{})
            if args.get('omit_ict'):
                need('ict' not in meta,'missing-token experiment supplied an ICT')
            elif args.get('ict_mutation'):
                mutation=args['ict_mutation']
                original=all_steps[mutation['same_claims_as']]['result']['ict']
                token=meta['ict'];h,p,s=token.split('.')
                ctx=corpus['context']['key_contexts']
                expected={'alg':'ES256','typ':mutation.get('typ','zti-ict+jwt'),'kid':ctx['mandate_kid' if mutation['kid_role']=='KI' else 'permit_kid']}
                need(canonical(decoded(b64(h)))==canonical(expected),'wrong-role ICT advertised header differs')
                need(canonical(decoded(b64(p)))==canonical(decoded(b64(original.split('.')[1]))),'wrong-role ICT changed otherwise valid claims')
                verify_signature_only(original,keys['KP'])
                verify_signature_only(token,keys[mutation['sign_with']])
            else:
                source=args.get('ict_from','reserve:'+args['action_ref'])
                alias=source.split(':',1)[-1]
                candidates=[s for s in all_steps.values() if s.get('method')==EXT+'.reserve' and s.get('action_ref')==alias and 'ict' in s.get('result',{})]
                need(bool(candidates) and meta.get('ict')==candidates[0]['result']['ict'],'binding experiment did not reuse the intended valid ICT')
    elif method in (EXT+'.cancel',EXT+'.lookup'):
        operation=corpus['operation_ids'][args['operation_ref']]
        need(params.get('operation_id')==operation and params.get('tenant_id')==corpus['context']['key_contexts']['tenant_id'] and params.get('root_mandate_id')==corpus['context']['root_mandate_id'],'lookup/cancel experiment identity differs')
    elif method==EXT+'.revoke':
        target=mandates_for(corpus,specification)[args['mandate_ref']]['mandate_id']
        need(params.get('mandate_id')==target,'revocation target differs from frozen experiment')

"""Public-key-only sensitivity check for the frozen raw duplicated-key input."""
import base64
import hashlib
import json
from primitives import b64, verify_jws, verify_signature_only
from state import need

def audit_raw_jws(directory, fixture_path):
    evidence=json.loads((directory/'raw_jws.json').read_text(encoding='utf-8'))
    fixture=json.loads(fixture_path.read_text(encoding='utf-8'))
    need(evidence['fixture_sha256']==hashlib.sha256(fixture_path.read_bytes()).hexdigest(),'raw JWS fixture identity')
    need(evidence['context']==fixture['context'] and evidence['sdk_executions']==0,'raw JWS diagnostic scope/context')
    key=evidence['public_jwk'];ctx=fixture['context']
    need('d' not in key,'raw diagnostic leaked private key')
    results={}
    for name in ('positive','negative'):
        value=evidence['inputs'][name]
        token=value['token'];payload=b64(token.split('.')[1])
        need(payload==fixture[name+'_payload_template'].encode('ascii'),'raw payload bytes differ from frozen template')
        need(base64.b64decode(value['payload_utf8_base64'],validate=True)==payload,'raw payload convenience copy differs')
        verify_signature_only(token,key)
        if name=='positive':
            verify_jws(token,key,typ='zti-mandate+jwt',kid=ctx['mandate_kid'],issuer=ctx['mandate_issuer'],audience=ctx['registry_id'])
            results[name]={'signature':'VALID','raw_reader':'ACCEPT'}
        else:
            try:
                verify_jws(token,key,typ='zti-mandate+jwt',kid=ctx['mandate_kid'],issuer=ctx['mandate_issuer'],audience=ctx['registry_id'])
            except ValueError as error:
                need(str(error)=='duplicate decoded object key','raw negative rejected for a different reason')
            else:raise ValueError('raw duplicated iss was accepted')
            results[name]={'signature':'VALID','raw_reader':'REJECT_DUPLICATE_KEY'}
    return {'status':'PASS','inputs':results,'sdk_executions':0,'scope':'Raw syntax/context/signature only, not complete mandate or provider execution.'}

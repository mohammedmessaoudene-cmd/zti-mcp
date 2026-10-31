#!/usr/bin/env python3
"""Verify exported signatures with the exported public JWK and check bindings.

Not a general JOSE/JCS/JSON-Schema validator or an MCP implementation.
"""
import argparse,hashlib,json,re,sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec,utils
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT));sys.dont_write_bytecode=True
from authority import canonical,unb64,PROFILE,U64,SAFE

def read(path):return json.loads(path.read_text())
def digest(v):return hashlib.sha256(canonical(v)).hexdigest()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,help='Write the verification report outside tracked fixtures.')
    args=parser.parse_args()
    output=None
    if args.output is not None:
        raw=args.output.absolute();work=ROOT.parent/'work';output=raw.resolve()
        if (work.is_symlink() or output==work.resolve() or not output.is_relative_to(work.resolve())
            or any(path.is_symlink() for path in (raw,*raw.parents)) or output.exists()):
            parser.error('--output must name a fresh file under work/, without symbolic links.')
    examples=ROOT.parent/'examples';schema=ROOT.parent/'schema'
    jwk=read(examples/'public_jwk.json')
    assert jwk['kty']=='EC' and jwk['crv']=='P-256' and jwk['alg']=='ES256'
    key=ec.EllipticCurvePublicNumbers(int.from_bytes(unb64(jwk['x']),'big'),int.from_bytes(unb64(jwk['y']),'big'),ec.SECP256R1()).public_key()
    verified=[]
    for label,typ in [('root_mandate','zti-mandate+jwt'),('child_mandate','zti-mandate+jwt'),('ict','zti-ict+jwt')]:
        token=(examples/(label+'.jwt')).read_text().strip();h,p,s=token.split('.')
        assert read_json(unb64(h))=={'alg':'ES256','kid':jwk['kid'],'typ':typ}
        raw=unb64(s);assert len(raw)==64
        signature=utils.encode_dss_signature(int.from_bytes(raw[:32],'big'),int.from_bytes(raw[32:],'big'))
        key.verify(signature,(h+'.'+p).encode(),ec.ECDSA(hashes.SHA256()))
        claims=read_json(unb64(p));assert claims==read(examples/(label+'_claims.json'))
        assert all(type(claims[t]) is int and 0<=claims[t]<=SAFE for t in ['iat','nbf','exp'])
        assert claims['iat']<=claims['nbf']<claims['exp']
        verified.append({'file':label+'.jwt','signature_octets':len(raw),'algorithm':'ES256','verified':True})
    root=read(examples/'root_mandate_claims.json');child=read(examples/'child_mandate_claims.json');ict=read(examples/'ict_claims.json')
    rb,cb,z=root['zti_mandate'],child['zti_mandate'],ict['zti']
    action=read(examples/'action.json');receipt=read(examples/'receipt.json')
    assert rb['parent_id'] is None and rb['parent_hash'] is None and rb['mandate_id']==rb['root_mandate_id']
    assert cb['parent_id']==rb['mandate_id'] and cb['parent_hash']==digest(rb) and cb['root_policy'] is None
    assert rb['policy_hash']==cb['policy_hash']==z['policy_hash']==digest(rb['root_policy'])
    assert z['mandate_hash']==digest(cb) and z['action_hash']==digest(action)
    assert root['sub']==rb['delegatee_id'] and child['sub']==cb['delegatee_id']==ict['sub']
    assert root['aud']==child['aud']=='urn:lab:registry' and ict['aud']==action['executor_id']
    assert ict['exp']-ict['iat']<=60 and ict['nbf']>=cb['valid_from'] and ict['exp']<=cb['valid_until']
    assert rb['valid_from']<=cb['valid_from']<cb['valid_until']<=rb['valid_until']
    assert cb['tenant_id']==rb['tenant_id']==z['tenant_id']==action['tenant_id']
    assert cb['root_mandate_id']==rb['root_mandate_id']==z['root_mandate_id']==action['root_mandate_id']
    assert cb['correlation_id']==rb['correlation_id']==z['correlation_id']
    assert z['mandate_id']==cb['mandate_id']==action['mandate_id'] and action['operation_id']==z['operation_id']
    assert action['method']=='tools/call' and action['tool_name']=='lab.compute'
    for k in ['allowed_executors','allowed_resources','allowed_methods','allowed_tools']:
        assert set(cb['constraints'][k])<=set(rb['constraints'][k])
    assert z['cost_bounds']=={'ops':{'unit':'operation','amount':action['arguments']['units']},'bytes':{'unit':'byte','amount':str(len(action['arguments']['payload'].encode()))}}
    assert z['facts']==[]
    for dim in ['ops','bytes']:
        assert int(z['cost_bounds'][dim]['amount'])<=int(cb['constraints']['action_caps'][dim]['amount'])<=int(rb['constraints']['action_caps'][dim]['amount'])
        assert int(z['cost_bounds'][dim]['amount'])<=int(rb['root_policy']['budgets'][dim]['amount'])
    assert set(receipt)=={'profile','tenant_id','root_mandate_id','mandate_id','operation_id','reservation_id','action_hash','effect_boundary','status','state_revision'}
    for field in set(receipt)-{'effect_boundary','status','state_revision'}:assert receipt[field]==z[field]
    assert receipt['effect_boundary']=='resource-mutation' and receipt['status']=='COMMITTED'

    # Static local-reference/syntax checks only; no full JSON Schema engine installed.
    files=sorted(p for p in schema.glob('*.schema.json') if p.name!='zti-control-0.1.schema.json')
    docs={p.name:read(p) for p in files};refs=[]
    def walk(v,current):
        if isinstance(v,list):
            for x in v:walk(x,current)
        elif isinstance(v,dict):
            if '$ref' in v:
                ref=v['$ref'];fn,_,fragment=ref.partition('#');target=docs[fn or current]
                if fragment:
                    assert fragment.startswith('/')
                    for part in fragment[1:].split('/'):target=target[part.replace('~1','/').replace('~0','~')]
                refs.append((current,ref))
            for x in v.values():walk(x,current)
    for name,doc in docs.items():
        assert doc['$schema']=='https://json-schema.org/draft/2020-12/schema';walk(doc,name)
    pattern=docs['zti-common-0.1.schema.json']['$defs']['uint64']['pattern']
    accepted=['0','1',str(U64-1),str(U64)]
    rejected=['-1','01','1.0','true','',str(U64+1),'9'*20,'0\n']
    assert all(re.search(pattern,s) is not None for s in accepted)
    assert all(re.search(pattern,s) is None for s in rejected)
    assert re.search(pattern,receipt['state_revision']) is not None
    result={'signatures':verified,'binding_assertions_passed':True,'example_origin':'Existing C02 run; not an additional scenario.',
            'schema_files_parsed':len(files),'local_schema_references_resolved':len(refs),
            'uint64_pattern_boundary_examples':{'accepted':accepted,'rejected':rejected},
            'full_json_schema_validation':False,'full_jcs_validation':False,'mcp_transport_validation':False,
            'receipt_is_offline_documentary_view':True,
            'artifact_sha256':{str(p.relative_to(ROOT.parent)):hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in sorted(list(examples.glob('*.json'))+list(examples.glob('*.jwt'))+files) if p.name!='VERIFICATION.json'}}
    if output is None:
        (examples/'VERIFICATION.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf-8',newline='\n')
    else:
        output.parent.mkdir(parents=True,exist_ok=True)
        with output.open('x',encoding='utf-8',newline='\n') as stream:
            stream.write(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='artifact_sha256'},indent=2))

def read_json(raw):return json.loads(raw)
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Separate lab issuer: sign frozen raw JSON bytes, including a duplicate key."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from issuer import make_keys
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

def b64(raw):return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--private-dir',type=Path,required=True)
    args=parser.parse_args()
    if args.output_dir.exists():raise ValueError('Fresh raw diagnostic evidence directory required')
    r6=Path(__file__).resolve().parents[1]
    fixture_path=r6/'fixtures/raw_jws.json'
    fixture=json.loads(fixture_path.read_text(encoding='utf-8'))
    keys=make_keys(args.private_dir)
    key=serialization.load_pem_private_key(Path(keys['KI']['private']).read_bytes(),password=None)
    header=json.dumps(fixture['header'],sort_keys=True,separators=(',',':')).encode('utf-8')
    inputs={}
    for name in ('positive','negative'):
        payload=fixture[name+'_payload_template'].encode('ascii')
        h,p=b64(header),b64(payload)
        der=key.sign((h+'.'+p).encode('ascii'),ec.ECDSA(hashes.SHA256()))
        r,s=decode_dss_signature(der)
        inputs[name]={'token':h+'.'+p+'.'+b64(r.to_bytes(32,'big')+s.to_bytes(32,'big')),'payload_utf8_base64':base64.b64encode(payload).decode('ascii')}
    report={'format':'zti-r6-raw-jws-evidence-v1','fixture_sha256':hashlib.sha256(fixture_path.read_bytes()).hexdigest(),'public_jwk':keys['KI']['jwk'],'context':fixture['context'],'inputs':inputs,'sdk_executions':0,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    args.output_dir.mkdir(parents=True)
    (args.output_dir/'raw_jws.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'status':'GENERATED_NOT_AUDITED','sdk_executions':0,'inputs':2}))
if __name__=='__main__':main()

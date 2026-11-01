#!/usr/bin/env python3
"""Verify frozen R6 inputs, preserved history and actual local source identity."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
R6=ROOT/'successor/r6'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def load(path):return json.loads(path.read_text(encoding='utf-8'))
def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args],text=True).strip()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-sha',default=os.environ.get('EXPECTED_SOURCE_SHA'))
    parser.add_argument('--allow-dirty',action='store_true',help='Development evidence only; never a qualification gate.')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    seal=load(R6/'preexecution.json')
    for name,expected in seal['files'].items():
        if sha(R6/name)!=expected:raise ValueError('Frozen R6 input differs: '+name)
    baseline=load(R6/'PRESERVED_BASELINE.json')
    implementation=load(R6/'oracle-implementation-seal.json')
    if implementation.get('format')!='zti-r6-oracle-implementation-seal/1' or implementation.get('status')!='FROZEN_BEFORE_QUALIFICATION' or implementation.get('preexecution_sha256')!=sha(R6/'preexecution.json'):
        raise ValueError('Reader implementation seal is missing or refers to another contract')
    expected_names={p.relative_to(R6).as_posix() for p in (R6/'oracle').glob('*.py')}|{'ORACLE_IMPLEMENTATION_ERRATA.json','DEPENDENCY_ENTRY_POINTS.json'}
    if set(implementation['files'])!=expected_names:raise ValueError('Reader implementation file set differs')
    for name,expected_hash in implementation['files'].items():
        if sha(R6/name)!=expected_hash:raise ValueError('Sealed reader code differs: '+name)
    for name,expected in baseline['files'].items():
        if sha(ROOT/name)!=expected:raise ValueError('Historical file differs: '+name)
    source=git('rev-parse','HEAD')
    status=git('status','--porcelain','--untracked-files=normal')
    if args.expected_sha and source!=args.expected_sha:raise ValueError('Actual source commit differs from expected commit')
    if status and not args.allow_dirty:raise ValueError('Source tree is dirty; do not attribute this run to a clean commit')
    corpus=load(R6/'fixtures/scenarios.json')
    expected={'histories':20,'binding_vectors':24,'binding_diagnostics':4,'causal_plans':12,'date_diagnostics':8,'synthetics':6,'mutants':6}
    for field,count in expected.items():
        if len(corpus[field])!=count:raise ValueError('Frozen count differs: '+field)
    report={'status':'PASS' if not status else 'DEVELOPMENT_DIRTY_SOURCE','commit':source,'tree':git('rev-parse','HEAD^{tree}'),'parents':git('show','-s','--format=%P','HEAD').split(),'git_status':status,'freeze_id':seal['freeze_id'],'preexecution_sha256':sha(R6/'preexecution.json'),'contract_sha256':sha(R6/'CONTRACT.md'),'scenarios_sha256':sha(R6/'fixtures/scenarios.json'),'historical_files_preserved':len(baseline['files']),'counts':corpus['counts'],'qualification_run_performed':False,'notice':'Integrity and source attribution only; not proof of execution, provenance authenticity or outside attestation.'}
    report['public_manifest_sha256']=sha(ROOT/'PUBLIC_MANIFEST.json')
    report['oracle_implementation_seal_sha256']=sha(R6/'oracle-implementation-seal.json')
    report['input_sha256']=load(ROOT/'PUBLIC_MANIFEST.json')['files']
    if args.output:
        if args.output.exists():raise ValueError('Fresh source receipt required')
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()

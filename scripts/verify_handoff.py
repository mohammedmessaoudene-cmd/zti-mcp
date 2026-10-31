#!/usr/bin/env python3
"""Verify the public package with Python's standard library only.

No shell, subprocess, network client, credential lookup or publication action.
--write-manifest records an intentional packaging snapshot after the required
files and preserved R4 hashes have passed checks; CI never uses that option.
This manifest detects changes. It is not a signature or a safety certificate.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath

ROOT=Path(__file__).resolve().parents[1]
MANIFEST='PUBLIC_MANIFEST.json'
FROZEN_MANIFEST_SHA256='fec612069c75359c22241a145373153d65a7d194e12bdaf2ab17b637fe67de33'
PINNED={
    'reference/authority.py':'0489bf76fc482558051e65ac3517aab9189109bc3d1647724e54211b623aa11f',
    'reference/run_r4.py':'56e382fa65a079ee8b24b03aa5a9d0874a09938400442a9c707cd54fa0394741',
}
ASSETS=['draft-messaoudene-zti-mcp-00.xml','draft-messaoudene-zti-mcp-00.txt','ZTI_MCP_SPECIFICATION_00_EN.pdf']
REQUIRED={
    'README.md','LICENSE','NOTICE','LICENSE_SCOPE.md','LICENSES/CC-BY-4.0.txt','THIRD_PARTY_NOTICES.md',
    'requirements.txt','.gitignore','.gitattributes','.github/workflows/reproduce.yml',
    'reference/authority.py','reference/run_r4.py','reference/verify_examples.py',
    'reference/preexecution_manifest.json','reference/cases.json','reference/CONTRACT.txt',
    'reference/ORACLE_INTERPRETATION.txt','reference/CENTRAL_SOURCE_SNAPSHOT.txt',
    'scripts/verify_handoff.py','scripts/reproduce.ps1','docs/REPRODUCE_WINDOWS.md',
    'docs/PUBLIC_PACKAGE_SCOPE.md','docs/evidence/COVERAGE_R4.txt',
    'docs/evidence/OBSERVATION_ERRATA.txt','docs/fr/NOTE_IMPLEMENTATION_ET_STRATEGIE_FR.txt',
    'results/initial_summary.json','results/coordinator_summary.json','results/observations.json',
    'results/review_probes.json','results/SOURCE_PROVENANCE.json',
    'examples/action.json','examples/root_mandate.jwt','examples/child_mandate.jwt',
    'examples/ict.jwt','examples/public_jwk.json','examples/receipt.json',
    'examples/VERIFICATION.json','examples/wire/MANIFEST.json',
    'schema/zti-common-0.1.schema.json','schema/zti-action-0.1.schema.json',
    'schema/zti-mandate-0.1.schema.json','schema/zti-mandate-claims-0.1.schema.json',
    'schema/zti-ict-claims-0.1.schema.json','schema/zti-control-0.1.schema.json',
}|{'docs/specification/'+n for n in ASSETS}|{'release_assets/'+n for n in ASSETS}
IGNORED_TOP={'.git','.venv','work','__pycache__'}
TEXT_SUFFIXES={'.py','.json','.md','.txt','.xml','.yml','.yaml','.ps1','.jwt'}

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

def load(path):
    with path.open(encoding='utf-8') as stream:return json.load(stream)

def inventory():
    found={}
    for path in ROOT.rglob('*'):
        rel=path.relative_to(ROOT)
        if rel.parts[0] in IGNORED_TOP or '__pycache__' in rel.parts:continue
        if path.is_symlink():raise ValueError('Symlink is outside the public package contract: '+rel.as_posix())
        if path.is_file() and rel.as_posix()!=MANIFEST:found[rel.as_posix()]=path
    return found

def safe_manifest_name(name):
    p=PurePosixPath(name)
    if not name or p.is_absolute() or '..' in p.parts or '\\' in name or ':' in name:
        raise ValueError('Manifest path must be relative and portable.')
    return name

def fresh_report_path(value):
    raw=value.absolute()
    work=ROOT/'work'
    target=raw.resolve()
    if work.is_symlink() or target==work.resolve() or not target.is_relative_to(work.resolve()):
        raise ValueError('Generated reports must be fresh files under work/.')
    if any(path.is_symlink() for path in (raw,*raw.parents)):
        raise ValueError('Generated report paths may not use symbolic links.')
    if target.exists():raise ValueError('Generated report target already exists; use a fresh name.')
    return target

def check_summary(path):
    data=load(path)
    expected={'scenario_count':40,'expected_observations_matched':40,'targeted_mutants':3,'mutants_detected':3,'child_processes':13,'errors':0}
    for key,value in expected.items():
        if data.get(key)!=value:raise ValueError('Unexpected aggregate '+key)
    for path_name,expected_hash in PINNED.items():
        if data.get('source_sha256',{}).get(Path(path_name).name)!=expected_hash:
            raise ValueError('Aggregate uses different source: '+path_name)
    return expected

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write-manifest',action='store_true',help='Record an intentional packaging snapshot; never used by CI.')
    parser.add_argument('--summary',type=Path,help='Also check one completed reproduction SUMMARY.json.')
    parser.add_argument('--report',type=Path,help='Optionally write the verification report; use work/ for generated output.')
    args=parser.parse_args()
    report_path=fresh_report_path(args.report) if args.report is not None else None
    files=inventory();missing=sorted(REQUIRED-set(files))
    if missing:raise ValueError('Required files missing: '+', '.join(missing))
    for name,expected in PINNED.items():
        if digest(files[name])!=expected:raise ValueError('Preserved R4 source differs: '+name)
    if digest(ROOT/'reference/preexecution_manifest.json')!=FROZEN_MANIFEST_SHA256:
        raise ValueError('The preserved R4 preexecution manifest differs.')
    frozen=load(ROOT/'reference/preexecution_manifest.json')['sha256']
    for name,expected in frozen.items():
        safe_manifest_name(name)
        if digest(ROOT/'reference'/name)!=expected:raise ValueError('Frozen R4 input differs: '+name)
    corpus=load(ROOT/'reference/cases.json')
    if len(corpus['cases'])!=40 or len(corpus['mutants'])!=3:raise ValueError('Unexpected corpus size')
    for name in ASSETS:
        if digest(ROOT/'docs/specification'/name)!=digest(ROOT/'release_assets'/name):
            raise ValueError('Release asset differs from specification copy: '+name)
    for name,path in files.items():
        lower=name.lower()
        if any(lower.endswith(s) for s in ['.sqlite','.sqlite-wal','.sqlite-shm','.db','.log','.rng','.zip']):
            raise ValueError('Private/bulk/toolchain artifact in public tree: '+name)
        if Path(name).name.startswith('reference.RFC.'):
            raise ValueError('Downloaded bibliography file is outside the public package: '+name)
        if path.suffix.lower() in TEXT_SUFFIXES:
            value=path.read_text(encoding='utf-8')
            # These identify private build locations, not public URL references.
            patterns=['/workspace/'+'scratch/','/root/'+'\\.codex',r'C:\\Users\\[^\\]+\\']
            if any(re.search(pattern,value) for pattern in patterns):
                raise ValueError('Private machine path found in public text: '+name)
    actual={name:digest(path) for name,path in sorted(files.items())}
    if args.write_manifest:
        value={'format':'zti-mcp-public-handoff-v1','hash_algorithm':'SHA-256','files':actual,
               'notice':'Change detection only, not an authenticated signature or conformance certificate.'}
        (ROOT/MANIFEST).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n',encoding='utf-8',newline='\n')
    manifest=load(ROOT/MANIFEST)
    if manifest.get('format')!='zti-mcp-public-handoff-v1':raise ValueError('Unknown manifest format')
    expected={safe_manifest_name(name):value for name,value in manifest['files'].items()}
    if expected!=actual:
        changed=sorted(set(expected)^set(actual)|{name for name in set(expected)&set(actual) if expected[name]!=actual[name]})
        raise ValueError('Public manifest mismatch: '+', '.join(changed))
    summary=check_summary(args.summary) if args.summary is not None else None
    report={'status':'VERIFIED','files_hashed':len(actual),'frozen_inputs_verified':len(frozen),
            'core_sources':PINNED,'scenario_definitions':40,'mutant_definitions':3,
            'release_assets_equal':True,'checked_reproduction_summary':summary,
            'manifest_written':args.write_manifest,'external_processes_started':0,'network_calls':0,
            'publication_performed':False,'manifest_sha256':digest(ROOT/MANIFEST)}
    if report_path is not None:
        report_path.parent.mkdir(parents=True,exist_ok=True)
        with report_path.open('x',encoding='utf-8',newline='\n') as stream:
            stream.write(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps(report,indent=2,sort_keys=True))

if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError) as error:
        print('HANDOFF VERIFICATION FAILED: '+str(error),file=sys.stderr)
        raise SystemExit(1)

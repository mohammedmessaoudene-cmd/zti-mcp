"""Read-only-by-default R5 inventory, baseline and exact-source gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
MANIFEST=ROOT/'integration/MANIFEST.json'
BASELINE=ROOT/'docs/evidence/baseline-v0.1.0-research/PUBLIC_MANIFEST.json'
FROZEN={'contract.md':'5d85f4ecf6d1e0f0fceffacf3d05e260c5e673abd64bc15c3faf4e6709fc3ad4','scenarios.json':'4ff940eb1c9ee00140472953f257026d7dd21eb296fcde10544d5368d868214f'}
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):
    return json.loads(path.read_text(encoding='utf-8'))
def git(*args):
    return subprocess.run(['git','-C',str(ROOT),*args],check=True,capture_output=True).stdout.decode().strip()
def inventory():
    files={}
    for path in (ROOT/'integration').rglob('*'):
        if '__pycache__' in path.parts:
            continue
        if path.is_symlink() or (hasattr(path,'is_junction') and path.is_junction()):
            raise ValueError('Link outside R5 package contract')
        if path.is_file() and path!=MANIFEST:
            files[path.relative_to(ROOT).as_posix()]=sha(path)
    files['.github/workflows/stdio-r5.yml']=sha(ROOT/'.github/workflows/stdio-r5.yml')
    return dict(sorted(files.items()))
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write-manifest',action='store_true')
    parser.add_argument('--expected-sha',default=os.environ.get('EXPECTED_SOURCE_SHA'))
    parser.add_argument('--summary',type=Path)
    parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    for name,expected in FROZEN.items():
        assert sha(HERE/name)==expected, 'Frozen contract differs: '+name
    assert sha(BASELINE)=='8f3aa96f4e5089773694b5ccac1196391321dbedb833a0da1cd1c8ee9536a137'
    historical=read(BASELINE)['files']
    protected={name:expected for name,expected in historical.items() if name.startswith(('reference/','examples/','schema/','results/','docs/specification/','release_assets/'))}
    for name,expected in protected.items():
        assert sha(ROOT/name)==expected,'Historical R4 file changed: '+name
    files=inventory()
    if args.write_manifest:
        MANIFEST.write_text(json.dumps({'format':'zti-mcp-stdio-r5-sources-v1','files':files,'notice':'Intentional reviewed R5 source inventory; not an authenticated signature or a conformance certificate.'},indent=2,sort_keys=True)+'\n',encoding='utf-8',newline='\n')
    current=read(MANIFEST)
    assert current['format']=='zti-mcp-stdio-r5-sources-v1'
    for name in current['files']:
        rel=PurePosixPath(name)
        assert not rel.is_absolute() and '..' not in rel.parts and ':' not in name and '\\' not in name
    assert current['files']==files,'R5 source inventory differs'
    commit=git('rev-parse','HEAD')
    if args.expected_sha:
        assert commit==args.expected_sha,'Actual checkout differs from required source revision'
        assert git('status','--porcelain')=='','Tracked/untracked source changes at required revision'
    if args.summary:
        summary=read(args.summary)
        required={'status':'PASS','full_campaign':True,'scenario_count':8,'normal_variant_count':20,'normal_variants_matched':20,'integration_mutant_count':2,'integration_mutants_detected':2,'infrastructure_error_count':0}
        assert all(summary.get(k)==v for k,v in required.items()),'R5 aggregate gate incomplete'
        assert summary['source_commit']==commit and summary['source_git_status']=='','Campaign source identity differs'
        source=read(args.summary.parent/'SOURCE.json')
        expected_inputs={name:value for name,value in files.items() if name.startswith('integration/stdio_r5/')}
        assert source['inputs']==expected_inputs,'Campaign source bytes differ from verified inventory'
    report={'status':'PASS','actual_source_commit':commit,'expected_source_commit':args.expected_sha,'r5_files_hashed':len(files),'historical_r4_files_unchanged':len(protected),'contract_hashes':FROZEN,'integration_manifest_sha256':sha(MANIFEST),'global_manifest_sha256':sha(ROOT/'PUBLIC_MANIFEST.json'),'manifest_written':args.write_manifest,'full_campaign_verified':bool(args.summary)}
    if args.report:
        target=args.report.resolve()
        assert target.is_relative_to((ROOT/'work').resolve()) and not target.exists(),'Report must be fresh under ignored work/'
        target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('x',encoding='utf-8',newline='\n') as f:
            json.dump(report,f,indent=2)
    print(json.dumps(report,indent=2))
if __name__=='__main__':
    main()

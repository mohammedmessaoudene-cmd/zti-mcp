#!/usr/bin/env python3
"""Build/install and run R6 in a fresh directory, or audit data without running it.

Declared live/build prerequisites: a Git checkout, Python 3.12, Node 24.22.2
and npm, network access to official registries. Audit needs Python 3.12 and
the trusted source package. Dependencies are local; no global upgrades.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
R6 = ROOT / 'successor' / 'r6'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n', encoding='utf-8', newline='\n')

def run(command, *, cwd, journal):
    """No shell interpolation; retain failures and the actual invocation."""
    env = os.environ.copy()
    env.pop('PYTHONPATH', None)
    env.pop('PYTHONHOME', None)
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    process = subprocess.run([str(x) for x in command], cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1200)
    record = {'argv':[str(x) for x in command], 'cwd':str(cwd), 'returncode':process.returncode, 'output':process.stdout.decode('utf-8', 'replace')}
    with journal.open('a', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(record, ensure_ascii=False)+'\n')
    print(record['output'][-4000:], flush=True)
    if process.returncode:
        raise RuntimeError('Subprocess failed; retained in '+str(journal))
    return record['output'].strip()

def safe_name(name):
    path = PurePosixPath(name)
    if not name or not name.isascii() or any(ord(c)<32 for c in name) or path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name:
        raise ValueError('Unsafe archive member')
    devices={'CON','PRN','AUX','NUL'}|{'COM'+str(i) for i in range(1,10)}|{'LPT'+str(i) for i in range(1,10)}
    if str(path)!=name.rstrip('/') or any(part.rstrip(' .')!=part or part.split('.')[0].upper() in devices or any(c in part for c in '<>"|?*') for part in path.parts):
        raise ValueError('Archive member is not a canonical portable file path')
    return path

def unpack_zip(archive, output):
    """Data only. Reject links, duplicates and unbounded expansion."""
    with zipfile.ZipFile(archive) as source:
        names = set()
        total = 0
        for item in source.infolist():
            path = safe_name(item.filename)
            if item.filename in names or (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('Duplicate or linked archive member')
            names.add(item.filename)
            total += item.file_size
            if total > 300_000_000 or len(names) > 20000:
                raise ValueError('Evidence expansion limit')
            target = output.joinpath(*path.parts)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as stream:
                    stream.write(source.read(item))

def unpack_client(archive, output):
    """Install original client sources from a distribution, never tar links."""
    with tarfile.open(archive, 'r:gz') as source:
        seen = set()
        total = 0
        for member in source.getmembers():
            path = safe_name(member.name)
            if path.parts[0] != 'package' or member.name in seen or not (member.isfile() or member.isdir()):
                raise ValueError('Invalid client distribution member')
            seen.add(member.name)
            total += member.size
            if total > 10_000_000:
                raise ValueError('Client distribution expansion limit')
            target = output.joinpath(*path.parts[1:])
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as stream:
                    stream.write(source.extractfile(member).read())

def stage(source, target):
    files = {}
    for item in source.rglob('*'):
        if any(part in {'__pycache__', 'node_modules', 'build', 'dist'} or part.endswith('.egg-info') for part in item.relative_to(source).parts):
            continue
        if item.is_symlink():
            raise ValueError('Linked source not permitted')
        if item.is_file():
            rel = item.relative_to(source)
            dest = target / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item, dest)
            if sha(item) != sha(dest):
                raise ValueError('Staged source differs')
            files[rel.as_posix()] = sha(dest)
    return files

def expected_project_files(public_files, project):
    prefix='successor/r6/'+project+'/'
    result={}
    for name,value in public_files.items():
        if not name.startswith(prefix):continue
        relative=name.removeprefix(prefix)
        if any(part in {'__pycache__','node_modules','build','dist'} or part.endswith('.egg-info') for part in Path(relative).parts):continue
        result[relative]=value
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['live','audit','build'], required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--distributions', type=Path, help='Use the same previously built distributions; do not rebuild.')
    parser.add_argument('--runtime-dir', type=Path, help='Fresh installed application directory outside the checkout; default is a retained temporary directory.')
    parser.add_argument('--node', default='node')
    parser.add_argument('--npm', default='npm.cmd' if os.name == 'nt' else 'npm')
    args = parser.parse_args()
    if sys.version_info[:2] != (3,12):
        raise ValueError('Python 3.12 required')
    output = args.output_dir.resolve()
    if output.exists() or output == ROOT or not (output.is_relative_to(ROOT/'work') or not output.is_relative_to(ROOT)):
        raise ValueError('Use a fresh work/ directory or a fresh directory outside the checkout')
    output.mkdir(parents=True)
    if args.runtime_dir:
        runtime_root=args.runtime_dir.resolve()
        if runtime_root.exists() or runtime_root.is_relative_to(ROOT) or 'node_modules' in runtime_root.parts:
            raise ValueError('Runtime must be a fresh directory outside checkout and node_modules')
        runtime_root.mkdir(parents=True)
    else:
        runtime_root=Path(tempfile.mkdtemp(prefix='zti-r6-installed-')).resolve()
        if runtime_root.is_relative_to(ROOT) or 'node_modules' in runtime_root.parts:
            raise ValueError('Temporary runtime is inside checkout/node_modules; specify an outside --runtime-dir')
    journal = output / 'BOOTSTRAP.jsonl'
    receipt = {'format':'r6-bootstrap-v1','mode':args.mode,'status':'RUNNING','python':sys.version,'runtime_directory':str(runtime_root),'source':{},'dist_hashes':{}}
    pending_build=None
    try:
        run([sys.executable,'-I',ROOT/'scripts/verify_handoff.py'],cwd=ROOT,journal=journal)
        initial_manifest_sha=sha(ROOT/'PUBLIC_MANIFEST.json')
        initial_public_files=json.loads((ROOT/'PUBLIC_MANIFEST.json').read_text(encoding='utf-8'))['files']
        if args.mode!='audit':
            run([sys.executable,'-I',ROOT/'scripts/verify_r6.py','--output',output/'SOURCE.json'],cwd=ROOT,journal=journal)
        subprocess.run([sys.executable,'-I','-m','venv',str(runtime_root/'python')], check=True, timeout=120)
        python = runtime_root/'python'/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
        run([python,'-I','-m','pip','install','--disable-pip-version-check','--no-input','--require-hashes','--only-binary=:all:','--cache-dir',output/'pip-cache','--report',output/'PIP_INSTALL_REPORT.json','-r',R6/'locks/requirements.lock'],cwd=output,journal=journal)
        if args.mode == 'audit':
            if not args.evidence:
                raise ValueError('--evidence required for audit')
            evidence = output/'evidence'
            unpack_zip(args.evidence.resolve(), evidence)
            receipt['archive_sha256'] = sha(args.evidence.resolve())
            run([python,'-I',R6/'oracle/audit.py','--evidence-dir',evidence,'--output',output/'AUDIT.json'],cwd=output,journal=journal)
        else:
            node_version = run([args.node,'--version'],cwd=output,journal=journal)
            if node_version != 'v24.22.2':
                raise ValueError('Use exactly Node v24.22.2')
            receipt['node'] = node_version
            receipt['npm'] = run([args.npm,'--version'],cwd=output,journal=journal)
            if args.distributions:
                dist = args.distributions.resolve()
                if not dist.is_dir():
                    raise ValueError('Distribution set missing')
            else:
                dist = output/'distributions'
                dist.mkdir()
                for project in ('provider','consumer'):
                    target = output/'staging'/project
                    receipt['source'][project] = stage(R6/project,target)
                    if receipt['source'][project]!=expected_project_files(initial_public_files,project):
                        raise ValueError('Staged project source differs from the initial verified public manifest')
                    run([python,'-I','-m','pip','wheel','--no-deps','--no-build-isolation','--wheel-dir',dist,target],cwd=output,journal=journal)
                target = output/'staging'/'clients'
                receipt['source']['clients'] = stage(R6/'clients',target)
                if receipt['source']['clients']!=expected_project_files(initial_public_files,'clients'):
                    raise ValueError('Staged client source differs from initial manifest')
                run([args.npm,'pack','--ignore-scripts','--pack-destination',dist],cwd=target,journal=journal)
            artifacts = sorted([*dist.glob('*.whl'), *dist.glob('*.tgz')])
            if len([x for x in artifacts if x.suffix=='.whl']) != 2 or len([x for x in artifacts if x.suffix=='.tgz']) != 1:
                raise ValueError('Expected exactly two project wheels and one TypeScript tgz')
            receipt['dist_hashes'] = {x.name:sha(x) for x in artifacts}
            write(output/'DISTRIBUTIONS.json', receipt['dist_hashes'])
            if args.distributions:
                build = json.loads((dist/'BUILD.json').read_text(encoding='utf-8'))
                source = json.loads((output/'SOURCE.json').read_text(encoding='utf-8'))
                if build.get('status')!='PASS' or build['source']['commit']!=source['commit'] or build['source']['tree']!=source['tree'] or build['files']!=receipt['dist_hashes']:
                    raise ValueError('Distributions do not match this exact source commit/tree/hash set')
            else:
                pending_build={'format':'zti-r6-distributions-v1','status':'PASS','source':json.loads((output/'SOURCE.json').read_text(encoding='utf-8')),'files':receipt['dist_hashes'],'staged_project_sources':receipt['source'],'lock_sha256':sha(R6/'locks/requirements.lock')}
            run([sys.executable,'-I',R6/'distribution_guard.py','--distributions',dist,'--public-manifest',ROOT/'PUBLIC_MANIFEST.json','--output',output/'DISTRIBUTION_GUARD.json'],cwd=output,journal=journal)
            if args.mode == 'live':
                run([python,'-I','-m','pip','install','--no-deps','--report',output/'OWN_INSTALL_REPORT.json',*[x for x in artifacts if x.suffix=='.whl']],cwd=output,journal=journal)
                run([python,'-I','-m','pip','check'],cwd=output,journal=journal)
                run([python,'-I',R6/'runtime_receipt.py','--expected-public-manifest',ROOT/'PUBLIC_MANIFEST.json','--output',output/'RUNTIME.private.json','--portable-output',output/'RUNTIME.portable.json'],cwd=output,journal=journal)
                client = runtime_root/'client-installed'
                unpack_client(next(x for x in artifacts if x.suffix=='.tgz'),client)
                shutil.copyfile(client/'runtime-lock.json',client/'package-lock.json')
                if sha(client/'runtime-lock.json')!=sha(client/'package-lock.json') or sha(client/'runtime-lock.json')!=sha(R6/'clients/runtime-lock.json'):
                    raise ValueError('Extracted lock/copy differs from the frozen lock')
                receipt['installed_client_sources']={p.relative_to(client).as_posix():sha(p) for p in client.rglob('*') if p.is_file()}
                run([args.npm,'ci','--ignore-scripts','--no-audit','--no-fund','--cache',output/'npm-cache'],cwd=client,journal=journal)
                campaign_command=[python,'-I',R6/'campaign/run.py','--output-dir',output/'campaign','--python',python,'--node',args.node,'--client-dir',client,'--private-root',runtime_root/'campaign-private','--runtime-receipt',output/'RUNTIME.portable.json','--distribution-guard',output/'DISTRIBUTION_GUARD.json','--distribution-manifest',output/'DISTRIBUTIONS.json','--source-receipt',output/'SOURCE.json']
                if args.distributions:campaign_command.extend(['--build-receipt',dist/'BUILD.json'])
                run(campaign_command,cwd=output,journal=journal)
                run([python,'-I',R6/'oracle/audit.py','--evidence-dir',output/'campaign','--output',output/'AUDIT.json'],cwd=output,journal=journal)
        run([sys.executable,'-I',ROOT/'scripts/verify_handoff.py'],cwd=ROOT,journal=journal)
        if sha(ROOT/'PUBLIC_MANIFEST.json')!=initial_manifest_sha:
            raise ValueError('Public source manifest changed during execution')
        if args.mode!='audit':
            initial_source=json.loads((output/'SOURCE.json').read_text(encoding='utf-8'))
            run([sys.executable,'-I',ROOT/'scripts/verify_r6.py','--expected-sha',initial_source['commit'],'--output',output/'SOURCE_FINAL.json'],cwd=ROOT,journal=journal)
            final_source=json.loads((output/'SOURCE_FINAL.json').read_text(encoding='utf-8'))
            if any(initial_source[key]!=final_source[key] for key in ('commit','tree','preexecution_sha256')):
                raise ValueError('Source/freeze identity changed during execution')
        if pending_build is not None:
            pending_build['final_source']=final_source
            write(dist/'BUILD.json',pending_build)
        receipt['status'] = 'PASS'
    except BaseException as error:
        receipt['status'] = 'FAIL'
        receipt['error'] = str(error)
        raise
    finally:
        write(output/'BOOTSTRAP.json',receipt)

if __name__ == '__main__':
    main()

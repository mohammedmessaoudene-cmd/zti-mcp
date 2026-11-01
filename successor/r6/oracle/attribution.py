"""Check captured identities against trusted source, never execute pack code.

Internal consistency is not authentication or outside runner attestation.
"""
import hashlib
import base64
import json
import re
import subprocess
from pathlib import Path
from state import need

ROOT=Path(__file__).resolve().parents[3]
R6=ROOT/'successor/r6'
def load(path):return json.loads(path.read_text(encoding='utf-8'))
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args],text=True).strip()

def audit_attribution(directory, manifests, *, expected_sha=None):
    root=Path(directory);source=load(root/'SOURCE.json');dists=load(root/'DISTRIBUTIONS.json')
    files=load(ROOT/'PUBLIC_MANIFEST.json')['files']
    for name,value in files.items():need(sha(ROOT/name)==value,'trusted checkout differs from its source manifest '+name)
    commit=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}')
    need(not git('status','--porcelain','--untracked-files=normal'),'trusted audit checkout is dirty')
    need(source.get('status')=='PASS' and source.get('git_status')=='','campaign source was not clean and verified')
    need(source.get('commit')==commit and source.get('tree')==tree,'campaign exact source differs from trusted checkout')
    need(expected_sha is None or commit==expected_sha,'campaign source differs from requested exact SHA')
    need(source.get('parents')==git('show','-s','--format=%P','HEAD').split(),'source parent identity differs')
    for field,name in [('preexecution_sha256','preexecution.json'),('contract_sha256','CONTRACT.md'),('scenarios_sha256','fixtures/scenarios.json')]:
        need(source.get(field)==sha(R6/name),'source freeze identity differs '+field)
    need(source.get('public_manifest_sha256')==sha(ROOT/'PUBLIC_MANIFEST.json'),'source public manifest identity differs')
    need(source.get('oracle_implementation_seal_sha256')==sha(R6/'oracle-implementation-seal.json'),'source reader implementation seal differs')
    need(source.get('input_sha256')==files,'source closed file map differs from trusted public manifest')
    fingerprints=load(R6/'DEPENDENCY_ENTRY_POINTS.json')
    need(fingerprints.get('format')=='zti-r6-dependency-entry-points/1' and fingerprints.get('status')=='VERIFIED_FROM_PINNED_OFFICIAL_ARCHIVES','dependency entry fingerprints missing/unverified')
    for field,path in [('npm_runtime_lock_sha256','clients/runtime-lock.json'),('pypi_provenance_sha256','locks/pypi_provenance.json'),('python_lock_sha256','locks/requirements.lock')]:
        need(fingerprints['source_inputs'].get(field)==sha(R6/path),'dependency fingerprints derive from another frozen lock')
    upstream={(release['name'],release['version']):{wheel['filename']:wheel for wheel in release['wheels']} for release in load(R6/'locks/pypi_provenance.json')['releases']}
    for module,entry in fingerprints['python'].items():
        need(entry['module_entry']==module+'/__init__.py' and re.fullmatch('[0-9a-f]{64}',entry['entry_sha256']) and bool(entry['archives']),'invalid dependency entry fingerprint')
        allowed=upstream[(entry['distribution'],entry['version'])]
        for archive in entry['archives']:
            pinned=allowed[archive['filename']]
            need(archive['archive_sha256']==pinned['digests']['sha256'] and archive['url']==pinned['url'] and archive['entry_sha256']==entry['entry_sha256'],'Python entry fingerprint is not linked to pinned archives')
    ts_pin=load(R6/'clients/runtime-lock.json')['packages']['node_modules/@modelcontextprotocol/client']
    ts_entry=fingerprints['typescript']
    need(ts_entry['version']==ts_pin['version'] and ts_entry['archive_url']==ts_pin['resolved'] and ts_entry['locked_integrity']==ts_pin['integrity'],'TypeScript entry fingerprint derives from another package')
    need('sha512-'+base64.b64encode(bytes.fromhex(ts_entry['archive_sha512'])).decode('ascii')==ts_pin['integrity'] and re.fullmatch('[0-9a-f]{64}',ts_entry['entry_sha256']),'TypeScript archive integrity/fingerprint differs')
    names={'zti_mcp_r6-0.3.0-py3-none-any.whl','zti_r6_demo-0.3.0-py3-none-any.whl','zti-r6-clients-0.3.0-research.tgz'}
    need(set(dists)==names and all(type(h) is str and re.fullmatch('[0-9a-f]{64}',h) for h in dists.values()),'distribution set must contain exact two wheels and one tgz')
    summary=load(root/'SUMMARY.json')
    need(summary.get('source')==source,'summary source differs from campaign source')
    need(summary.get('full_campaign') is True and summary.get('selection') is None,'selected run is not a complete qualification')
    need(summary.get('status')=='EXECUTION_COMPLETE_PENDING_INDEPENDENT_AUDIT' and not summary.get('infrastructure_errors'),'campaign execution incomplete or has infrastructure errors')
    guard=load(root/'DISTRIBUTION_GUARD.json');guard_sha=sha(root/'DISTRIBUTION_GUARD.json')
    need(summary.get('distribution_guard_sha256')==guard_sha,'summary not linked to actual preinstall distribution inspection')
    need(guard.get('format')=='zti-r6-distribution-guard/1' and guard.get('status')=='PASS' and guard.get('code_imported') is False and guard.get('archives_extracted') is False and guard.get('source_bound_before_install_or_import') is True,'preinstall archive inspection missing/failed')
    need(guard.get('public_manifest_sha256')==source['public_manifest_sha256'],'archive inspection used another source manifest')
    need({name:entry['sha256'] for name,entry in guard['archives'].items()}==dists,'inspected archive bytes differ from distribution receipts')
    build_paths=[p for p in (root/'BUILD.json',root/'bootstrap/BUILD.json') if p.exists()]
    declared_build=summary.get('build_receipt_sha256')
    if declared_build is not None:
        need((root/'BUILD.json').exists() and sha(root/'BUILD.json')==declared_build,'campaign build receipt missing/different')
    builds=[]
    for path in build_paths:
        build=load(path);builds.append(build)
        need(build.get('format')=='zti-r6-distributions-v1' and build.get('status')=='PASS','build not finalized as PASS')
        need(build.get('source')==source and build.get('final_source')==source,'build source/final source differs from this exact commit receipt')
        need(build.get('files')==dists and build.get('lock_sha256')==sha(R6/'locks/requirements.lock'),'build distributions or dependency lock differ')
        staged={}
        for project in ('provider','consumer','clients'):
            prefix='successor/r6/'+project+'/'
            staged[project]={name.removeprefix(prefix):h for name,h in files.items() if name.startswith(prefix)}
        need(build.get('staged_project_sources')==staged,'build staged source map differs from verified source')
    need(not builds or all(build==builds[0] for build in builds),'campaign/bootstrap build receipts disagree')
    runtime=load(root/'RUNTIME.json')
    need(summary.get('runtime_receipt_sha256')==sha(root/'RUNTIME.json'),'summary is not linked to the observed installed runtime')
    need(runtime.get('format')=='zti-r6-runtime-portable/1' and runtime.get('status')=='PASS','installed runtime observation missing/failed')
    need(runtime.get('expected_public_manifest_sha256')==source['public_manifest_sha256'],'installed runtime observed another public manifest')
    need(runtime['python']['version_info'][:2]==[3,12] and all(runtime['python'].get(k) is True for k in ('isolated','environment_paths_disabled','user_site_disabled')),'installed interpreter identity/isolation differs')
    need(runtime.get('own_modules_outside_checkout') is True and runtime.get('own_installations_editable') is False and runtime.get('own_source_closed_sets_match') is True,'own distributions were not observed as isolated archive installations')
    own={'zti_mcp_r6':('provider','zti-mcp-r6','zti_mcp_r6-0.3.0-py3-none-any.whl'),
         'zti_r6_demo':('consumer','zti-r6-demo','zti_r6_demo-0.3.0-py3-none-any.whl')}
    for module,(project,distribution,wheel) in own.items():
        entry=runtime['packages'][module];prefix=f'successor/r6/{project}/src/{module}/'
        expected={n.removeprefix(prefix):h for n,h in files.items() if n.startswith(prefix) and n.endswith('.py')}
        need(entry.get('files')==expected and entry.get('source_prefix')==prefix,'installed own closed Python source map differs '+module)
        need(entry.get('distribution')==distribution and entry.get('version')=='0.3.0' and entry.get('installation_kind')=='archive' and entry.get('editable') is False,'own distribution metadata differs')
        need(entry.get('installed_archive_sha256')==dists[wheel],'loaded own installation differs from built wheel')
        need(entry.get('module_entry_sha256')==expected['__init__.py'],'loaded own module entry differs')
    for module,distribution,version in [('mcp','mcp','2.3.0'),('mcp_types','mcp-types','2.3.0'),('cryptography','cryptography','50.0.2')]:
        entry=runtime['packages'][module]
        need(entry.get('distribution')==distribution and entry.get('version')==version,'actual Python SDK/crypto identity differs')
        need(entry.get('module_entry_sha256')==fingerprints['python'][module]['entry_sha256'],'actual Python SDK/crypto entry bytes differ from pinned upstream archive')
    for role,module,relative in [('provider','zti_mcp_r6','__main__.py'),('consumer','zti_r6_demo','client.py')]:
        entry=runtime['entrypoints'][role]
        need(entry.get('relative_file')==relative and entry.get('sha256')==runtime['packages'][module]['files'][relative],'installed entry point differs')
    expected_py={'entry':files['successor/r6/consumer/src/zti_r6_demo/client.py'],'binding':files['successor/r6/consumer/src/zti_r6_demo/binding.py']}
    expected_ts={n:files['successor/r6/clients/'+n] for n in ('client.ts','binding.ts','runtime-lock.json')}
    ts_sdk_hashes=set();connections=0
    def python_identity(value):
        need(str(value.get('python','')).startswith('3.12.'),'actual Python client is not 3.12')
        need(value.get('versions')=={'mcp':'2.3.0','mcp-types':'2.3.0','zti-r6-demo':'0.3.0'},'actual Python client versions differ')
        for key,h in expected_py.items():need(value.get(key,{}).get('sha256')==h,'actual loaded Python client source differs '+key)
    def ts_identity(value, *, vector=False):
        need(value.get('node')=='v24.22.2','actual Node runtime differs')
        if vector:
            need(value.get('sdk_version')=='2.4.0','actual TypeScript SDK version differs')
            for n,h in expected_ts.items():need(value.get('files',{}).get(n,{}).get('sha256')==h,'actual TS vector source/lock differs')
        else:
            for key,name in [('entry','client.ts'),('binding','binding.ts'),('runtime_lock','runtime-lock.json')]:
                need(value.get(key,{}).get('sha256')==expected_ts[name],'actual loaded TypeScript source differs '+key)
            h=value.get('sdk_entry',{}).get('sha256')
            need(type(h) is str and re.fullmatch('[0-9a-f]{64}',h),'actual TS SDK module hash missing')
            ts_sdk_hashes.add(h)
    for case_dir,manifest in manifests:
        need(manifest.get('source')==source and manifest.get('distributions')==dists,'case source/distribution identity differs '+manifest['case_id'])
        need(manifest.get('runtime_receipt_sha256')==sha(root/'RUNTIME.json'),'case is not linked to the observed installed runtime')
        need(manifest.get('distribution_guard_sha256')==guard_sha and manifest.get('build_receipt_sha256')==declared_build,'case distribution/build provenance links differ')
        if manifest['category']=='synthetic':continue
        for connection in load(case_dir/'observation.json')['connections']:
            connections+=1
            if connection['client']=='P':python_identity(connection['loaded'])
            elif connection['client']=='T':ts_identity(connection['loaded'])
            else:raise ValueError('unknown actual SDK client')
    for group,client in [('vectors','P'),('vectors','T'),('binding_auxiliary','P'),('binding_auxiliary','T'),('vectors','M01')]:
        value=load(root/group/(client+'.json'))
        need(value.get('process_returncode')==0 and value.get('source')==source,'vector source/process identity differs')
        if client=='P':python_identity(value['runtime'])
        else:ts_identity(value['runtime'],vector=True)
    need(ts_sdk_hashes=={ts_entry['entry_sha256']},'actual TS SDK entry bytes differ from pinned upstream archive')
    return {'status':'PASS','commit':commit,'tree':tree,'parents':source['parents'],
        'preexecution_sha256':source['preexecution_sha256'],'public_manifest_sha256':source['public_manifest_sha256'],
        'distributions':dists,'actual_connections_checked':connections,
        'distribution_guard_sha256':guard_sha,'build_receipt_checked':bool(builds),
        'python_packages':{n:v['version'] for n,v in runtime['packages'].items()},
        'typescript_sdk':'2.4.0','typescript_sdk_entry_sha256':next(iter(ts_sdk_hashes)),'node':'v24.22.2',
        'notice':'Captured identity and internal consistency only; not an independent runner attestation.'}

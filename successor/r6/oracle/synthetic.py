"""Verify exact synthetic evidence deltas and ordinary semantic rejection."""
import base64
import copy
import hashlib
import json
import sqlite3
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from evidence_io import snapshot
from primitives import b64,canonical,decoded,verify_signature_only
from state import need
from wire import jsonl

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def inventory(directory):return {p.relative_to(directory).as_posix():digest(p) for p in directory.rglob('*') if p.is_file()}

def verify_inventory(root, case_relative, expected, *, omit=()):
    case=root/case_relative
    actual=inventory(case)
    for name in omit:actual.pop(name,None)
    need(set(actual)==set(expected),'copied evidence path set differs from preserved inventory')
    export_path=root/'EXPORT_MANIFEST.json'
    exported=json.loads(export_path.read_text(encoding='utf-8'))['files'] if export_path.exists() else {}
    for name,value in expected.items():
        if actual[name]==value:continue
        record=exported.get((Path(case_relative)/name).as_posix(),{})
        need(record.get('original_sha256')==value and record.get('sha256')==actual[name] and record.get('byte_preserved') is False,'evidence changed without declared portable metadata projection')

def _replace(value,old,new):
    if type(value) is dict:return {k:_replace(v,old,new) for k,v in value.items()}
    if type(value) is list:return [_replace(v,old,new) for v in value]
    return value.replace(old,new) if type(value) is str else value

def _transform(value, name, old, new):
    """Independent description of the one frozen synthetic semantic delta."""
    if type(value) is dict:value={k:_transform(v,name,old,new) for k,v in value.items()}
    elif type(value) is list:return [_transform(v,name,old,new) for v in value]
    elif type(value) is str:return value.replace(old,new) if name=='SE01' else value
    if name.startswith('SD') and type(value) is dict and 'supportedVersions' in value:
        if name=='SD01':value.update(supportedVersions=['2025-03-26'],protocolVersion='2026-07-28')
        elif name=='SD02':value.setdefault('_meta',{})['io.modelcontextprotocol/serverCapabilities']=value.pop('capabilities')
        else:value.pop('supportedVersions');value['protocolVersion']='2026-07-28'
    return value

def _schema(path):
    connection=sqlite3.connect(path.resolve().as_uri()+'?mode=ro&immutable=1',uri=True)
    try:
        connection.execute('PRAGMA trusted_schema=OFF');connection.execute('PRAGMA query_only=ON')
        return list(connection.execute('SELECT name,type,tbl_name,sql FROM sqlite_schema ORDER BY name'))
    finally:connection.close()

def _rows(tables):
    return {name:sorted(canonical(row).decode('utf-8') for row in rows) for name,rows in tables.items()}

def _metadata(value):
    # Capture/coordinator monotonic nanoseconds are metadata, not bounded action
    # integers; preserve their exact JSON types without applying the action cap.
    return json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False)

def _exact_surfaces(original, case, name):
    """Compare wire, JSON views, SQL and unchanged files, never just rehashes."""
    names=inventory(original)
    copied=inventory(case);copied.pop('SYNTHETIC_COPY.json',None)
    need(set(copied)==set(names),'synthetic copy path set differs from its original')
    original_observation=json.loads((original/'observation.json').read_text(encoding='utf-8'))
    old=original_observation['steps']['r1']['result']['ict'];h,p,_=old.split('.')
    new=h+'.'+p+'.'+base64.urlsafe_b64encode(bytes(64)).decode().rstrip('=')
    # Check captures first, so a restored valid signature on the wire cannot be
    # hidden behind the still-invalid SQL/convenience-index copy.
    for relative in sorted(n for n in names if n.endswith('.jsonl')):
        before=jsonl(original/relative);after=jsonl(case/relative)
        need(len(before)==len(after),'synthetic copy changed captured record count')
        for source,actual in zip(before,after):
            expected=_transform(copy.deepcopy(source),name,old,new)
            if type(source.get('frame')) is dict and canonical(expected['frame'])!=canonical(source['frame']):
                expected['raw_base64']=base64.b64encode(canonical(expected['frame'])+b'\n').decode('ascii')
            need(_metadata(actual)==_metadata(expected),'synthetic wire/event delta differs from its exact prescribed transformation '+name)
    for relative in sorted(n for n in names if n.endswith('.json') and (name.startswith('SD') or not n.endswith('.tables.json'))):
        expected=_transform(json.loads((original/relative).read_text(encoding='utf-8')),name,old,new)
        if relative=='manifest.json':expected.update(category='synthetic',case_id=name,synthetic_id=name,source_case_id='I01__P',actual_sdk_execution=False)
        actual=json.loads((case/relative).read_text(encoding='utf-8'))
        need(_metadata(actual)==_metadata(expected),'synthetic JSON view delta differs from its exact prescribed transformation '+name+' '+relative)
    for relative in sorted(n for n in names if n.endswith('.sqlite')):
        source_db=original/relative;target_db=case/relative
        if name.startswith('SD'):
            need(digest(source_db)==digest(target_db),'discovery synthetic changed SQLite bytes')
            continue
        before=snapshot(source_db);expected=copy.deepcopy(before)
        if name=='SE01':expected=_replace(expected,old,new)
        elif name=='SE02':
            for row in expected['demo_records']:
                if row['label']=='alpha':row['label']='bravo'
        else:
            for row in expected['reservations']:
                if row['state']=='COMMITTED':
                    cost=decoded(row['cost_json']);need(cost['ops']['amount']=='2','SE03 original amount not two')
                    cost['ops']['amount']='1';row['cost_json']=canonical(cost).decode('utf-8')
        actual=snapshot(target_db)
        need(_rows(actual)==_rows(expected) and _schema(source_db)==_schema(target_db),'synthetic SQL delta/schema differs from frozen fault '+name)
        projection=target_db.with_suffix('.tables.json')
        if projection.exists():
            source_view=json.loads(source_db.with_suffix('.tables.json').read_text(encoding='utf-8'))
            target_view=json.loads(projection.read_text(encoding='utf-8'))
            expected_view={**source_view,'tables':actual} if 'tables' in source_view else actual
            need(canonical(target_view)==canonical(expected_view),'synthetic SQL JSON view differs from actual changed tables '+name)
    for relative in names:
        if relative.endswith(('.json','.jsonl','.sqlite')):continue
        need(digest(original/relative)==digest(case/relative),'synthetic copy changed an unrelated raw file '+relative)
    return {'wire_events':True,'json_views':True,'sql_and_schema':True,'unrelated_files':True}

def audit_synthetics(root, reports, corpus):
    root=Path(root);summary=json.loads((root/'SYNTHETICS.json').read_text(encoding='utf-8'))
    need(summary.get('original_unchanged') is True,'synthetic generator did not preserve original')
    original=root/'cases/base/I01__P'
    verify_inventory(root,'cases/base/I01__P',summary['original_inventory'])
    original_manifest=json.loads((original/'manifest.json').read_text(encoding='utf-8'))
    keys=original_manifest['public_keys']
    results=[]
    reasons={'SD01':'modern supportedVersions','SD02':'modern extension capabilities','SD03':'modern supportedVersions','SE01':'Invalid ES256 signature','SE02':'consumer actual effect differs','SE03':'recomputed cost/facts differ'}
    need(set(reports)==set(reasons),'synthetic set differs from frozen six copies')
    for spec in corpus['synthetics']:
        name=spec['id'];case=root/'cases/synthetic'/name
        receipt=json.loads((case/'SYNTHETIC_COPY.json').read_text(encoding='utf-8'))
        manifest=json.loads((case/'manifest.json').read_text(encoding='utf-8'))
        need(manifest.get('actual_sdk_execution') is False and receipt['kind']=='SYNTHETIC_COPIED_EVIDENCE_NOT_SDK_EXECUTION','synthetic copy mislabeled as a live execution')
        need(receipt['source_case_id']=='I01__P' and receipt['source_unchanged'] is True,'synthetic source identity')
        need(receipt['source_inventory_sha256']==hashlib.sha256(canonical(summary['original_inventory'])).hexdigest(),'synthetic source inventory digest')
        verify_inventory(root,'cases/synthetic/'+name,receipt['copied_files'],omit=('SYNTHETIC_COPY.json',))
        report=reports[name]
        need(report['status']=='VIOLATION' and reasons[name] in report.get('reason',''),'synthetic copy not rejected for its prescribed semantic reason '+name)
        exact=_exact_surfaces(original,case,name)
        if name.startswith('SD'):
            changed=0
            for wire_path in (original/'wire').glob('*.jsonl'):
                if wire_path.name.endswith('.lifecycle.jsonl'):continue
                before=jsonl(wire_path);after=jsonl(case/'wire'/wire_path.name)
                need(len(before)==len(after),'synthetic discovery changed number of captured frames')
                for old,new in zip(before,after):
                    expected=copy.deepcopy(old['frame'])
                    result=expected.get('result',{})
                    if 'supportedVersions' in result:
                        changed+=1
                        if name=='SD01':result.update(supportedVersions=['2025-03-26'],protocolVersion='2026-07-28')
                        elif name=='SD02':result.setdefault('_meta',{})['io.modelcontextprotocol/serverCapabilities']=result.pop('capabilities')
                        else:result.pop('supportedVersions');result['protocolVersion']='2026-07-28'
                    need(canonical(new['frame'])==canonical(expected),'discovery copy changed a different semantic field')
                    raw=base64.b64decode(new['raw_base64'],validate=True)
                    need(canonical(decoded(raw))==canonical(expected),'synthetic raw/decoded discovery differ')
            need(changed>0,'synthetic discovery delta was never activated')
        else:
            for source_db in (original/'checkpoints').glob('*.sqlite'):
                before=snapshot(source_db);after=snapshot(case/'checkpoints'/source_db.name)
                expected=copy.deepcopy(before)
                if name=='SE01':
                    old=before['reservations'][0]['ict_jws'];h,p,_=old.split('.')
                    new=h+'.'+p+'.'+base64.urlsafe_b64encode(bytes(64)).decode().rstrip('=')
                    verify_signature_only(old,keys['KP'])
                    try:verify_signature_only(new,keys['KP'])
                    except InvalidSignature:pass
                    else:raise ValueError('synthetic zero signature unexpectedly valid')
                    expected=_replace(expected,old,new)
                elif name=='SE02':
                    for row in expected['demo_records']:
                        if row['label']=='alpha':row['label']='bravo'
                else:
                    for row in expected['reservations']:
                        if row['state']=='COMMITTED':
                            cost=decoded(row['cost_json']);need(cost['ops']['amount']=='2','SE03 original amount not two')
                            cost['ops']['amount']='1';row['cost_json']=canonical(cost).decode('utf-8')
                need(canonical(after)==canonical(expected),'synthetic SQL delta differs from frozen fault '+name)
        results.append({'id':name,'status':'DETECTED','kind':'SYNTHETIC_DATA_COPY','ordinary_rejection':report['reason'],'new_sdk_execution':False,'exact_delta_surfaces':exact})
    return {'status':'PASS','discovery_copies':3,'other_copies':3,'copies':results,'original_preserved':True}

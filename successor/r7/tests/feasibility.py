"""Portable R7 feasibility checks, separate from the frozen comparison.

Original contribution Mohammed Messaoudene, Apache-2.0; AI-assisted.
Run from a verified source checkout with Python3.12 and cryptography50.0.2:
  python tests/feasibility.py --output-dir <new-directory>
The nine probe categories are diagnostics, not nine benchmark tasks. Outputs
contain temporary private laboratory keys/configuration: publish only an
explicitly reviewed evidence subset, never the whole output directory.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

SRC = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(SRC))
from zti_r7 import domain
from zti_r7.zti_backend import ZtiBackend
from zti_r7._provider.integration import BusinessRefusal, TableSpec, Writer

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output-dir', type=Path, required=True)
options = parser.parse_args()
HERE = options.output_dir.resolve()
if HERE.exists():
    raise SystemExit('Output must be absent; preserve previous diagnostic runs')
HERE.mkdir(parents=True, exist_ok=False)
# Deliberately authored development data, not the 24 frozen pair fixtures.
seed = {
    'self_id': 'p.self',
    'messages': {
        'msg.001': {'thread_id':'thread.001','sender':'p.alpha','to':['p.self'],
                    'cc':['p.bravo'],'bcc':[],'read':False,'version':1},
        'msg.002': {'thread_id':'thread.001','sender':'p.charlie','to':['p.self'],
                    'cc':[],'bcc':[],'read':False,'version':1},
    },
    'directory': {'version':1,'aliases':{'alias.alpha':['p.alpha']},
                  'groups':{'group.team':['p.alpha','p.bravo']}},
}
policy = {'principal_id':'service.r7','allowed_messages':['msg.001'],
          'allowed_recipients':['p.alpha'],'allowed_modes':['reply','reply_all','mark_read'],
          'allow_read':True,'allowed_body':'body.alpha','budget_ops':8,'budget_bytes':4096}
results = []
# The script deliberately loads its adjacent source tree, not a random global
# installation. Record the exact bytes; the caller freezes/source-checks them.
for module in (domain, sys.modules[ZtiBackend.__module__]):
    Path(module.__file__).resolve().relative_to(SRC.resolve())


def args(backend, obligation='development.obligation', *, version=None, set_read=True, recipient='p.alpha'):
    view = backend.observe()
    msg = view['messages']['msg.001']
    return {'obligation_id': obligation, 'kind': 'reply', 'message_id': 'msg.001',
        'to': [recipient], 'cc': [], 'bcc': [],
        'expected_message_version': msg['version'] if version is None else version,
        'expected_directory_version': view['directory']['version'],
        'expected_to': [recipient], 'expected_cc': [], 'expected_bcc': [],
        'body': 'body.alpha', 'set_read': set_read,
        'expected_read_change': set_read and not msg['read']}


def counts(backend):
    with sqlite3.connect(backend.db_path.resolve().as_uri()+'?mode=ro', uri=True) as db:
        result = {table: db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]
                  for table in ('mail_events', 'receipts', 'business_effects')}
        result['reservations'] = db.execute('SELECT state,COUNT(*) FROM reservations GROUP BY state').fetchall()
        result['event_kinds'] = db.execute('SELECT event_kind,COUNT(*) FROM mail_events GROUP BY event_kind').fetchall()
        return result


# This handle reads uncommitted own inserts from the very same transaction.
db = sqlite3.connect(':memory:', isolation_level=None)
db.execute('CREATE TABLE sample(row_id INTEGER PRIMARY KEY AUTOINCREMENT,value TEXT NOT NULL)')
db.execute('BEGIN IMMEDIATE')
w = Writer(db, (TableSpec('sample', {'value':'TEXT'}),), lambda *_: None)
w.insert('sample', {'value':'uncommitted'})
rows = w.read_rows('sample')
assert len(rows)==1 and rows[0]['value']=='uncommitted'
try:
    rows[0]['value']='changed'
except TypeError:
    immutable = True
else:
    raise AssertionError('Mutable read result')
try:
    w.read_rows('roots')
except ValueError:
    owner_guard = True
else:
    raise AssertionError('Undeclared table read')
w._finish()
try:
    w.read_rows('sample')
except ValueError:
    lifetime_guard = True
else:
    raise AssertionError('Expired handle read')
db.execute('ROLLBACK')
assert db.execute('SELECT COUNT(*) FROM sample').fetchone()[0]==0
db.execute('BEGIN IMMEDIATE')
db.executemany('INSERT INTO sample(value) VALUES (?)', [('row',)]*1024)
w = Writer(db,(TableSpec('sample',{'value':'TEXT'}),),lambda *_:None)
assert len(w.read_rows('sample'))==1024
db.execute('INSERT INTO sample(value) VALUES (?)',('overflow',))
try:
    w.read_rows('sample')
except BusinessRefusal as error:
    assert error.reason=='READ_LIMIT'
else:
    raise AssertionError('Silent truncation')
w._finish(); db.execute('ROLLBACK'); db.close()
results.append({'probe':'writer_transaction_guards','status':'PASS',
    'uncommitted_insert_visible':True,'immutable':immutable,
    'table_owner_guard':owner_guard,'lifetime_guard':lifetime_guard,
    'positive_rows':1024,'overflow_rows':1025,'overflow_reason':'READ_LIMIT',
    'all_rows_rolled_back':True})

b=ZtiBackend(HERE/'nominal',seed,policy)
a=args(b)
prepared=b.prepare(a,'op.nominal')
r=b.reserve(a,'op.nominal'); assert r['status']=='RESERVED'
out=b.execute(a,'op.nominal',r); assert out['status']=='COMMITTED'
assert out['receipt']['action_hash']==prepared['action_hash']
before=counts(b)
assert before['mail_events']==3 and before['receipts']==1 and before['business_effects']==1
assert b.observe()['messages']['msg.001']['read'] is True
assert not set(b.observe()) & {'outbox','receipts','mail_events'}
retry=b.execute(a,'op.nominal',r)
assert retry['receipt']==out['receipt'] and retry['result']==out['result'] and counts(b)==before
lookup=b.lookup('op.nominal')
assert lookup['status']=='COMMITTED' and lookup['receipt']==out['receipt'] and 'result' not in lookup
results.append({'probe':'complete_nominal_and_same_operation_retry','status':'PASS',
    'receipt':out['receipt'],'business_result':out['result'],'sql':before,
    'lookup_result_json_exposed':False,'retry_new_rows':0})

# Intentionally demonstrate observability, rather than semantic deduplication.
a2=args(b)
r2=b.reserve(a2,'op.duplicate'); assert r2['status']=='RESERVED'
o2=b.execute(a2,'op.duplicate',r2); assert o2['status']=='COMMITTED'
state=b.export_state()
assert len(state['projected']['outbox'])==2
assert len({row['obligation_id'] for row in state['projected']['outbox']})==1
a3=args(b,'development.different.obligation')
r3=b.reserve(a3,'op.second.obligation')
o3=b.execute(a3,'op.second.obligation',r3); assert o3['status']=='COMMITTED'
assert len(b.export_state()['projected']['outbox'])==3
results.append({'probe':'multiplicity_not_masked','status':'PASS',
    'same_obligation_new_operation_outboxes':2,
    'distinct_obligation_same_content_additional_outboxes':1,'sql':counts(b)})

s=ZtiBackend(HERE/'stale',seed,policy)
sa=args(s); sr=s.reserve(sa,'op.stale')
s.inject_environment({'kind':'message_version','message_id':'msg.001','version':2})
so=s.execute(sa,'op.stale',sr)
assert so['status']=='REFUSED' and so['reason']=='STALE_STATE'
sc=counts(s)
assert sc['event_kinds']==[('ENV_MESSAGE_VERSION',1)] and sc['receipts']==0 and sc['business_effects']==0
assert s.cancel('op.stale',sr)['status']=='CANCELLED'
results.append({'probe':'stale_state_before_effect','status':'PASS','refusal':so,'sql_before_cancel':sc})

p=ZtiBackend(HERE/'policy',seed,{**policy,'allow_read':False})
pa=args(p); pr=p.reserve(pa,'op.unapproved.read')
po=p.execute(pa,'op.unapproved.read',pr)
assert po['status']=='REFUSED' and po['reason']=='POLICY_DENIED'
assert counts(p)['mail_events']==0 and counts(p)['receipts']==0
assert p.cancel('op.unapproved.read',pr)['status']=='CANCELLED'
pa2=args(p,set_read=False); pr2=p.reserve(pa2,'op.permitted.continuation')
assert p.execute(pa2,'op.permitted.continuation',pr2)['status']=='COMMITTED'
assert not p.observe()['messages']['msg.001']['read'] and counts(p)['mail_events']==2
results.append({'probe':'explicit_read_right_and_permitted_continuation','status':'PASS','sql':counts(p)})

u=ZtiBackend(HERE/'recipient',seed,policy)
ua=args(u,recipient='p.charlie'); ur=u.reserve(ua,'op.unapproved.recipient')
uo=u.execute(ua,'op.unapproved.recipient',ur)
assert uo['status']=='REFUSED' and uo['reason']=='POLICY_DENIED' and counts(u)['mail_events']==0
results.append({'probe':'actual_recipient_authorization','status':'PASS','refusal':uo,'sql':counts(u)})

def intentional(event, detail):
    if event=='after_first_insert_before_commit':
        raise BusinessRefusal('STALE_STATE')

rb=ZtiBackend(HERE/'rollback_typed',seed,policy,hook=intentional)
ra=args(rb); rr=rb.reserve(ra,'op.rollback.typed')
ro=rb.execute(ra,'op.rollback.typed',rr)
assert ro['status']=='REFUSED' and ro['reason']=='STALE_STATE'
assert counts(rb)['mail_events']==counts(rb)['receipts']==counts(rb)['business_effects']==0
results.append({'probe':'typed_refusal_after_first_insert_full_rollback','status':'PASS',
    'sql':counts(rb),'controlled_development_fault':True})

def unexpected(event, detail):
    if event=='after_first_insert_before_commit':
        raise RuntimeError('announced development engine fault')

err=ZtiBackend(HERE/'rollback_unexpected',seed,policy,hook=unexpected)
ea=args(err); er=err.reserve(ea,'op.rollback.unexpected')
try:
    err.execute(ea,'op.rollback.unexpected',er)
except RuntimeError as error:
    error_message=str(error)
else:
    raise AssertionError('Unexpected engine error counted as refusal')
assert counts(err)['mail_events']==counts(err)['receipts']==counts(err)['business_effects']==0
results.append({'probe':'unexpected_error_not_qualified_refusal','status':'PASS',
    'observed_exception':error_message,'sql':counts(err),'controlled_development_fault':True})

# Real child process exits after commit, before it can return the result.
lost=ZtiBackend(HERE/'lost_response',seed,policy)
la=args(lost)
(HERE/'lost_arguments.json').write_text(domain.canonical(la),encoding='utf-8')
child=HERE/'lost_child.py'
child.write_text('''from pathlib import Path
import json,os,sys
sys.path.insert(0,sys.argv[1])
from zti_r7.zti_backend import ZtiBackend
p=Path(sys.argv[2]); a=json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
seed=json.loads((p/"seed.json").read_text(encoding="utf-8")); policy=json.loads((p/"policy.json").read_text(encoding="utf-8"))
def hook(event,detail):
 if event=="after_commit_before_response":os._exit(86)
b=ZtiBackend(p,seed,policy,hook=hook,initialize=False)
prepared=b.prepare(a,"op.lost.response"); reservation=b.reserve(a,"op.lost.response")
with (p/"dispatch.json").open("w",encoding="utf-8") as stream:
 json.dump({"child_pid":os.getpid(),"principal_id":policy["principal_id"],"arguments":a,"prepared":prepared,"reservation":reservation},stream);stream.flush();os.fsync(stream.fileno())
b.execute(a,"op.lost.response",reservation)
raise RuntimeError("after-commit hook did not exit")
''',encoding='utf-8')
run=subprocess.run([sys.executable,str(child),str(SRC),str(HERE/'lost_response'),str(HERE/'lost_arguments.json')],capture_output=True,text=True,timeout=30)
(HERE/'lost_child.stdout.txt').write_text(run.stdout,encoding='utf-8')
(HERE/'lost_child.stderr.txt').write_text(run.stderr,encoding='utf-8')
assert run.returncode==86, (run.returncode,run.stderr)
dispatch=json.loads((HERE/'lost_response/dispatch.json').read_text(encoding='utf-8'))
assert dispatch['child_pid']!=os.getpid()
restarted=ZtiBackend(HERE/'lost_response',seed,policy,initialize=False)
lo=restarted.lookup('op.lost.response')
assert lo['status']=='COMMITTED' and lo['receipt']['action_hash']==dispatch['prepared']['action_hash']
lc=counts(restarted)
assert lc['mail_events']==3 and lc['receipts']==1
assert restarted.execute(la,'op.lost.response',dispatch['reservation'])['receipt']==lo['receipt']
assert counts(restarted)==lc
results.append({'probe':'actual_process_exit_after_commit_and_same_principal_recovery','status':'PASS',
    'child_pid':dispatch['child_pid'],'recovery_pid':os.getpid(),'child_exit_code':run.returncode,
    'principal_id':policy['principal_id'],'durable_dispatch_before_execute':True,
    'lookup':lo,'sql':lc,'retry_new_rows':0})

receipt={'status':'PASS_DEVELOPMENT_ONLY','qualified_campaign':False,
    'new_mcp_sdk_or_wire':False,'frozen_comparative_cases_executed':0,
    'author':'A/provider','independent_review':False,'parent_pid':os.getpid(),
    'fixture_source':'authored_development_data_in_test_not_frozen_cases',
    'probes':results,'source_sha256':{path.relative_to(SRC).as_posix():hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((SRC/'zti_r7/_provider').glob('*.py'))},
    'additional_source_sha256':{name:hashlib.sha256((SRC/'zti_r7'/name).read_bytes()).hexdigest()
        for name in ('domain.py','zti_backend.py')}}
(HERE/'RECEIPT.json').write_text(json.dumps(receipt,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
print(json.dumps({'status':receipt['status'],'probes':len(results),'receipt':'RECEIPT.json'}))

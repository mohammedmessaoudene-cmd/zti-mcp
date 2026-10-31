"""Local R4 authority fixture. No network/MCP endpoint or general JCS claim."""
from __future__ import annotations
import base64, contextlib, copy, hashlib, json, os, re, secrets, sqlite3
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature

PROFILE='zti-mcp/0.1'; ISSUER='https://authority.example.invalid'
REGISTRY='urn:lab:registry'; EXECUTOR='urn:lab:executor'; RESOURCE='urn:lab:resource'
TENANT='lab-tenant'; KID='public-laboratory-p256-key'; NOW=1793404800
U64=18446744073709551615; SAFE=9007199254740991
KEY=ec.derive_private_key(1,ec.SECP256R1())  # PUBLIC TEST PRIVATE KEY, NOT DEPLOYMENT.
TOOLS=['lab.compute','lab.read_sensitive','lab.export_external']
UNITS={'ops':'operation','bytes':'byte'}
BODY_FIELDS={'profile','tenant_id','principal_id','root_mandate_id','mandate_id','parent_id','parent_hash','correlation_id','delegatee_id','valid_from','valid_until','constraints','root_policy','policy_hash'}
CONSTRAINT_FIELDS={'allowed_executors','allowed_resources','allowed_methods','allowed_tools','action_caps'}
ACTION_FIELDS={'profile','tenant_id','root_mandate_id','mandate_id','operation_id','executor_id','resource_id','method','tool_name','tool_revision','arguments'}
ZTI_FIELDS={'profile','mode','tenant_id','root_mandate_id','mandate_id','mandate_hash','correlation_id','operation_id','reservation_id','action_hash','policy_hash','authority_epoch','cost_bounds','facts'}
CHARGED={'COMMITTED','COMPLETED','UNKNOWN'}
STATES=CHARGED|{'RESERVED','CANCELLED','EXPIRED','REVOKED'}

class Fault(Exception):
    def __init__(self,code): self.code=code;super().__init__(code)

def fail(code): raise Fault(code)
def uid(prefix): return prefix+secrets.token_hex(16)
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def unb64(s):
    if type(s) is not str or not re.fullmatch('[A-Za-z0-9_-]*',s): fail('JWT_FORMAT')
    try: b=base64.urlsafe_b64decode(s+'='*((-len(s))%4))
    except Exception: fail('JWT_FORMAT')
    if b64(b)!=s: fail('JWT_FORMAT')
    return b

def canonical(v):
    def check(x):
        if x is None or type(x) is bool: return
        if type(x) is int:
            if abs(x)>SAFE: fail('UNSUPPORTED_SUBSET')
        elif type(x) is str:
            try:x.encode('utf-8')
            except UnicodeError:fail('UNSUPPORTED_SUBSET')
        elif type(x) is list:
            for y in x:check(y)
        elif type(x) is dict:
            for k,y in x.items():
                if type(k) is not str or not k.isascii():fail('UNSUPPORTED_SUBSET')
                check(y)
        else:fail('UNSUPPORTED_SUBSET')
    check(v)
    return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()

def loads(b):
    def pairs(ps):
        d={}
        for k,v in ps:
            if k in d:fail('DUPLICATE_KEY')
            d[k]=v
        return d
    try:v=json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:fail('JSON_FORMAT'))
    except Fault:raise
    except Exception:fail('JSON_FORMAT')
    canonical(v)
    return v

def sha(v):return hashlib.sha256(canonical(v)).hexdigest()
def uint(s):
    if type(s) is not str or not re.fullmatch('0|[1-9][0-9]*',s):fail('INVALID_QUANTITY')
    n=int(s)
    if n>U64:fail('INVALID_QUANTITY')
    return n
def quant(ops=0,byte=0):return {'ops':{'unit':'operation','amount':str(ops)},'bytes':{'unit':'byte','amount':str(byte)}}
def numbers(q):
    if type(q) is not dict or set(q)!=set(UNITS):fail('INVALID_QUANTITY')
    out={}
    for d,u in UNITS.items():
        if type(q[d]) is not dict or set(q[d])!={'unit','amount'} or q[d]['unit']!=u:fail('INVALID_QUANTITY')
        out[d]=uint(q[d]['amount'])
    return out
def fromnums(n):return quant(n['ops'],n['bytes'])

def sign(claims,typ):
    header={'alg':'ES256','typ':typ,'kid':KID}
    h,p=b64(canonical(header)),b64(canonical(claims))
    der=KEY.sign((h+'.'+p).encode(),ec.ECDSA(hashes.SHA256()))
    r,s=utils.decode_dss_signature(der)
    return h+'.'+p+'.'+b64(r.to_bytes(32,'big')+s.to_bytes(32,'big'))

def verify(token,typ,now):
    try:h,p,s=token.split('.')
    except Exception:fail('JWT_FORMAT')
    header=loads(unb64(h))
    if type(header) is not dict:fail('JWT_HEADER')
    if header.get('typ')!=typ:fail('TOKEN_TYPE')
    if header!={'alg':'ES256','typ':typ,'kid':KID}:fail('JWT_HEADER')
    sig=unb64(s)
    if len(sig)!=64:fail('SIGNATURE')
    try:
        KEY.public_key().verify(utils.encode_dss_signature(int.from_bytes(sig[:32],'big'),int.from_bytes(sig[32:],'big')),
                                (h+'.'+p).encode(),ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:fail('SIGNATURE')
    c=loads(unb64(p)); nested='zti' if typ=='zti-ict+jwt' else 'zti_mandate'
    if type(c) is not dict or set(c)!={'iss','sub','aud','iat','nbf','exp','jti',nested}:fail('JWT_CLAIMS')
    if c['iss']!=ISSUER or any(type(c[k]) is not str for k in ['iss','sub','aud','jti']):fail('JWT_CLAIMS')
    if any(type(c[k]) is not int or not 0<=c[k]<=SAFE for k in ['iat','nbf','exp']):fail('JWT_TIME')
    if not c['iat']<=c['nbf']<c['exp']:fail('JWT_TIME')
    if nested=='zti' and c['exp']-c['iat']>60:fail('JWT_TIME')
    if not c['nbf']<=now<c['exp']:fail('EXPIRED')
    return c

def public_jwk():
    n=KEY.public_key().public_numbers()
    return {'kty':'EC','crv':'P-256','x':b64(n.x.to_bytes(32,'big')),'y':b64(n.y.to_bytes(32,'big')),'kid':KID,'alg':'ES256','use':'sig'}

def connect(db):
    c=sqlite3.connect(str(db),timeout=20,isolation_level=None);c.row_factory=sqlite3.Row
    c.execute('PRAGMA busy_timeout=20000');return c

class Authority:
    def __init__(self,db,mutant=None):self.db=str(db);self.mutant=mutant
    def initialize(self):
        c=connect(self.db);c.execute('PRAGMA journal_mode=WAL');c.execute('PRAGMA synchronous=FULL')
        c.executescript('''
          CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT);
          CREATE TABLE roots(tenant TEXT,rid TEXT,policy TEXT,epoch TEXT,PRIMARY KEY(tenant,rid));
          CREATE TABLE mandates(mid TEXT PRIMARY KEY,tenant TEXT,rid TEXT,body TEXT,hash TEXT,jwt TEXT,revoked INTEGER);
          CREATE TABLE reservations(tenant TEXT,rid TEXT,resid TEXT,op TEXT,jti TEXT UNIQUE,subject TEXT,audience TEXT,
             mid TEXT,action TEXT,action_hash TEXT,cost TEXT,facts TEXT,state TEXT,claims TEXT,jwt TEXT,
             PRIMARY KEY(tenant,rid,resid),UNIQUE(tenant,rid,op));
          CREATE TABLE effects(id INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT,rid TEXT,resid TEXT,op TEXT,
             action_hash TEXT,cost TEXT,facts TEXT,pid INTEGER);
          CREATE TABLE audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,event TEXT,detail TEXT,pid INTEGER);
        ''');c.execute('INSERT INTO meta VALUES (?,?)',('clock',str(NOW)));c.close()
    @contextlib.contextmanager
    def tx(self):
        c=connect(self.db);c.execute('BEGIN IMMEDIATE')
        try:yield c;c.execute('COMMIT')
        except BaseException:c.execute('ROLLBACK');raise
        finally:c.close()
    def now(self,c):return int(c.execute("SELECT value FROM meta WHERE key='clock'").fetchone()[0])
    def log(self,c,event,detail):c.execute('INSERT INTO audit(event,detail,pid) VALUES (?,?,?)',(event,canonical(detail).decode(),os.getpid()))
    def validate_policy(self,p):
        if type(p) is not dict or set(p)!={'budgets','forbidden_sets'}:fail('POLICY_UNSUPPORTED')
        numbers(p['budgets'])
        if type(p['forbidden_sets']) is not list:fail('POLICY_UNSUPPORTED')
        for s in p['forbidden_sets']:
            if type(s) is not list or not s or any(type(x) is not str for x in s) or len(set(s))!=len(s):fail('POLICY_UNSUPPORTED')
    def constraint_shape(self,c):
        if type(c) is not dict or set(c)!=CONSTRAINT_FIELDS:fail('MANDATE_FORMAT')
        numbers(c['action_caps'])
        for k in CONSTRAINT_FIELDS-{'action_caps'}:
            if type(c[k]) is not list or any(type(v) is not str for v in c[k]) or len(set(c[k]))!=len(c[k]):fail('MANDATE_FORMAT')
    def store_mandate(self,c,b):
        h=sha(b)
        if c.execute('SELECT 1 FROM mandates WHERE mid=?',(b['mandate_id'],)).fetchone():fail('IMMUTABLE_CONFLICT')
        claims={'iss':ISSUER,'sub':b['delegatee_id'],'aud':REGISTRY,'iat':self.now(c),'nbf':b['valid_from'],
                'exp':b['valid_until'],'jti':uid('m-'),'zti_mandate':b}
        token=sign(claims,'zti-mandate+jwt')
        c.execute('INSERT INTO mandates VALUES (?,?,?,?,?,?,0)',(b['mandate_id'],b['tenant_id'],b['root_mandate_id'],canonical(b).decode(),h,token))
        return {'status':'REGISTERED','mandate':b,'mandate_hash':h,'jwt':token}
    def register_root(self,budget=None,caps=None,tools=None,policy_override=None):
        with self.tx() as c:
            p=policy_override if policy_override is not None else {'budgets':quant(3,10) if budget is None else budget,'forbidden_sets':[['read_sensitive','export_external']]}
            self.validate_policy(p)
            constraints={'allowed_executors':[EXECUTOR],'allowed_resources':[RESOURCE],'allowed_methods':['tools/call'],
                         'allowed_tools':TOOLS.copy() if tools is None else tools,'action_caps':quant(3,10) if caps is None else caps}
            self.constraint_shape(constraints);mid=uid('root-');now=self.now(c)
            b={'profile':PROFILE,'tenant_id':TENANT,'principal_id':'principal-root','root_mandate_id':mid,'mandate_id':mid,
               'parent_id':None,'parent_hash':None,'correlation_id':uid('corr-'),'delegatee_id':'agent-a',
               'valid_from':now,'valid_until':now+3600,'constraints':constraints,'root_policy':p,'policy_hash':sha(p)}
            c.execute('INSERT INTO roots VALUES (?,?,?,?)',(TENANT,mid,canonical(p).decode(),'0'))
            return self.store_mandate(c,b)
    def lineage(self,c,mid):
        line=[];seen=set()
        while mid is not None:
            if mid in seen or len(line)>=8:fail('DEPTH_LIMIT')
            seen.add(mid);row=c.execute('SELECT * FROM mandates WHERE mid=?',(mid,)).fetchone()
            if row is None:fail('STATE_INCOMPLETE')
            b=loads(row['body']);claims=verify(row['jwt'],'zti-mandate+jwt',self.now(c))
            if set(b)!=BODY_FIELDS or claims['zti_mandate']!=b or sha(b)!=row['hash']:fail('STATE_INCOMPLETE')
            if claims['sub']!=b['delegatee_id'] or claims['aud']!=REGISTRY or claims['nbf']!=b['valid_from'] or claims['exp']!=b['valid_until']:fail('MANDATE_FORMAT')
            if row['revoked']:fail('REVOKED')
            self.constraint_shape(b['constraints'])
            root=c.execute('SELECT * FROM roots WHERE tenant=? AND rid=?',(b['tenant_id'],b['root_mandate_id'])).fetchone()
            if root is None:fail('STATE_INCOMPLETE')
            policy=loads(root['policy'])
            if b['policy_hash']!=sha(policy):fail('POLICY_BINDING')
            if b['parent_id'] is None:
                if b['mandate_id']!=b['root_mandate_id'] or b['parent_hash'] is not None or b['root_policy']!=policy:fail('MANDATE_FORMAT')
            elif b['root_policy'] is not None:fail('MANDATE_FORMAT')
            line.append(b)
            if self.mutant=='skip_ancestors':break
            if b['parent_id']:
                parent=c.execute('SELECT hash,body FROM mandates WHERE mid=?',(b['parent_id'],)).fetchone()
                if parent is None:fail('STATE_INCOMPLETE')
                if parent['hash']!=b['parent_hash']:fail('PARENT_HASH')
                pb=loads(parent['body'])
                if any(pb[k]!=b[k] for k in ['tenant_id','root_mandate_id','correlation_id','principal_id','policy_hash']):fail('SCOPE_MISMATCH')
                self.attenuated(pb,b)
            mid=b['parent_id']
        return line
    def attenuated(self,parent,child):
        if self.mutant=='skip_ancestors':return
        for k in CONSTRAINT_FIELDS-{'action_caps'}:
            if not set(child['constraints'][k])<=set(parent['constraints'][k]):fail('DELEGATION_WIDEN')
        pc,cc=numbers(parent['constraints']['action_caps']),numbers(child['constraints']['action_caps'])
        if any(cc[d]>pc[d] for d in UNITS):fail('DELEGATION_WIDEN')
        if not parent['valid_from']<=child['valid_from']<child['valid_until']<=parent['valid_until']:fail('DELEGATION_WIDEN')
    def delegate(self,parent_id,caller,delegatee,constraints=None,valid_until=None,parent_hash=None):
        with self.tx() as c:
            line=self.lineage(c,parent_id);p=line[0]
            if caller!=p['delegatee_id']:fail('SUBJECT')
            if len(line)>=8:fail('DEPTH_LIMIT')
            if parent_hash is not None and parent_hash!=sha(p):fail('PARENT_HASH')
            b=copy.deepcopy(p);b.update({'mandate_id':uid('child-'),'parent_id':parent_id,'parent_hash':sha(p),
                'delegatee_id':delegatee,'root_policy':None,'valid_from':max(self.now(c),p['valid_from'])})
            if constraints is not None:b['constraints']=constraints
            if valid_until is not None:b['valid_until']=valid_until
            self.constraint_shape(b['constraints']);self.attenuated(p,b)
            return self.store_mandate(c,b)
    def replace(self,mid,body):
        with self.tx() as c:
            if c.execute('SELECT 1 FROM mandates WHERE mid=?',(mid,)).fetchone():fail('IMMUTABLE_CONFLICT')
            fail('STATE_INCOMPLETE')
    def catalog(self,a):
        canonical(a)
        if set(a)!=ACTION_FIELDS or a['profile']!=PROFILE or a['tool_revision']!='1':fail('ACTION_FORMAT')
        if a['tool_name'] not in TOOLS or a['method']!='tools/call':fail('ACTION_FORMAT')
        args=a['arguments']
        if type(args) is not dict or set(args)!={'units','payload'} or type(args['payload']) is not str:fail('ACTION_FORMAT')
        n=uint(args['units']);count=len(args['payload'].encode())
        if count>U64:fail('OVERFLOW')
        facts=[] if a['tool_name']=='lab.compute' else [a['tool_name'][4:]]
        return quant(n,count),facts
    def aggregate(self,c,tenant,rid,honest=False,own=None):
        d={k:0 for k in UNITS};r={k:0 for k in UNITS};cf=set();pf=set()
        for x in c.execute('SELECT * FROM reservations WHERE tenant=? AND rid=?',(tenant,rid)):
            state=x['state'];cost=numbers(loads(x['cost']));facts=set(loads(x['facts']))
            if state not in STATES:fail('STATE_INCOMPLETE')
            if state in CHARGED and not (self.mutant=='release_unknown' and state=='UNKNOWN' and not honest):
                for k in d:d[k]+=cost[k]
                cf|=facts;pf|=facts
            elif state=='RESERVED':
                for k in r:r[k]+=cost[k]
                if honest or self.mutant!='ignore_reserved_facts' or x['resid']==own:pf|=facts
        return d,r,cf,pf
    def gate(self,c,line,a,cost,facts,new=True,own=None):
        for b in line:
            cs=b['constraints'];mappings={'allowed_executors':'executor_id','allowed_resources':'resource_id','allowed_methods':'method','allowed_tools':'tool_name'}
            if any(a[field] not in cs[allowed] for allowed,field in mappings.items()):fail('ACTION_NOT_ALLOWED')
            cap=numbers(cs['action_caps']);n=numbers(cost)
            if any(n[k]>cap[k] for k in UNITS):fail('ACTION_CAP')
        b=line[0];root=c.execute('SELECT * FROM roots WHERE tenant=? AND rid=?',(b['tenant_id'],b['root_mandate_id'])).fetchone()
        policy=loads(root['policy']);self.validate_policy(policy)
        d,r,cf,pf=self.aggregate(c,b['tenant_id'],b['root_mandate_id'],own=own)
        n=numbers(cost);limit=numbers(policy['budgets'])
        totals={k:d[k]+r[k]+(n[k] if new else 0) for k in UNITS}
        if any(v>U64 for v in totals.values()):fail('OVERFLOW')
        if any(totals[k]>limit[k] for k in UNITS):fail('BUDGET')
        projected=pf|set(facts)
        if any(set(s)<=projected for s in policy['forbidden_sets']):fail('FORBIDDEN')
        return root
    def reserve(self,mid,actor,a):
        with self.tx() as c:
            line=self.lineage(c,mid);b=line[0]
            if actor!=b['delegatee_id']:fail('SUBJECT')
            if any(a[k]!=b[k] for k in ['tenant_id','root_mandate_id','mandate_id']):fail('SCOPE_MISMATCH')
            cost,facts=self.catalog(a);ah=sha(a)
            old=c.execute('SELECT * FROM reservations WHERE tenant=? AND rid=? AND op=?',(b['tenant_id'],b['root_mandate_id'],a['operation_id'])).fetchone()
            if old:
                if old['state'] not in STATES:fail('STATE_INCOMPLETE')
                if old['action_hash']!=ah or old['subject']!=actor:fail('CONFLICT')
                return {'status':old['state'],'token':old['jwt'],'reservation_id':old['resid'],'reused':True}
            root=self.gate(c,line,a,cost,facts);rid=uid('r-');jti=uid('ict-');now=self.now(c)
            z={'profile':PROFILE,'mode':'current-online','tenant_id':b['tenant_id'],'root_mandate_id':b['root_mandate_id'],
               'mandate_id':mid,'mandate_hash':sha(b),'correlation_id':b['correlation_id'],'operation_id':a['operation_id'],
               'reservation_id':rid,'action_hash':ah,'policy_hash':b['policy_hash'],'authority_epoch':root['epoch'],
               'cost_bounds':cost,'facts':facts}
            claims={'iss':ISSUER,'sub':actor,'aud':a['executor_id'],'iat':now,'nbf':now,
                    'exp':min(now+60,min(x['valid_until'] for x in line)),'jti':jti,'zti':z}
            token=sign(claims,'zti-ict+jwt')
            c.execute('INSERT INTO reservations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
              (b['tenant_id'],b['root_mandate_id'],rid,a['operation_id'],jti,actor,a['executor_id'],mid,
               canonical(a).decode(),ah,canonical(cost).decode(),canonical(facts).decode(),'RESERVED',canonical(claims).decode(),token))
            self.log(c,'RESERVED',{'reservation_id':rid,'action_hash':ah,'cost':cost,'facts':facts})
            return {'status':'RESERVED','token':token,'reservation_id':rid,'claims':claims}
    def commit(self,token,actor,a,audience=None):
        with self.tx() as c:
            claims=verify(token,'zti-ict+jwt',self.now(c));z=claims['zti']
            if type(z) is not dict or set(z)!=ZTI_FIELDS or z['profile']!=PROFILE or z['mode']!='current-online':fail('PROFILE')
            uint(z['authority_epoch'])
            if claims['sub']!=actor:fail('SUBJECT')
            if claims['aud']!=(audience or EXECUTOR):fail('AUDIENCE')
            line=self.lineage(c,z['mandate_id']);b=line[0]
            if actor!=b['delegatee_id']:fail('SUBJECT')
            row=c.execute('SELECT * FROM reservations WHERE tenant=? AND rid=? AND resid=?',(z['tenant_id'],z['root_mandate_id'],z['reservation_id'])).fetchone()
            if row is None:fail('RESERVATION_UNKNOWN')
            stored=loads(row['claims']);expected=stored['zti']
            if any(z[k]!=expected[k] for k in ZTI_FIELDS-{'cost_bounds','facts'}):fail('PERMIT_BINDING')
            if claims['jti']!=row['jti'] or claims['sub']!=row['subject'] or claims['aud']!=row['audience']:fail('PERMIT_BINDING')
            if any(claims[k]!=stored[k] for k in ['iat','nbf','exp']):fail('PERMIT_BINDING')
            if b['correlation_id']!=z['correlation_id'] or b['tenant_id']!=z['tenant_id'] or sha(b)!=z['mandate_hash']:fail('SCOPE_MISMATCH')
            root=c.execute('SELECT * FROM roots WHERE tenant=? AND rid=?',(z['tenant_id'],z['root_mandate_id'])).fetchone()
            if z['authority_epoch']!=root['epoch']:fail('STALE_AUTHORITY')
            if sha(a)!=row['action_hash']:fail('ACTION_MISMATCH')
            cost,facts=self.catalog(a)
            try:numbers(z['cost_bounds'])
            except Fault:fail('COST_BINDING')
            if z['cost_bounds']!=loads(row['cost']) or z['cost_bounds']!=cost or z['cost_bounds']!=expected['cost_bounds']:fail('COST_BINDING')
            if (type(z['facts']) is not list or any(type(v) is not str for v in z['facts'])
                or sorted(z['facts'])!=sorted(facts) or z['facts']!=loads(row['facts'])
                or z['facts']!=expected['facts'] or len(set(z['facts']))!=len(z['facts'])):fail('FACT_BINDING')
            if row['state'] not in STATES:fail('STATE_INCOMPLETE')
            if row['state'] in CHARGED:return {'status':row['state'],'effect_created':False,'reused':True}
            if row['state']!='RESERVED':return {'status':row['state'],'effect_created':False}
            self.gate(c,line,a,cost,facts,new=False,own=row['resid'])
            c.execute("UPDATE reservations SET state='COMMITTED' WHERE tenant=? AND rid=? AND resid=?",(row['tenant'],row['rid'],row['resid']))
            c.execute('INSERT INTO effects(tenant,rid,resid,op,action_hash,cost,facts,pid) VALUES (?,?,?,?,?,?,?,?)',
                      (row['tenant'],row['rid'],row['resid'],row['op'],row['action_hash'],row['cost'],row['facts'],os.getpid()))
            self.log(c,'COMMITTED',{'reservation_id':row['resid'],'operation_id':row['op']})
            return {'status':'COMMITTED','effect_created':True}
    def lookup(self,tenant,rid,op,actor):
        with self.tx() as c:
            r=c.execute('SELECT * FROM reservations WHERE tenant=? AND rid=? AND op=?',(tenant,rid,op)).fetchone()
            if r is None:fail('RESERVATION_UNKNOWN')
            if r['subject']!=actor:fail('SUBJECT')
            if r['state'] not in STATES:fail('STATE_INCOMPLETE')
            return {'status':r['state'],'reservation_id':r['resid']}
    def cancel(self,tenant,rid,resid,actor):
        with self.tx() as c:
            r=c.execute('SELECT * FROM reservations WHERE tenant=? AND rid=? AND resid=?',(tenant,rid,resid)).fetchone()
            if r is None:fail('RESERVATION_UNKNOWN')
            if r['subject']!=actor:fail('SUBJECT')
            if r['state'] not in STATES:fail('STATE_INCOMPLETE')
            if r['state']!='RESERVED':fail('CANCEL_REJECTED')
            c.execute("UPDATE reservations SET state='CANCELLED' WHERE tenant=? AND rid=? AND resid=?",(tenant,rid,resid))
            self.log(c,'CANCELLED',{'reservation_id':resid});return {'status':'CANCELLED'}
    def unknown(self,tenant,rid,resid):
        with self.tx() as c:
            r=c.execute('SELECT state FROM reservations WHERE tenant=? AND rid=? AND resid=?',(tenant,rid,resid)).fetchone()
            if r is None or r['state']!='COMMITTED':fail('STATE_TRANSITION')
            c.execute("UPDATE reservations SET state='UNKNOWN' WHERE tenant=? AND rid=? AND resid=?",(tenant,rid,resid))
            self.log(c,'UNKNOWN',{'reservation_id':resid});return {'status':'UNKNOWN'}
    def revoke(self,mid):
        with self.tx() as c:
            row=c.execute('SELECT * FROM mandates WHERE mid=?',(mid,)).fetchone()
            if row is None:fail('STATE_INCOMPLETE')
            c.execute('UPDATE mandates SET revoked=1 WHERE mid=?',(mid,))
            old=uint(c.execute('SELECT epoch FROM roots WHERE tenant=? AND rid=?',(row['tenant'],row['rid'])).fetchone()[0])
            if old==U64:
                c.execute('UPDATE mandates SET revoked=1 WHERE mid=?',(row['rid'],))
                self.log(c,'ROOT_TERMINAL',{'root_mandate_id':row['rid'],'epoch':str(old)})
                return {'status':'REVOKED','root_terminal':True}
            epoch=old+1
            c.execute('UPDATE roots SET epoch=? WHERE tenant=? AND rid=?',(str(epoch),row['tenant'],row['rid']))
            self.log(c,'REVOKED',{'mandate_id':mid,'epoch':str(epoch)});return {'status':'REVOKED'}
    def advance_clock(self,seconds):
        with self.tx() as c:c.execute("UPDATE meta SET value=? WHERE key='clock'",(str(self.now(c)+seconds),))
    def bump_epoch(self,rid):
        with self.tx() as c:
            old=int(c.execute('SELECT epoch FROM roots WHERE tenant=? AND rid=?',(TENANT,rid)).fetchone()[0])
            if old==U64:
                c.execute('UPDATE mandates SET revoked=1 WHERE mid=?',(rid,))
                self.log(c,'ROOT_TERMINAL',{'root_mandate_id':rid,'epoch':str(old)})
                return {'status':'REVOKED','root_terminal':True}
            c.execute('UPDATE roots SET epoch=? WHERE tenant=? AND rid=?',(str(old+1),TENANT,rid))
    def snapshot(self):
        c=connect(self.db);d={k:0 for k in UNITS};r={k:0 for k in UNITS};cf=set();pf=set()
        for x in c.execute('SELECT tenant,rid FROM roots'):
            a,b,f,g=self.aggregate(c,x['tenant'],x['rid'],honest=True)
            for k in d:d[k]+=a[k];r[k]+=b[k]
            cf|=f;pf|=g
        effects=[dict(x) for x in c.execute('SELECT * FROM effects ORDER BY id')]
        reservations=[dict(x) for x in c.execute('SELECT * FROM reservations ORDER BY op')]
        mandates=[dict(x) for x in c.execute('SELECT * FROM mandates ORDER BY mid')]
        audit_rows=[dict(x) for x in c.execute('SELECT * FROM audit ORDER BY seq')];c.close()
        return {'effect_rows':len(effects),'consumed':fromnums(d),'reserved':fromnums(r),
                'committed_facts':sorted(cf),'possible_facts':sorted(pf),
                'effects':effects,'reservations':reservations,'mandates':mandates,'audit':audit_rows}

def command(body,op='operation-1',units='1',payload='',tool='lab.compute'):
    return {'profile':PROFILE,'tenant_id':body['tenant_id'],'root_mandate_id':body['root_mandate_id'],
            'mandate_id':body['mandate_id'],'operation_id':op,'executor_id':EXECUTOR,'resource_id':RESOURCE,
            'method':'tools/call','tool_name':tool,'tool_revision':'1','arguments':{'units':units,'payload':payload}}

"""Independent R6 audit primitives. No provider, tool, driver or R5 imports.

This is a bounded JSON domain, not a general RFC8785 implementation.
"""
import base64
import hashlib
import json
import re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

MAX_SAFE = 9007199254740991
MAX_U64 = 18446744073709551615

def u64(value):
    if type(value) is not str or re.fullmatch(r'0|[1-9][0-9]*', value) is None:
        raise ValueError('noncanonical uint64')
    number = int(value)
    if number > MAX_U64:
        raise ValueError('uint64 overflow')
    return number

def bounded(value):
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if abs(value) > MAX_SAFE:
            raise ValueError('unsafe JSON integer')
    elif type(value) is str:
        value.encode('utf-8', errors='strict')
    elif type(value) is list:
        for child in value:
            bounded(child)
    elif type(value) is dict:
        for key, child in value.items():
            if type(key) is not str or not key.isascii():
                raise ValueError('non-ASCII object key')
            bounded(child)
    else:
        raise ValueError('value outside bounded JSON domain')

def canonical(value):
    bounded(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')

def action_hash(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate decoded object key')
        result[key] = value
    return result

def decoded(raw):
    def no_float(value):
        raise ValueError('noninteger lexical number')
    value = json.loads(raw, object_pairs_hook=_pairs, parse_float=no_float, parse_constant=no_float)
    bounded(value)
    return value

def b64(raw):
    if type(raw) is not str or re.fullmatch(r'[A-Za-z0-9_-]+', raw) is None:
        raise ValueError('invalid base64url alphabet')
    value = base64.urlsafe_b64decode(raw + '=' * ((-len(raw)) % 4))
    if base64.urlsafe_b64encode(value).decode().rstrip('=') != raw:
        raise ValueError('noncanonical base64url')
    return value

def verify_jws(token, jwk, *, typ, kid, issuer, audience):
    """Verify captured compact JWS using the externally configured key role."""
    if type(token) is not str:
        raise ValueError('token type')
    h, p, s = token.split('.')
    header, claims, signature = decoded(b64(h)), decoded(b64(p)), b64(s)
    if header != {'alg':'ES256', 'kid':kid, 'typ':typ}:
        raise ValueError('JWS protected context')
    if type(claims) is not dict or claims.get('iss') != issuer or claims.get('aud') != audience:
        raise ValueError('JWS issuer/audience context')
    nested={'zti-mandate+jwt':'zti_mandate','zti-ict+jwt':'zti'}.get(typ)
    if nested is None or set(claims)!={'iss','sub','aud','iat','nbf','exp','jti',nested}:
        raise ValueError('JWS closed claim shape')
    if any(type(claims[f]) is not str or not claims[f] for f in ('iss','sub','aud','jti')):
        raise ValueError('JWS string context types')
    if any(type(claims[f]) is not int or not 0<=claims[f]<=MAX_SAFE for f in ('iat','nbf','exp')):
        raise ValueError('JWS integer date domain')
    if not claims['iat']<=claims['nbf']<claims['exp']:
        raise ValueError('JWS date ordering')
    if jwk.get('kty') != 'EC' or jwk.get('crv') != 'P-256' or 'd' in jwk or len(signature) != 64:
        raise ValueError('public key or signature shape')
    x, y = b64(jwk['x']), b64(jwk['y'])
    if len(x) != 32 or len(y) != 32:
        raise ValueError('public key coordinate width')
    public = ec.EllipticCurvePublicNumbers(int.from_bytes(x,'big'), int.from_bytes(y,'big'), ec.SECP256R1()).public_key()
    der = encode_dss_signature(int.from_bytes(signature[:32],'big'), int.from_bytes(signature[32:],'big'))
    public.verify(der, (h+'.'+p).encode('ascii'), ec.ECDSA(hashes.SHA256()))
    return claims

def verify_signature_only(token, jwk):
    """Math-only proof on exact segments, deliberately no JSON/context decision.

    Used to isolate wrong-role/context and duplicate-key diagnostics. Successful
    return is never authorization or a claim that the payload is acceptable.
    """
    if type(token) is not str:
        raise ValueError('token type')
    h,p,s=token.split('.')
    b64(h);b64(p)
    signature=b64(s)
    if jwk.get('kty')!='EC' or jwk.get('crv')!='P-256' or 'd' in jwk or len(signature)!=64:
        raise ValueError('public key/signature shape')
    x,y=b64(jwk['x']),b64(jwk['y'])
    if len(x)!=32 or len(y)!=32:
        raise ValueError('public coordinate width')
    key=ec.EllipticCurvePublicNumbers(int.from_bytes(x,'big'),int.from_bytes(y,'big'),ec.SECP256R1()).public_key()
    signature=encode_dss_signature(int.from_bytes(signature[:32],'big'),int.from_bytes(signature[32:],'big'))
    key.verify(signature,(h+'.'+p).encode('ascii'),ec.ECDSA(hashes.SHA256()))
    return True

def demo_effect(arguments):
    """Recompute the frozen demo semantics without importing its ToolSpec."""
    if type(arguments) is not dict or set(arguments) != {'quantity','label','tags'}:
        raise ValueError('demo argument keys')
    quantity = u64(arguments['quantity'])
    label, tags = arguments['label'], arguments['tags']
    if type(label) is not str or type(tags) is not list or any(type(x) is not str for x in tags):
        raise ValueError('demo argument types')
    bounded(arguments)
    if len(label.encode('utf-8')) > 256 or len(tags) > 8 or any(x not in {'red','blue','neutral'} for x in tags) or len(tags) != len(set(tags)):
        raise ValueError('demo bounds')
    return {'ops':{'unit':'operation','amount':str(quantity)}, 'bytes':{'unit':'byte','amount':str(len(label.encode('utf-8')))}}, sorted(tags)

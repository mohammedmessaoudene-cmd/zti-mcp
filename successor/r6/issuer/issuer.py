"""Local laboratory issuer, a separate role never imported by the provider.

The bootstrap owns this module and KI.private. Deliberately malformed fixture
claims can be signed here for negative tests; provider acceptance is separate.
"""
import base64
import json
import os
from pathlib import Path
import uuid
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

CONTEXT = {
    'tenant_id':'r6-lab-tenant', 'admin_principal':'urn:r6:admin',
    'registry_id':'urn:r6:registry', 'executor_id':'urn:r6:executor',
    'resource_id':'urn:r6:resource', 'mandate_issuer':'urn:r6:mandate-issuer',
    'mandate_kid':'r6-KI', 'permit_issuer':'urn:r6:permit-issuer',
    'permit_kid':'r6-KP',
}
NOW = 2000000000

def b64(value):
    return base64.urlsafe_b64encode(value).decode('ascii').rstrip('=')

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')

def public_jwk(key):
    numbers = key.public_key().public_numbers() if isinstance(key,ec.EllipticCurvePrivateKey) else key.public_numbers()
    return {'kty':'EC', 'crv':'P-256', 'x':b64(numbers.x.to_bytes(32,'big')), 'y':b64(numbers.y.to_bytes(32,'big'))}

def make_keys(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    result = {}
    for role in ('KI','KP'):
        key = ec.generate_private_key(ec.SECP256R1())
        private = directory/(role+'.private.pem')
        public = directory/(role+'.public.pem')
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        os.chmod(private,0o600)
        public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        result[role] = {'private':str(private.resolve()), 'public':str(public.resolve()), 'jwk':public_jwk(key)}
    return result

def sign_claims(claims, private_path, *, typ='zti-mandate+jwt', kid='r6-KI', header=None):
    key = serialization.load_pem_private_key(Path(private_path).read_bytes(),password=None)
    if not isinstance(key,ec.EllipticCurvePrivateKey) or not isinstance(key.curve,ec.SECP256R1):
        raise ValueError('Expected P-256 signing key')
    protected = header if header is not None else {'alg':'ES256','typ':typ,'kid':kid}
    h,p = b64(encoded(protected)),b64(encoded(claims))
    signature = key.sign((h+'.'+p).encode('ascii'),ec.ECDSA(hashes.SHA256()))
    r,s = decode_dss_signature(signature)
    return h+'.'+p+'.'+b64(r.to_bytes(32,'big')+s.to_bytes(32,'big'))

def mandate_claims(body, *, context=None, issued_at=None, jti=None):
    ctx = context or CONTEXT
    if issued_at is None:
        issued_at = body['valid_from']
    return {'iss':ctx['mandate_issuer'],'sub':body['delegatee_id'],'aud':ctx['registry_id'],
            'iat':issued_at,'nbf':body['valid_from'],'exp':body['valid_until'],
            'jti':jti or body['mandate_id'], 'zti_mandate':body}

def sign_mandate(body, private_path, *, context=None, issued_at=None, claims_overrides=None, header=None):
    ctx = context or CONTEXT
    claims = mandate_claims(body,context=ctx,issued_at=issued_at)
    if claims_overrides:
        claims.update(claims_overrides)
    return sign_claims(claims,private_path,typ='zti-mandate+jwt',kid=ctx['mandate_kid'],header=header)

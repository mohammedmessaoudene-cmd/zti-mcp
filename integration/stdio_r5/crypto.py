"""Public laboratory crypto helpers; P-256 scalar 1 is deliberately NOT secret.

Canonical-subset/JWS helpers are adapted from reference/authority.py at
fc350b219f4f8ed452a6e59784ea69ea68fbaf07 (Apache-2.0). This successor adds
explicit error vocabulary, separable signature/time validation and R5 identities.
It does not implement complete RFC 8785 canonicalization or production key custody.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

PROFILE = 'zti-mcp/0.1'
ISSUER = 'https://authority.example.invalid'
TENANT = 'r5-lab-tenant'
REGISTRY = 'urn:r5:registry'
EXECUTOR = 'urn:r5:executor'
RESOURCE = 'urn:r5:resource'
KID = 'public-laboratory-p256-key'
NOW = 1793404800
U64 = 18446744073709551615
SAFE = 9007199254740991
KEY = ec.derive_private_key(1, ec.SECP256R1())  # PUBLIC TEST MATERIAL.


class DomainError(Exception):
    def __init__(self, reason: str, status: str = 'REFUSED'):
        self.reason = reason
        self.status = status
        super().__init__(reason)


def reject(reason: str, status: str = 'REFUSED'):
    raise DomainError(reason, status)


def canonical(value):
    """The explicitly bounded ASCII-key/safe-integer JSON domain of R5."""
    def check(item):
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            if abs(item) > SAFE:
                reject('BINDING_MISMATCH')
        elif type(item) is str:
            try:
                item.encode('utf-8')
            except UnicodeError:
                reject('BINDING_MISMATCH')
        elif type(item) is list:
            for child in item:
                check(child)
        elif type(item) is dict:
            for key, child in item.items():
                if type(key) is not str or not key.isascii():
                    reject('BINDING_MISMATCH')
                check(child)
        else:
            reject('BINDING_MISMATCH')
    check(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def parse_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                reject('INVALID_TOKEN')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: reject('INVALID_TOKEN'))
        canonical(value)
        return value
    except DomainError:
        reject('INVALID_TOKEN')
    except (ValueError, TypeError, UnicodeError):
        reject('INVALID_TOKEN')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def unb64(value):
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        reject('INVALID_TOKEN')
    try:
        raw = base64.urlsafe_b64decode(value + '=' * ((-len(value)) % 4))
    except (ValueError, TypeError):
        reject('INVALID_TOKEN')
    if b64(raw) != value:
        reject('INVALID_TOKEN')
    return raw


def sign(claims, typ):
    header = b64(canonical({'alg': 'ES256', 'typ': typ, 'kid': KID}))
    payload = b64(canonical(claims))
    der = KEY.sign((header + '.' + payload).encode('ascii'), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return header + '.' + payload + '.' + b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))


def verify_jws(token, typ, now=None):
    """Verify received signing segments; optional time check permits history reads."""
    if type(token) is not str:
        reject('INVALID_TOKEN')
    try:
        h, p, s = token.split('.')
    except ValueError:
        reject('INVALID_TOKEN')
    header = parse_json(unb64(h))
    if header != {'alg': 'ES256', 'typ': typ, 'kid': KID}:
        reject('INVALID_TOKEN')
    signature = unb64(s)
    if len(signature) != 64:
        reject('INVALID_TOKEN')
    try:
        KEY.public_key().verify(
            utils.encode_dss_signature(int.from_bytes(signature[:32], 'big'),
                                       int.from_bytes(signature[32:], 'big')),
            (h + '.' + p).encode('ascii'), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        reject('INVALID_TOKEN')
    claims = parse_json(unb64(p))
    nested = 'zti' if typ == 'zti-ict+jwt' else 'zti_mandate'
    if (type(claims) is not dict or
            set(claims) != {'iss', 'sub', 'aud', 'iat', 'nbf', 'exp', 'jti', nested}):
        reject('INVALID_TOKEN')
    if (claims['iss'] != ISSUER or
            any(type(claims[k]) is not str or not claims[k] for k in ('iss', 'sub', 'aud', 'jti')) or
            any(type(claims[k]) is not int or not 0 <= claims[k] <= SAFE for k in ('iat', 'nbf', 'exp')) or
            not claims['iat'] <= claims['nbf'] < claims['exp']):
        reject('INVALID_TOKEN')
    if nested == 'zti' and claims['exp'] - claims['iat'] > 60:
        reject('INVALID_TOKEN')
    if now is not None and not claims['nbf'] <= now < claims['exp']:
        reject('EXPIRED')
    return claims


def uint(value):
    if type(value) is not str or len(value) > 20 or not re.fullmatch(r'0|[1-9][0-9]*', value):
        reject('CONSTRAINT_VIOLATION')
    number = int(value)
    if number > U64:
        reject('CONSTRAINT_VIOLATION')
    return number


def quantities(ops=0, bytes_=0):
    return {'ops': {'unit': 'operation', 'amount': str(ops)},
            'bytes': {'unit': 'byte', 'amount': str(bytes_)}}


def numbers(value):
    units = {'ops': 'operation', 'bytes': 'byte'}
    if type(value) is not dict or set(value) != set(units):
        reject('CONSTRAINT_VIOLATION')
    result = {}
    for key, unit in units.items():
        if type(value[key]) is not dict or set(value[key]) != {'unit', 'amount'} or value[key]['unit'] != unit:
            reject('CONSTRAINT_VIOLATION')
        result[key] = uint(value[key]['amount'])
    return result

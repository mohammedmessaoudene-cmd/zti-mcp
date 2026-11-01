"""Client-owned bounded canonicalization; imports no provider binder or oracle."""
import hashlib
import json
import re

SAFE = 9007199254740991
U64 = 18446744073709551615


class BindingError(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def canonical(value):
    def check(item):
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            if abs(item) > SAFE:
                raise BindingError("BINDING_MISMATCH")
        elif type(item) is str:
            try:
                item.encode("utf-8")
            except UnicodeError as exc:
                raise BindingError("BINDING_MISMATCH") from exc
        elif type(item) is list:
            for child in item:
                check(child)
        elif type(item) is dict:
            for key, child in item.items():
                if type(key) is not str or not key.isascii():
                    raise BindingError("BINDING_MISMATCH")
                check(child)
        else:
            raise BindingError("BINDING_MISMATCH")
    check(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def bind(action):
    raw = canonical(action)
    args = action.get("arguments") if type(action) is dict else None
    if type(args) is not dict or set(args) != {"quantity", "label", "tags"}:
        raise BindingError("BINDING_MISMATCH")
    q = args["quantity"]
    if type(q) is not str or not re.fullmatch(r"0|[1-9][0-9]{0,19}", q) or int(q) > U64:
        raise BindingError("CONSTRAINT_VIOLATION")
    if type(args["label"]) is not str or len(args["label"].encode("utf-8")) > 256:
        raise BindingError("CONSTRAINT_VIOLATION")
    tags = args["tags"]
    if (type(tags) is not list or len(tags) > 8 or any(type(t) is not str or t not in {"red", "blue", "neutral"} for t in tags)
            or len(set(tags)) != len(tags)):
        raise BindingError("CONSTRAINT_VIOLATION")
    return {"canonical_utf8_base64": __import__("base64").b64encode(raw).decode("ascii"),
            "action_hash": hashlib.sha256(raw).hexdigest(),
            "costs": {"ops": {"unit": "operation", "amount": q},
                      "bytes": {"unit": "byte", "amount": str(len(args["label"].encode("utf-8")))}},
            "facts": sorted(tags)}


def validate_domain(action):
    """Separate client tool-context check; canonical bytes alone grant nothing."""
    if (type(action) is not dict or action.get("method") != "tools/call" or
            action.get("tool_name") != "demo.add_record" or action.get("tool_revision") != "1"):
        raise BindingError("BINDING_MISMATCH")


def verify_ict(token, jwk, context, principal, binding):
    """Verify a received permit using public material, never a provider helper."""
    import base64
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    def decode(value):
        if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise ValueError("Invalid compact JWS encoding")
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
            raise ValueError("Noncanonical compact JWS segment")
        return raw
    h, p, s = token.split(".")
    header, claims, signature = json.loads(decode(h)), json.loads(decode(p)), decode(s)
    if header != {"alg": "ES256", "typ": "zti-ict+jwt", "kid": context["permit_kid"]} or len(signature) != 64:
        raise ValueError("Invalid permit header/signature shape")
    public = ec.EllipticCurvePublicNumbers(int.from_bytes(decode(jwk["x"]), "big"), int.from_bytes(decode(jwk["y"]), "big"), ec.SECP256R1()).public_key()
    public.verify(utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")),
                  (h + "." + p).encode("ascii"), ec.ECDSA(hashes.SHA256()))
    if claims["iss"] != context["permit_issuer"] or claims["aud"] != context["executor_id"] or claims["sub"] != principal:
        raise ValueError("Wrong permit key context")
    if any(type(claims[k]) is not int or not 0 <= claims[k] <= SAFE for k in ("iat", "nbf", "exp")) or not claims["iat"] <= claims["nbf"] < claims["exp"] or claims["exp"] - claims["iat"] > 60:
        raise ValueError("Invalid permit integer dates")
    zti = claims["zti"]
    if zti["action_hash"] != binding["action_hash"] or zti["cost_bounds"] != binding["costs"] or zti["facts"] != binding["facts"]:
        raise ValueError("Received permit differs from client-computed binding")
    return {"signature_valid": True, "kid": header["kid"], "action_hash": zti["action_hash"]}
